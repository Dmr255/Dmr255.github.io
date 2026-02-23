/**
 * ULTRA SCANNER v8.0 - CLOUDFLARE WORKER EDITION
 * Stateless, KV Storage, DoH DNS Resolution
 */

// Konfigurasi KV Namespace binding (buat di dashboard Cloudflare)
// Bind KV dengan nama "SCANNER_KV"

const CONFIG = {
    VERSION: '8.0-WORKER',
    DNS_API: 'https://cloudflare-dns.com/dns-query', // DoH (DNS over HTTPS)
    HTTP_TIMEOUT: 8000,
    MAX_WORDLIST: 50000 // Workers limit: 50MB payload, 50ms CPU time
};

// UUID Generator (Workers support crypto)
function generateUUID() {
    return crypto.randomUUID();
}

// DNS Resolution via DoH (Cloudflare DNS)
async function resolveDNS(hostname) {
    try {
        const response = await fetch(`${CONFIG.DNS_API}?name=${hostname}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        
        if (!response.ok) return null;
        
        const data = await response.json();
        if (data.Answer && data.Answer.length > 0) {
            return data.Answer[0].data; // Return IP
        }
        return null;
    } catch (e) {
        return null;
    }
}

// HTTP Check via fetch()
async function httpCheck(hostname, protocol) {
    const url = `${protocol}://${hostname}/`;
    const startTime = Date.now();
    
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), CONFIG.HTTP_TIMEOUT);
        
        const response = await fetch(url, {
            method: 'HEAD',
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0 (Ultra-Scanner/8.0)' }
        });
        
        clearTimeout(timeout);
        
        return {
            statusCode: response.status,
            headers: Object.fromEntries(response.headers),
            responseTime: Date.now() - startTime
        };
    } catch (e) {
        return null;
    }
}

// CDN Detection
function detectCDN(headers) {
    if (!headers) return 'Unknown';
    const server = headers['server'] || '';
    const via = headers['via'] || '';
    const cfRay = headers['cf-ray'];
    const akamai = headers['x-akamai-transformed'];
    const cloudfront = headers['x-amz-cf-id'];
    const fastly = headers['x-fastly-request-id'];
    
    if (cfRay || server.toLowerCase().includes('cloudflare')) return 'Cloudflare';
    if (akamai || server.toLowerCase().includes('akamai')) return 'Akamai';
    if (cloudfront) return 'CloudFront';
    if (fastly) return 'Fastly';
    if (server.toLowerCase().includes('nginx')) return 'Nginx';
    if (server.toLowerCase().includes('apache')) return 'Apache';
    return 'Unknown';
}

// CORS Headers
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
};

// Main Handler
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        
        // CORS Preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }
        
        // Serve Static HTML (Single Page Application)
        if (path === '/' || path === '/index.html') {
            return new Response(HTML_CONTENT, {
                headers: { 'Content-Type': 'text/html' }
            });
        }
        
        // API Routes
        if (path === '/api/scan' && request.method === 'POST') {
            return await handleStartScan(request, env);
        }
        
        if (path === '/api/scan/status' && request.method === 'POST') {
            return await handleCheckStatus(request, env);
        }
        
        if (path === '/api/scans' && request.method === 'GET') {
            return await handleGetScans(env);
        }
        
        if (path === '/api/scan/export' && request.method === 'POST') {
            return await handleExportCSV(request, env);
        }
        
        return new Response('Not Found', { status: 404 });
    }
};

// Handler: Start Scan (Async, return immediately)
async function handleStartScan(request, env) {
    try {
        const { domain, wordlist, mode = 'normal', concurrency = 10 } = await request.json();
        
        if (!domain || !wordlist || !Array.isArray(wordlist)) {
            return jsonResponse({ error: 'Invalid parameters' }, 400);
        }
        
        if (wordlist.length > CONFIG.MAX_WORDLIST) {
            return jsonResponse({ error: `Wordlist too large (max ${CONFIG.MAX_WORDLIST})` }, 400);
        }
        
        const scanId = generateUUID();
        const total = wordlist.length;
        
        // Simpan metadata scan ke KV
        const scanMeta = {
            id: scanId,
            domain,
            status: 'running',
            total,
            processed: 0,
            found: 0,
            mode,
            start_time: Date.now(),
            end_time: null
        };
        
        await env.SCANNER_KV.put(`scan:${scanId}`, JSON.stringify(scanMeta));
        await env.SCANNER_KV.put(`results:${scanId}`, JSON.stringify([]));
        
        // Trigger background scanning (fire and forget)
        // Di Workers, kita gak bisa run long process, jadi scan per batch via client polling
        // ATAU gunakan Queue (paid) atau Durable Objects (complex)
        
        // Solusi: Simpan state, client akan polling untuk continue scan
        await env.SCANNER_KV.put(`queue:${scanId}`, JSON.stringify({
            wordlist,
            currentIndex: 0,
            config: { mode, concurrency }
        }));
        
        return jsonResponse({
            success: true,
            scanId,
            total,
            message: 'Scan started. Poll /api/scan/status to continue.'
        });
        
    } catch (err) {
        return jsonResponse({ error: err.message }, 500);
    }
}

// Handler: Check Status & Process Batch (Client-driven scanning)
async function handleCheckStatus(request, env) {
    try {
        const { scanId, batchSize = 10 } = await request.json();
        
        const scanData = await env.SCANNER_KV.get(`scan:${scanId}`);
        if (!scanData) return jsonResponse({ error: 'Scan not found' }, 404);
        
        const scan = JSON.parse(scanData);
        const queueData = await env.SCANNER_KV.get(`queue:${scanId}`);
        const queue = JSON.parse(queueData);
        
        if (scan.status === 'completed') {
            const results = JSON.parse(await env.SCANNER_KV.get(`results:${scanId}`) || '[]');
            return jsonResponse({ scan, results, completed: true });
        }
        
        // Process next batch (Workers CPU limit ~50ms, jadi batch kecil)
        const batch = queue.wordlist.slice(queue.currentIndex, queue.currentIndex + batchSize);
        const results = [];
        
        for (const subdomain of batch) {
            const result = await checkSubdomain(subdomain, scan.domain, queue.config);
            if (result) {
                results.push(result);
                scan.found++;
            }
            scan.processed++;
        }
        
        queue.currentIndex += batch.length;
        
        // Save results
        const existingResults = JSON.parse(await env.SCANNER_KV.get(`results:${scanId}`) || '[]');
        existingResults.push(...results);
        await env.SCANNER_KV.put(`results:${scanId}`, JSON.stringify(existingResults));
        
        // Check completion
        if (queue.currentIndex >= queue.wordlist.length) {
            scan.status = 'completed';
            scan.end_time = Date.now();
        }
        
        await env.SCANNER_KV.put(`scan:${scanId}`, JSON.stringify(scan));
        await env.SCANNER_KV.put(`queue:${scanId}`, JSON.stringify(queue));
        
        return jsonResponse({
            scan,
            batchResults: results,
            completed: scan.status === 'completed',
            progress: {
                current: queue.currentIndex,
                total: queue.wordlist.length,
                percentage: Math.round((queue.currentIndex / queue.wordlist.length) * 100)
            }
        });
        
    } catch (err) {
        return jsonResponse({ error: err.message }, 500);
    }
}

// Handler: Get All Scans
async function handleGetScans(env) {
    try {
        const list = await env.SCANNER_KV.list({ prefix: 'scan:' });
        const scans = [];
        
        for (const key of list.keys) {
            const data = await env.SCANNER_KV.get(key.name);
            if (data) scans.push(JSON.parse(data));
        }
        
        return jsonResponse({ 
            scans: scans.sort((a, b) => b.start_time - a.start_time) 
        });
        
    } catch (err) {
        return jsonResponse({ error: err.message }, 500);
    }
}

// Handler: Export CSV
async function handleExportCSV(request, env) {
    try {
        const { scanId } = await request.json();
        const results = JSON.parse(await env.SCANNER_KV.get(`results:${scanId}`) || '[]');
        
        const csv = [
            'Subdomain,IP,CDN,Status,Response Time,Timestamp',
            ...results.map(r => `"${r.subdomain}","${r.ip}","${r.cdn}","${r.status}",${r.responseTime},"${r.timestamp}"`)
        ].join('\n');
        
        return new Response(csv, {
            headers: {
                'Content-Type': 'text/csv',
                'Content-Disposition': `attachment; filename="scan-${scanId}.csv"`,
                ...corsHeaders
            }
        });
        
    } catch (err) {
        return jsonResponse({ error: err.message }, 500);
    }
}

// Check Single Subdomain
async function checkSubdomain(subdomain, domain, config) {
    const fullDomain = `${subdomain}.${domain}`;
    const startTime = Date.now();
    
    // DNS Check via DoH
    const ip = await resolveDNS(fullDomain);
    if (!ip) return null;
    
    let result = {
        subdomain: fullDomain,
        ip,
        cdn: 'DNS Only',
        status: 'DNS Only',
        responseTime: Date.now() - startTime,
        timestamp: new Date().toISOString()
    };
    
    if (config.mode === 'fast') return result;
    
    // HTTPS Check
    const httpsRes = await httpCheck(fullDomain, 'https');
    if (httpsRes) {
        result.status = `HTTPS ${httpsRes.statusCode}`;
        result.cdn = detectCDN(httpsRes.headers);
        result.responseTime = Date.now() - startTime;
    } else if (config.mode === 'deep') {
        const httpRes = await httpCheck(fullDomain, 'http');
        if (httpRes) {
            result.status = `HTTP ${httpRes.statusCode}`;
            result.cdn = detectCDN(httpRes.headers);
        }
    }
    
    return result;
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
        }
    });
}

// HTML Content (Embedded biar single file)
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔥 Ultra Scanner v8.0 - Cloudflare Edition</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; background: linear-gradient(45deg, #00f260, #0575e6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #8892b0; font-size: 1.1em; }
        
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #64ffda; font-weight: 600; }
        input, select, textarea {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 16px;
            transition: all 0.3s;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #64ffda;
            box-shadow: 0 0 20px rgba(100,255,218,0.1);
        }
        
        .btn {
            background: linear-gradient(45deg, #00f260, #0575e6);
            border: none;
            padding: 14px 32px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0,242,96,0.3); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .btn-danger { background: linear-gradient(45deg, #ff416c, #ff4b2b); }
        
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-box {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-value { font-size: 2em; font-weight: bold; color: #64ffda; }
        .stat-label { color: #8892b0; font-size: 0.9em; margin-top: 5px; }
        
        .progress-container {
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            height: 30px;
            overflow: hidden;
            margin: 20px 0;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #00f260, #0575e6);
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .results-table th, .results-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .results-table th {
            background: rgba(0,0,0,0.3);
            color: #64ffda;
            font-weight: 600;
        }
        .results-table tr:hover { background: rgba(255,255,255,0.05); }
        
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: rgba(0,242,96,0.2); color: #00f260; }
        .badge-info { background: rgba(5,117,230,0.2); color: #0575e6; }
        .badge-warning { background: rgba(255,193,7,0.2); color: #ffc107; }
        
        .log-container {
            background: rgba(0,0,0,0.5);
            border-radius: 8px;
            padding: 15px;
            height: 200px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
        }
        .log-entry { margin-bottom: 5px; }
        .log-time { color: #64ffda; }
        .log-info { color: #8892b0; }
        .log-success { color: #00f260; }
        .log-error { color: #ff416c; }
        
        .hidden { display: none; }
        
        /* Animations */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .scanning { animation: pulse 1.5s infinite; }
        
        .file-upload {
            border: 2px dashed rgba(255,255,255,0.3);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        .file-upload:hover { border-color: #64ffda; background: rgba(100,255,218,0.05); }
        .file-upload.dragover { border-color: #00f260; background: rgba(0,242,96,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔥 ULTRA SCANNER v8.0</h1>
            <p class="subtitle">Cloudflare Worker Edition - Serverless Subdomain Discovery</p>
        </header>

        <!-- Setup Section -->
        <div id="setupSection" class="card">
            <h2 style="margin-bottom: 20px; color: #64ffda;">⚙️ Scan Configuration</h2>
            
            <div class="grid">
                <div class="input-group">
                    <label>Target Domain</label>
                    <input type="text" id="domain" placeholder="example.com" value="google.com">
                </div>
                
                <div class="input-group">
                    <label>Scan Mode</label>
                    <select id="mode">
                        <option value="fast">⚡ Fast (DNS Only)</option>
                        <option value="normal" selected>🔥 Normal (DNS + HTTPS)</option>
                        <option value="deep">💀 Deep (DNS + HTTP + HTTPS)</option>
                    </select>
                </div>
            </div>

            <div class="input-group">
                <label>Wordlist Source</label>
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <button class="btn" onclick="loadPreset('small')" style="flex: 1; padding: 10px;">Small (100)</button>
                    <button class="btn" onclick="loadPreset('medium')" style="flex: 1; padding: 10px;">Medium (1k)</button>
                    <button class="btn" onclick="loadPreset('large')" style="flex: 1; padding: 10px;">Large (10k)</button>
                </div>
                
                <div class="file-upload" id="dropZone" onclick="document.getElementById('fileInput').click()">
                    <div style="font-size: 3em; margin-bottom: 10px;">📁</div>
                    <div>Drop wordlist file here or click to browse</div>
                    <div style="color: #8892b0; font-size: 0.9em; margin-top: 10px;">Supports .txt files (max 50k lines)</div>
                    <input type="file" id="fileInput" accept=".txt" style="display: none;">
                </div>
                
                <textarea id="wordlist" rows="8" placeholder="Enter subdomains manually (one per line)...&#10;www&#10;api&#10;admin&#10;mail" style="margin-top: 15px;"></textarea>
                <div style="text-align: right; margin-top: 5px; color: #8892b0; font-size: 0.9em;">
                    Lines: <span id="lineCount">0</span> | Est. Time: <span id="estTime">-</span>
                </div>
            </div>

            <button class="btn" onclick="startScan()" id="startBtn" style="width: 100%;">
                🚀 START SCAN
            </button>
        </div>

        <!-- Progress Section -->
        <div id="progressSection" class="card hidden">
            <h2 style="margin-bottom: 20px; color: #64ffda;" class="scanning">🔍 Scanning in Progress...</h2>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value" id="statProcessed">0</div>
                    <div class="stat-label">Processed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="statFound">0</div>
                    <div class="stat-label">Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="statSpeed">0</div>
                    <div class="stat-label">Speed (req/s)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="statTime">00:00</div>
                    <div class="stat-label">Elapsed</div>
                </div>
            </div>

            <div class="progress-container">
                <div class="progress-bar" id="progressBar" style="width: 0%">0%</div>
            </div>

            <div style="display: flex; gap: 10px; margin-top: 20px;">
                <button class="btn btn-danger" onclick="stopScan()" style="flex: 1;">⏹ STOP</button>
                <button class="btn" onclick="pauseScan()" id="pauseBtn" style="flex: 1;">⏸ PAUSE</button>
            </div>

            <div class="input-group" style="margin-top: 20px;">
                <label>Live Log</label>
                <div class="log-container" id="logContainer">
                    <div class="log-entry"><span class="log-time">[INIT]</span> <span class="log-info">Ready to scan...</span></div>
                </div>
            </div>
        </div>

        <!-- Results Section -->
        <div id="resultsSection" class="card hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="color: #64ffda;">📊 Results</h2>
                <div>
                    <button class="btn" onclick="exportCSV()" style="margin-right: 10px;">📥 Export CSV</button>
                    <button class="btn" onclick="newScan()">🔄 New Scan</button>
                </div>
            </div>

            <div class="stats" style="margin-bottom: 20px;">
                <div class="stat-box">
                    <div class="stat-value" id="resultTotal">0</div>
                    <div class="stat-label">Total Checked</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="resultFound">0</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" id="resultDuration">0s</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>

            <div style="overflow-x: auto;">
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                            <th>CDN/Server</th>
                            <th>Status</th>
                            <th>Response Time</th>
                        </tr>
                    </thead>
                    <tbody id="resultsBody">
                    </tbody>
                </table>
            </div>
        </div>

        <!-- History Section -->
        <div class="card">
            <h2 style="margin-bottom: 20px; color: #64ffda;">📜 Recent Scans</h2>
            <div id="historyList" style="max-height: 300px; overflow-y: auto;">
                <p style="color: #8892b0; text-align: center;">No scans yet</p>
            </div>
        </div>
    </div>

    <script>
        // State Management
        let currentScan = null;
        let scanInterval = null;
        let isPaused = false;
        let startTime = null;
        let processedCount = 0;
        
        // Preset Wordlists
        const presets = {
            small: ['www', 'mail', 'ftp', 'localhost', 'admin', 'api', 'blog', 'test', 'dev', 'shop', 'news', 'support', 'portal', 'webmail', 'remote'],
            medium: ['www', 'mail', 'ftp', 'localhost', 'admin', 'api', 'blog', 'test', 'dev', 'shop', 'news', 'support', 'portal', 'webmail', 'remote', 
                    'host', 'server', 'ns1', 'ns2', 'dns', 'mx', 'pop', 'imap', 'smtp', 'webdisk', 'cpanel', 'whm', 'webmin', 'plesk', 'directadmin',
                    'app', 'mobile', 'm', 'beta', 'alpha', 'staging', 'demo', 'old', 'new', 'v1', 'v2', 'v3', 'secure', 'vpn', 'ssh', 'ftp', 'sftp'],
            large: [] // Will be generated or loaded from file
        };

        // DOM Elements
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const wordlistInput = document.getElementById('wordlist');

        // File Upload Handlers
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length) handleFile(files[0]);
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) handleFile(e.target.files[0]);
        });

        function handleFile(file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                wordlistInput.value = e.target.result;
                updateStats();
                log('File loaded: ' + file.name, 'success');
            };
            reader.readAsText(file);
        }

        function loadPreset(size) {
            if (size === 'large') {
                // Generate larger list from patterns
                const subs = [];
                const common = ['www', 'mail', 'api', 'admin', 'test', 'dev', 'staging', 'prod', 'app', 'mobile'];
                const regions = ['us', 'eu', 'asia', 'au', 'sa'];
                const nums = Array.from({length: 20}, (_, i) => i + 1);
                
                common.forEach(c => {
                    subs.push(c);
                    regions.forEach(r => subs.push(\`\${c}-\${r}\`, \`\${c}.\${r}\`));
                    nums.forEach(n => subs.push(\`\${c}\${n}\`, \`\${c}-\${n}\`));
                });
                wordlistInput.value = subs.join('\\n');
            } else {
                wordlistInput.value = presets[size].join('\\n');
            }
            updateStats();
            log(\`Loaded \${size} preset: \${wordlistInput.value.split('\\n').filter(l => l.trim()).length} lines\`, 'success');
        }

        function updateStats() {
            const lines = wordlistInput.value.split('\\n').filter(l => l.trim()).length;
            document.getElementById('lineCount').textContent = lines;
            const estSeconds = Math.ceil(lines / 10); // 10 req/s estimate
            document.getElementById('estTime').textContent = estSeconds < 60 ? \`\${estSeconds}s\` : \`\${Math.ceil(estSeconds/60)}m\`;
        }

        wordlistInput.addEventListener('input', updateStats);

        function log(message, type = 'info') {
            const container = document.getElementById('logContainer');
            const time = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = \`<span class="log-time">[\${time}]</span> <span class="log-\${type}">\${message}</span>\`;
            container.appendChild(entry);
            container.scrollTop = container.scrollHeight;
        }

        async function startScan() {
            const domain = document.getElementById('domain').value.trim();
            const wordlist = wordlistInput.value.split('\\n').map(l => l.trim()).filter(l => l);
            const mode = document.getElementById('mode').value;

            if (!domain) return alert('Please enter a domain');
            if (wordlist.length === 0) return alert('Please provide a wordlist');
            if (wordlist.length > 50000) return alert('Wordlist too large (max 50k)');

            document.getElementById('setupSection').classList.add('hidden');
            document.getElementById('progressSection').classList.remove('hidden');
            document.getElementById('resultsSection').classList.add('hidden');

            log('Initializing scan...', 'info');
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain, wordlist, mode, concurrency: 10 })
                });

                const data = await response.json();
                
                if (data.success) {
                    currentScan = data.scanId;
                    startTime = Date.now();
                    processedCount = 0;
                    log(\`Scan started: \${data.scanId}\`, 'success');
                    log(\`Total targets: \${data.total}\`, 'info');
                    
                    // Start polling
                    isPaused = false;
                    scanInterval = setInterval(() => pollScan(), 1000);
                } else {
                    throw new Error(data.error);
                }
            } catch (err) {
                log('Error: ' + err.message, 'error');
                alert('Failed to start scan: ' + err.message);
                resetUI();
            }
        }

        async function pollScan() {
            if (isPaused || !currentScan) return;

            try {
                const response = await fetch('/api/scan/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scanId: currentScan, batchSize: 10 })
                });

                const data = await response.json();
                
                if (data.error) throw new Error(data.error);

                // Update stats
                const scan = data.scan;
                processedCount = scan.processed;
                
                document.getElementById('statProcessed').textContent = scan.processed;
                document.getElementById('statFound').textContent = scan.found;
                
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
                const secs = (elapsed % 60).toString().padStart(2, '0');
                document.getElementById('statTime').textContent = \`\${mins}:\${secs}\`;
                
                const speed = elapsed > 0 ? (scan.processed / elapsed).toFixed(1) : 0;
                document.getElementById('statSpeed').textContent = speed;

                // Update progress
                const pct = data.progress.percentage;
                document.getElementById('progressBar').style.width = pct + '%';
                document.getElementById('progressBar').textContent = pct + '%';

                // Log new results
                if (data.batchResults && data.batchResults.length > 0) {
                    data.batchResults.forEach(r => {
                        log(\`Found: \${r.subdomain} [\${r.ip}]\`, 'success');
                    });
                }

                // Check completion
                if (data.completed) {
                    clearInterval(scanInterval);
                    showResults(scan, data.progress.total, elapsed);
                }

            } catch (err) {
                log('Poll error: ' + err.message, 'error');
            }
        }

        function showResults(scan, total, duration) {
            document.getElementById('progressSection').classList.add('hidden');
            document.getElementById('resultsSection').classList.remove('hidden');

            document.getElementById('resultTotal').textContent = total;
            document.getElementById('resultFound').textContent = scan.found;
            document.getElementById('resultDuration').textContent = duration + 's';

            // Load full results
            loadResults();
            updateHistory();
        }

        async function loadResults() {
            try {
                const response = await fetch('/api/scan/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scanId: currentScan })
                });
                
                const data = await response.json();
                const tbody = document.getElementById('resultsBody');
                tbody.innerHTML = '';
                
                if (data.results) {
                    data.results.forEach(r => {
                        const row = tbody.insertRow();
                        row.innerHTML = \`
                            <td><strong>\${r.subdomain}</strong></td>
                            <td>\${r.ip}</td>
                            <td><span class="badge badge-info">\${r.cdn}</span></td>
                            <td><span class="badge \${r.status.includes('200') ? 'badge-success' : 'badge-warning'}">\${r.status}</span></td>
                            <td>\${r.responseTime}ms</td>
                        \`;
                    });
                }
            } catch (err) {
                console.error('Load results error:', err);
            }
        }

        function stopScan() {
            if (confirm('Stop current scan?')) {
                clearInterval(scanInterval);
                log('Scan stopped by user', 'error');
                resetUI();
            }
        }

        function pauseScan() {
            isPaused = !isPaused;
            document.getElementById('pauseBtn').textContent = isPaused ? '▶ RESUME' : '⏸ PAUSE';
            log(isPaused ? 'Scan paused' : 'Scan resumed', 'info');
        }

        function resetUI() {
            document.getElementById('setupSection').classList.remove('hidden');
            document.getElementById('progressSection').classList.add('hidden');
            currentScan = null;
        }

        function newScan() {
            resetUI();
            document.getElementById('resultsSection').classList.add('hidden');
        }

        async function exportCSV() {
            try {
                const response = await fetch('/api/scan/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scanId: currentScan })
                });
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = \`scan-\${currentScan}.csv\`;
                a.click();
                log('CSV exported', 'success');
            } catch (err) {
                alert('Export failed: ' + err.message);
            }
        }

        async function updateHistory() {
            try {
                const response = await fetch('/api/scans');
                const data = await response.json();
                const container = document.getElementById('historyList');
                
                if (data.scans && data.scans.length > 0) {
                    container.innerHTML = data.scans.map(s => \`
                        <div style="padding: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: 600; color: #64ffda;">\${s.domain}</div>
                                <div style="font-size: 0.85em; color: #8892b0;">
                                    \${new Date(s.start_time).toLocaleString()} | 
                                    <span class="badge \${s.status === 'completed' ? 'badge-success' : 'badge-warning'}">\${s.status}</span>
                                </div>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 1.2em; font-weight: bold;">\${s.found}/\${s.total}</div>
                                <div style="font-size: 0.8em; color: #8892b0;">found</div>
                            </div>
                        </div>
                    \`).join('');
                }
            } catch (err) {
                console.error('History error:', err);
            }
        }

        // Load history on startup
        updateHistory();
    </script>
</body>
</html>`;
