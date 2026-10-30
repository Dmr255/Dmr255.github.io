/* =========================================================
   Dmr255 — portfolio behaviour
   Vanilla JS, tanpa dependency. Semua data repo dari GitHub API.
   ========================================================= */

(function () {
  "use strict";

  var $ = function (sel, root) {
    return (root || document).querySelector(sel);
  };
  var $$ = function (sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  };

  var USER = "Dmr255";
  var API = "https://api.github.com";
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- tema ---------- */

  var root = document.documentElement;
  var themeToggle = $("#themeToggle");

  function syncThemeLabel() {
    if (!themeToggle) return;
    var next = root.dataset.theme === "dark" ? "terang" : "gelap";
    themeToggle.setAttribute("aria-label", "Aktifkan tema " + next);
    themeToggle.setAttribute("title", "Tema " + next);
  }

  if (themeToggle) {
    syncThemeLabel();
    themeToggle.addEventListener("click", function () {
      var next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("dmr-theme", next);
      } catch (e) {
        /* private mode */
      }
      syncThemeLabel();
    });
  }

  /* ---------- header & menu ---------- */

  var header = $("#siteHeader");
  var burger = $("#burger");
  var nav = $("#navMenu");

  function onScroll() {
    if (header) header.classList.toggle("is-scrolled", window.scrollY > 8);
  }
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  function closeNav() {
    if (!nav || !burger) return;
    nav.classList.remove("is-open");
    burger.setAttribute("aria-expanded", "false");
    burger.setAttribute("aria-label", "Buka menu");
  }

  if (burger && nav) {
    burger.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      burger.setAttribute("aria-expanded", String(open));
      burger.setAttribute("aria-label", open ? "Tutup menu" : "Buka menu");
    });

    nav.addEventListener("click", function (event) {
      if (event.target.closest("a")) closeNav();
    });

    window.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeNav();
    });

    window.addEventListener("resize", function () {
      if (window.innerWidth > 860) closeNav();
    });
  }

  var yearEl = $("#year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  /* ---------- nav aktif ---------- */

  var navLinks = $$('.nav-link[href^="#"]');
  var sections = navLinks
    .map(function (link) {
      return document.querySelector(link.getAttribute("href"));
    })
    .filter(Boolean);

  if (sections.length && "IntersectionObserver" in window) {
    var navObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          navLinks.forEach(function (link) {
            link.classList.toggle("is-active", link.getAttribute("href") === "#" + entry.target.id);
          });
        });
      },
      { rootMargin: "-42% 0px -52% 0px" }
    );
    sections.forEach(function (section) {
      navObserver.observe(section);
    });
  }

  /* ---------- reveal on scroll ---------- */

  var revealEls = $$(".reveal");

  if (reduceMotion || !("IntersectionObserver" in window)) {
    revealEls.forEach(function (el) {
      el.classList.add("is-in");
    });
  } else {
    var revealObserver = new IntersectionObserver(
      function (entries, observer) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -36px 0px" }
    );
    revealEls.forEach(function (el) {
      revealObserver.observe(el);
    });
  }

  /* ---------- terminal ---------- */

  var term = $("#term");

  var TERM_LINES = [
    { type: "cmd", text: "whoami" },
    { type: "out", html: "<strong>dmr255</strong> · android tinkerer &amp; infra builder" },
    { type: "gap" },
    { type: "cmd", text: "cat /etc/focus" },
    { type: "out", html: "ROM &amp; bootloader · VPS &amp; tunnel · otomasi" },
    { type: "gap" },
    { type: "cmd", text: "ls ~/stack" },
    { type: "out", html: "kotlin  smali  magisk  bash  node  xray" },
    { type: "gap" },
    { type: "cmd", text: "uptime" },
    { type: "out", html: "sejak 2022 — masih penasaran, masih ngoprek" }
  ];

  function sleep(ms) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, ms);
    });
  }

  function promptSpan() {
    var span = document.createElement("span");
    span.className = "prompt";
    span.textContent = "$";
    return span;
  }

  function addCursor() {
    var line = document.createElement("div");
    line.className = "term-line";
    line.appendChild(promptSpan());
    var cursor = document.createElement("span");
    cursor.className = "cursor";
    line.appendChild(cursor);
    term.appendChild(line);
  }

  function renderTermStatic() {
    term.innerHTML = "";
    TERM_LINES.forEach(function (line) {
      if (line.type === "gap") {
        var gap = document.createElement("div");
        gap.className = "term-line gap";
        term.appendChild(gap);
        return;
      }
      var el = document.createElement("div");
      el.className = "term-line" + (line.type === "out" ? " out" : "");
      if (line.type === "cmd") {
        el.appendChild(promptSpan());
        var cmd = document.createElement("span");
        cmd.className = "cmd";
        cmd.textContent = line.text;
        el.appendChild(cmd);
      } else {
        el.innerHTML = line.html;
      }
      term.appendChild(el);
    });
    addCursor();
  }

  async function typeTerm() {
    if (!term) return;
    term.innerHTML = "";

    for (var i = 0; i < TERM_LINES.length; i++) {
      var line = TERM_LINES[i];

      if (line.type === "gap") {
        var gap = document.createElement("div");
        gap.className = "term-line gap";
        term.appendChild(gap);
        await sleep(100);
        continue;
      }

      if (line.type === "cmd") {
        var el = document.createElement("div");
        el.className = "term-line";
        el.appendChild(promptSpan());
        var cmd = document.createElement("span");
        cmd.className = "cmd";
        el.appendChild(cmd);
        term.appendChild(el);

        for (var c = 1; c <= line.text.length; c++) {
          cmd.textContent = line.text.slice(0, c);
          await sleep(22 + Math.random() * 34);
        }
        await sleep(260);
      } else {
        var out = document.createElement("div");
        out.className = "term-line out";
        out.innerHTML = line.html;
        term.appendChild(out);
        await sleep(150);
      }
    }

    addCursor();
  }

  if (term) {
    var termStarted = false;
    var startTerm = function () {
      if (termStarted) return;
      termStarted = true;
      if (reduceMotion) {
        renderTermStatic();
      } else {
        typeTerm();
      }
    };

    if ("IntersectionObserver" in window && !reduceMotion) {
      var termObserver = new IntersectionObserver(
        function (entries) {
          if (entries.some(function (e) { return e.isIntersecting; })) {
            startTerm();
            termObserver.disconnect();
          }
        },
        { threshold: 0.2 }
      );
      termObserver.observe(term);
      window.setTimeout(startTerm, 3000);
    } else {
      startTerm();
    }
  }

  /* ---------- data GitHub ---------- */

  var FALLBACK_USER = {
    public_repos: 65,
    followers: 2,
    created_at: "2022-07-29T13:20:26Z"
  };

  var FALLBACK_REPOS = [
    {
      name: "fluxlinux",
      html_url: "https://github.com/Dmr255/fluxlinux",
      description: "FluxLinux is Linux on Android, advanced orchestrator application that transforms your Android device into a versatile Linux workstation.",
      language: "Kotlin",
      stargazers_count: 0,
      fork: true,
      pushed_at: "2026-10-29T04:55:35Z"
    },
    {
      name: "connectbot",
      html_url: "https://github.com/Dmr255/connectbot",
      description: "ConnectBot is the first SSH client for Android.",
      language: "Kotlin",
      stargazers_count: 0,
      fork: true,
      pushed_at: "2026-10-30T04:42:04Z"
    },
    {
      name: "MDFULL",
      html_url: "https://github.com/Dmr255/MDFULL",
      description: "Whatsapp Bot with multi-function menu and multi-device (MD) support in Node.JS using lightweight Baileys module",
      language: "JavaScript",
      stargazers_count: 1,
      fork: true,
      pushed_at: "2023-09-15T23:44:55Z"
    },
    {
      name: "fastboot-flasher",
      html_url: "https://github.com/Dmr255/fastboot-flasher",
      description: "",
      language: "Rust",
      stargazers_count: 0,
      fork: true,
      pushed_at: "2026-06-02T11:49:06Z"
    },
    {
      name: "OpenClash",
      html_url: "https://github.com/Dmr255/OpenClash",
      description: "",
      language: "Shell",
      stargazers_count: 1,
      fork: true,
      pushed_at: "2023-12-05T07:40:58Z"
    },
    {
      name: "scvps",
      html_url: "https://github.com/Dmr255/scvps",
      description: "Autoscript Xray Only X NoobzVPNS Free Use Lifetime All OS, By FN Project X Rerechan02 #V2ray #Xray #XTLS #vmess #vless#trojan#slowdns",
      language: "Shell",
      stargazers_count: 0,
      fork: true,
      pushed_at: "2025-10-04T09:05:25Z"
    },
    {
      name: "kaeru",
      html_url: "https://github.com/Dmr255/kaeru",
      description: "ARMv7 payload that provides arbitrary code execution on MediaTek bootloaders",
      language: "C",
      stargazers_count: 0,
      fork: true,
      pushed_at: "2026-05-20T11:16:28Z"
    },
    {
      name: "NEW-CFT",
      html_url: "https://github.com/Dmr255/NEW-CFT",
      description: "",
      language: "HTML",
      stargazers_count: 0,
      fork: false,
      pushed_at: "2026-10-29T23:45:01Z"
    },
    {
      name: "vangke",
      html_url: "https://github.com/Dmr255/vangke",
      description: "",
      language: "JavaScript",
      stargazers_count: 2,
      fork: false,
      pushed_at: "2024-09-17T14:29:11Z"
    }
  ];

  var FEATURED = [
    "fluxlinux",
    "connectbot",
    "MDFULL",
    "fastboot-flasher",
    "OpenClash",
    "scvps",
    "kaeru",
    "NEW-CFT",
    "vangke"
  ];

  var NOTES = {
    "fastboot-flasher": "Tool flashing lewat fastboot — fork untuk eksperimen device Android.",
    kaeru: "Payload ARMv7 untuk eksekusi kode di bootloader MediaTek.",
    scvps: "Autoscript Xray/V2Ray untuk VPS — pasang sekali, langsung jalan.",
    OpenClash: "Fork OpenClash untuk kebutuhan tunnel di router OpenWrt.",
    vangke: "Repo pertama yang dapat bintang di GitHub.",
    "NEW-CFT": "Eksperimen web terbaru — HTML polos, tanpa build step."
  };

  var CATEGORY = {
    fluxlinux: "android",
    connectbot: "android",
    "fastboot-flasher": "android",
    kaeru: "android",
    CFA: "android",
    "Ubuntu-magisk": "android",
    "Kaorios-Toolbox": "android",
    "apk-builder-action": "android",
    OpenClash: "network",
    scvps: "network",
    "UDP-ZIVPN": "network",
    sccvpn: "network",
    "heroku-xray-server.me": "network",
    railway_v2ray: "network",
    HelloVPN: "network",
    DamarVPN: "network",
    "Damar.VPN": "network",
    sc: "network",
    vip: "network",
    MDFULL: "bot",
    "R-TXZY-MD": "bot",
    "rzky-multidevice": "bot",
    WaOpenAI: "bot",
    mirrorleechbot: "bot",
    boet: "bot",
    "NEW-CFT": "web",
    "Dmr255.github.io": "web",
    "damzz25prjkt.github.io": "web",
    GRETONGDev: "web",
    "sing-ribet-web": "web",
    vangke: "web"
  };

  var LANG_COLORS = {
    Kotlin: "#A97BFF",
    Java: "#B07219",
    JavaScript: "#F1E05A",
    HTML: "#E34C26",
    Shell: "#89E051",
    Smali: "#F1E05A",
    SCSS: "#C6538C",
    Rust: "#DEA584",
    C: "#8A8A8A",
    Python: "#3572A5",
    CSS: "#563D7C"
  };

  var grid = $("#repoGrid");
  var statusEl = $("#repoStatus");

  function categoryOf(repo) {
    if (CATEGORY[repo.name]) return CATEGORY[repo.name];
    var lang = (repo.language || "").toLowerCase();
    if (lang === "kotlin" || lang === "java" || lang === "smali") return "android";
    if (lang === "shell") return "network";
    if (lang === "javascript" || lang === "python") return "bot";
    if (lang === "html" || lang === "css" || lang === "scss") return "web";
    return "other";
  }

  function escapeHTML(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function timeAgo(iso) {
    if (!iso) return "";
    var diff = Date.now() - new Date(iso).getTime();
    if (diff < 0) diff = 0;
    var days = Math.floor(diff / 86400000);
    if (days < 1) return "hari ini";
    if (days === 1) return "kemarin";
    if (days < 30) return days + " hari lalu";
    var months = Math.floor(days / 30);
    if (months < 12) return months + " bln lalu";
    return Math.floor(months / 12) + " thn lalu";
  }

  function repoCard(repo, index) {
    var cat = categoryOf(repo);
    var desc = repo.description || NOTES[repo.name] || "Tanpa deskripsi — langsung cek isinya di GitHub.";
    var lang = repo.language || "";
    var color = LANG_COLORS[lang] || "var(--muted)";
    var stars = Number(repo.stargazers_count) || 0;
    var url = /^https:\/\/github\.com\//.test(repo.html_url || "")
      ? repo.html_url
      : "https://github.com/" + USER + "/" + encodeURIComponent(repo.name);

    var badges = "";
    if (stars > 0) {
      badges += '<span class="badge" title="' + stars + ' bintang">★ ' + stars + "</span>";
    }
    if (repo.fork) badges += '<span class="badge badge-fork">fork</span>';

    return (
      '<article class="repo-card" data-cat="' + cat + '" style="--i:' + index + '">' +
        '<div class="repo-top">' +
          '<span class="repo-icon" aria-hidden="true">' +
            '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 7.5a2 2 0 0 1 2-2h3.2l2 2.2h7.8a2 2 0 0 1 2 2v8.3a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z"/></svg>' +
          "</span>" +
          '<div class="repo-badges">' + badges + "</div>" +
        "</div>" +
        "<h3><a href=\"" + escapeHTML(url) + '" target="_blank" rel="noopener">' + escapeHTML(repo.name) + "</a></h3>" +
        '<p class="repo-desc">' + escapeHTML(desc) + "</p>" +
        '<div class="repo-foot">' +
          (lang
            ? '<span class="lang"><i style="--c:' + color + '" aria-hidden="true"></i>' + escapeHTML(lang) + "</span>"
            : "") +
          "<span>" + escapeHTML(timeAgo(repo.pushed_at)) + "</span>" +
        "</div>" +
      "</article>"
    );
  }

  function renderRepos(repos, live) {
    if (!grid) return;

    var chosen = FEATURED.map(function (name) {
      return repos.filter(function (repo) {
        return repo.name === name;
      })[0];
    }).filter(Boolean);

    if (!chosen.length) {
      chosen = repos
        .slice()
        .sort(function (a, b) {
          return new Date(b.pushed_at) - new Date(a.pushed_at);
        })
        .slice(0, 9);
    }

    grid.innerHTML = chosen
      .map(function (repo, index) {
        return repoCard(repo, index);
      })
      .join("");

    if (statusEl) {
      statusEl.classList.remove("is-error");
      statusEl.innerHTML = live
        ? chosen.length + " pilihan dari " + repos.length + " repo · <a href=\"https://github.com/" + USER + "?tab=repositories\" target=\"_blank\" rel=\"noopener\">lihat semuanya di GitHub ↗</a>"
        : "GitHub API sedang tidak merespons — menampilkan data terakhir. <a href=\"https://github.com/" + USER + "?tab=repositories\" target=\"_blank\" rel=\"noopener\">Buka GitHub ↗</a>";
    }
  }

  function setStat(name, value) {
    var el = $('[data-stat="' + name + '"]');
    if (!el) return;
    var target = Number(value);
    if (!isFinite(target) || target < 0) return;

    if (reduceMotion) {
      el.textContent = String(target);
      return;
    }

    var start = 0;
    var duration = 900;
    var startedAt = 0;

    function step(now) {
      if (!startedAt) startedAt = now;
      var progress = Math.min((now - startedAt) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = String(Math.round(start + (target - start) * eased));
      if (progress < 1) window.requestAnimationFrame(step);
    }
    window.requestAnimationFrame(step);
  }

  function applyUser(user, repos) {
    var stars = repos.reduce(function (sum, repo) {
      return sum + (Number(repo.stargazers_count) || 0);
    }, 0);
    var years = 0;
    if (user.created_at) {
      years = Math.max(0, Math.floor((Date.now() - new Date(user.created_at).getTime()) / 31557600000));
    }

    setStat("repos", user.public_repos);
    setStat("stars", stars);
    setStat("followers", user.followers);
    setStat("years", years);

    renderRepos(repos, true);
  }

  function useFallback() {
    renderRepos(FALLBACK_REPOS, false);
    if (statusEl) statusEl.classList.add("is-error");
  }

  function loadGitHub() {
    if (!grid) return;

    var controller = new AbortController();
    var timer = window.setTimeout(function () {
      controller.abort();
    }, 9000);

    Promise.all([
      fetch(API + "/users/" + USER, {
        headers: { Accept: "application/vnd.github+json" },
        signal: controller.signal
      }),
      fetch(API + "/users/" + USER + "/repos?per_page=100&sort=pushed", {
        headers: { Accept: "application/vnd.github+json" },
        signal: controller.signal
      })
    ])
      .then(function (responses) {
        if (!responses[0].ok || !responses[1].ok) {
          throw new Error("GitHub API " + responses[0].status + "/" + responses[1].status);
        }
        return Promise.all([responses[0].json(), responses[1].json()]);
      })
      .then(function (data) {
        var user = data[0] || FALLBACK_USER;
        var repos = Array.isArray(data[1]) && data[1].length ? data[1] : FALLBACK_REPOS;
        applyUser(user, repos);
        window.clearTimeout(timer);
      })
      .catch(function () {
        window.clearTimeout(timer);
        useFallback();
      });
  }

  loadGitHub();

  /* ---------- filter repo ---------- */

  var chips = $$(".chip[data-filter]");

  chips.forEach(function (chip) {
    chip.addEventListener("click", function () {
      var filter = chip.getAttribute("data-filter");

      chips.forEach(function (other) {
        var active = other === chip;
        other.classList.toggle("is-active", active);
        other.setAttribute("aria-pressed", String(active));
      });

      var cards = $$(".repo-card", grid);
      var shown = 0;
      cards.forEach(function (card) {
        var match = filter === "all" || card.getAttribute("data-cat") === filter;
        card.classList.toggle("is-hidden", !match);
        if (match) shown++;
      });

      if (statusEl) {
        if (!shown) {
          statusEl.textContent = "Belum ada repo di kategori ini.";
        } else {
          statusEl.innerHTML =
            shown + " repo ditampilkan · " +
            '<a href="https://github.com/' + USER + '?tab=repositories" target="_blank" rel="noopener">lihat semuanya di GitHub ↗</a>';
        }
      }
    });
  });

  /* ---------- copy profil ---------- */

  var copyBtn = $("#copyProfile");

  if (copyBtn && navigator.clipboard) {
    copyBtn.addEventListener("click", function () {
      var label = $(".copy-label", copyBtn);
      var original = label ? label.textContent : "Salin link profil";

      navigator.clipboard
        .writeText("https://github.com/" + USER)
        .then(function () {
          if (!label) return;
          label.textContent = "Tersalin ✓";
          copyBtn.classList.add("is-done");
          window.setTimeout(function () {
            label.textContent = original;
            copyBtn.classList.remove("is-done");
          }, 2200);
        })
        .catch(function () {
          if (label) label.textContent = "Gagal menyalin";
        });
    });
  }

  /* ---------- easter egg kecil: judul tab ---------- */

  var originalTitle = document.title;
  document.addEventListener("visibilitychange", function () {
    document.title = document.hidden ? "jangan lupa kembali 👋" : originalTitle;
  });
})();
