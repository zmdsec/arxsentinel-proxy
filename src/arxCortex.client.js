(function () {
  const config = {
    blockPatterns: [
      /googlesyndication/i,
      /doubleclick/i,
      /adsystem/i,
      /taboola/i,
      /outbrain/i,
      /facebook.net/i,
      /analytics/i,
      /track|ad|sponsored|banner|pixel|beacon|impression|click/i
    ],
    whitelist: [
      "main", "content", "article", "body", "texto",
      "chapter-content", "manga-image", "reader", "comic",
      "cookie-consent", "cookie-notice", "accept-cookies",
      "consent-banner", "gdpr", "privacy-policy", "cookie-popup",
      "accept-all", "cookie-accept", "consent-button", "cookie-btn"
    ],
    keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
    trustedDomains: [
      /webtoons.com$/, /mangakakalot.com$/, /readmanganato.com$/,
      /mangadex.org$/, /cdn\./, /cloudflare.com$/, /akamai.net$/,
      /cookiebot.com$/, /onetrust.com$/, /consensu.org$/, /cmp\./
    ],
    heuristicWeights: {
      keywords: 3,
      tags: { iframe: 1.5, aside: 1.5, section: 1.5, script: 0.3 },
      events: 1,
      styles: 1.5,
      size: 1.5,
      patterns: 4
    },
    secretKey: 'arx_intel_secret_2025',
    version: '1.4',
    brand: 'Arx Intel'
  };

  const scoreCache = new Map();

  function simpleHash(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString(16);
  }

  async function scoreElemento(el) {
    try {
      const html = el.outerHTML || "";
      const txt = el.textContent?.toLowerCase() || "";
      const tag = el.tagName?.toLowerCase() || "";
      const className = el.className?.toLowerCase?.() || "";
      const src = el.src || el.getAttribute('href') || "";
      const cacheKey = simpleHash(`${tag}_${className}_${txt.slice(0, 50)}`);

      if (scoreCache.has(cacheKey)) return scoreCache.get(cacheKey);

      if (src && config.trustedDomains.some(rx => rx.test(new URL(src, window.location.href).hostname)))
        return 0;
      if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy'))
        return 0;

      let score = 0;
      if (config.keywords.some(w => txt.includes(w))) score += config.heuristicWeights.keywords;
      if (config.heuristicWeights.tags[tag]) score += config.heuristicWeights.tags[tag];
      if ([...el.attributes].some(a => /onload|onclick|onmouseover|onerror/.test(a.name))) score += config.heuristicWeights.events;
      const style = window.getComputedStyle(el);
      if (parseInt(style.zIndex) > 100 || style.position === "fixed") score += config.heuristicWeights.styles;
      if (el.offsetHeight < 120 || el.offsetWidth < 300) score += config.heuristicWeights.size;
      if (config.blockPatterns.some(rx => rx.test(html))) score += config.heuristicWeights.patterns;

      scoreCache.set(cacheKey, score);
      return score;
    } catch {
      return 0;
    }
  }

  async function limparAds(root = document) {
    const elements = root.querySelectorAll('iframe, script, div, aside, section');
    for (const el of elements) {
      const className = el.className?.toLowerCase?.() || "";
      if (config.whitelist.some(w => className.includes(w))) continue;

      const score = await scoreElemento(el);
      if (score >= 5) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
      }
    }
  }

  function protegerContraPopups() {
    const origOpen = window.open;
    window.open = function (...args) {
      const url = args[0];
      const evt = window.event || arguments.callee.caller?.arguments[0];
      if (evt && evt.isTrusted) return origOpen.apply(window, args);
      console.warn(`[${config.brand}] Popup bloqueado: ${url}`);
      return null;
    };

    document.addEventListener('click', e => {
      const target = e.target.closest('a[target="_blank"]');
      if (target && target.href && !config.trustedDomains.some(rx => rx.test(new URL(target.href).hostname))) {
        e.preventDefault();
        console.log(`[${config.brand}] Bloqueio de link externo em nova aba: ${target.href}`);
      }
    }, true);

    setInterval(() => {
      if (document.visibilityState === 'hidden' && document.hasFocus()) {
        console.warn(`[${config.brand}] Redirecionamento oculto detectado.`);
        window.stop();
      }
    }, 1000);
  }

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(() => limparAds(), 250);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });
  }

  if (window.localStorage) {
    limparAds();
    observarMutacoes();
    protegerContraPopups();
  }

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo no navegador`);
})();
