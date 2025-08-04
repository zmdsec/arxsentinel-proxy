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
      /webtoons\.com$/, /mangakakalot\.com$/, /readmanganato\.com$/,
      /mangadex\.org$/, /cdn\./, /cloudflare\.com$/, /akamai\.net$/,
      /cookiebot\.com$/, /onetrust\.com$/, /consensu\.org$/, /cmp\./
    ],
    maliciousPatterns: [
      /eval\(/i,
      /Function\(/i,
      /document\.createElement\s*\(\s*['"]script['"]/i,
      /window\.location\s*=\s*['"]http/i,
      /window\.open/i,
      /setTimeout\s*\(\s*function/i,
      /setInterval\s*\(\s*function/i
    ],
    heuristicWeights: {
      keywords: 3,
      tags: { iframe: 1.5, aside: 1.5, section: 1.5, script: 0.3 },
      events: 1,
      styles: 1.5,
      size: 1.5,
      patterns: 4,
      malicious: 10
    },
    secretKey: 'arx_intel_secret_2025',
    version: '1.4.2',
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

      if (src && config.trustedDomains.some(rx => rx.test(new URL(src, window.location.href).hostname))) return 0;
      if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy') || txt.includes('aceitar')) return 0;

      let score = 0;
      if (config.keywords.some(w => txt.includes(w))) score += config.heuristicWeights.keywords;
      if (config.heuristicWeights.tags[tag]) score += config.heuristicWeights.tags[tag];
      if ([...el.attributes].some(a => /onload|onclick|onmouseover|onerror|onfocus/.test(a.name))) score += config.heuristicWeights.events;
      const style = window.getComputedStyle(el);
      if (parseInt(style.zIndex) > 100 || style.position === "fixed") score += config.heuristicWeights.styles;
      if (el.offsetHeight < 120 || el.offsetWidth < 300) score += config.heuristicWeights.size;
      if (config.blockPatterns.some(rx => rx.test(html))) score += config.heuristicWeights.patterns;
      if (config.maliciousPatterns.some(rx => rx.test(html))) score += config.heuristicWeights.malicious;

      scoreCache.set(cacheKey, score);
      return score;
    } catch {
      return 0;
    }
  }

  async function limparAds(root = document) {
    const elements = root.querySelectorAll('iframe, script, div, aside, section');
    let blockedCount = 0;
    for (const el of elements) {
      const className = el.className?.toLowerCase?.() || "";
      if (config.whitelist.some(w => className.includes(w))) continue;

      const score = await scoreElemento(el);
      if (score >= 5) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
      }
    }
    console.log(`[${config.brand}] Bloqueados ${blockedCount} elementos`);
  }

  async function acceptCookies() {
    try {
      const selectors = [
        'button[class*="cookie"], button[class*="consent"], button[class*="accept"], button[class*="gdpr"], button[class*="privacy"], button[class*="cookie-accept"], button[class*="accept-all"], button[class*="cookie-btn"]',
        'a[class*="cookie"], a[class*="consent"], a[class*="accept"]',
        'div[class*="cookie"][role="button"], div[class*="consent"][role="button"]',
        'button:contains("Aceitar"), button:contains("Accept"), button:contains("Consent"), button:contains("OK"), button:contains("Agree"), button:contains("Confirmar")'
      ].join(', ');

      const cookieButtons = document.querySelectorAll(selectors);
      let clicked = false;
      for (const btn of cookieButtons) {
        try {
          setTimeout(() => {
            btn.click();
            console.log(`[${config.brand}] Botão de cookies clicado: ${btn.outerHTML.slice(0, 50)}...`);
          }, Math.random() * 200 + 50);
          clicked = true;
        } catch (e) {
          console.warn(`[${config.brand}] Falha ao clicar no botão de cookies:`, e);
        }
      }
      if (clicked) {
        console.log(`[${config.brand}] Cookies aceitos, reexecutando limpeza...`);
        setTimeout(() => limparAds(), 1000);
      }
      return clicked;
    } catch (e) {
      console.warn(`[${config.brand}] Erro ao aceitar cookies:`, e);
      return false;
    }
  }

  function protegerContraPopups() {
    // Bloquear window.open
    const origOpen = window.open;
    window.open = function (...args) {
      const url = args[0];
      if (!url || config.blockPatterns.some(rx => rx.test(url)) || !config.trustedDomains.some(rx => rx.test(new URL(url, window.location.href).hostname))) {
        console.warn(`[${config.brand}] Popup bloqueado: ${url || 'desconhecido'}`);
        return null;
      }
      return origOpen.apply(window, args);
    };

    // Bloquear redirecionamentos via location
    ['href', 'assign', 'replace'].forEach(prop => {
      const descriptor = Object.getOwnPropertyDescriptor(window.location, prop) || Object.getOwnPropertyDescriptor(Location.prototype, prop);
      Object.defineProperty(window.location, prop, {
        configurable: true,
        set(value) {
          if (config.blockPatterns.some(rx => rx.test(value)) || !config.trustedDomains.some(rx => rx.test(new URL(value, window.location.href).hostname))) {
            console.warn(`[${config.brand}] Redirecionamento bloqueado: ${value}`);
            return;
          }
          descriptor.set.call(window.location, value);
        },
        get: descriptor.get
      });
    });

    // Bloquear eventos dinâmicos
    ['click', 'mouseover', 'focus'].forEach(event => {
      document.addEventListener(event, e => {
        const target = e.target.closest('a[target="_blank"], [onclick], [onmouseover], [onfocus]');
        if (target) {
          const href = target.href || target.getAttribute('onclick')?.match(/['"](https?:\/\/[^'"]+)['"]/i)?.[1] || target.getAttribute('onmouseover')?.match(/['"](https?:\/\/[^'"]+)['"]/i)?.[1];
          if (href && !config.trustedDomains.some(rx => rx.test(new URL(href, window.location.href).hostname))) {
            e.preventDefault();
            e.stopPropagation();
            console.log(`[${config.brand}] Ação externa bloqueada: ${href}`);
          }
        }
      }, { capture: true, passive: false });
    });

    // Bloquear setTimeout/setInterval maliciosos
    const origSetTimeout = window.setTimeout;
    const origSetInterval = window.setInterval;
    window.setTimeout = function (fn, ...args) {
      const code = fn.toString();
      if (config.maliciousPatterns.some(rx => rx.test(code))) {
        console.warn(`[${config.brand}] Timeout malicioso bloqueado: ${code.slice(0, 50)}...`);
        return;
      }
      return origSetTimeout(fn, ...args);
    };
    window.setInterval = function (fn, ...args) {
      const code = fn.toString();
      if (config.maliciousPatterns.some(rx => rx.test(code))) {
        console.warn(`[${config.brand}] Interval malicioso bloqueado: ${code.slice(0, 50)}...`);
        return;
      }
      return origSetInterval(fn, ...args);
    };

    // Bloquear fetch/XMLHttpRequest suspeitos
    const origFetch = window.fetch;
    window.fetch = async function (...args) {
      const url = args[0];
      if (typeof url === 'string' && config.blockPatterns.some(rx => rx.test(url))) {
        console.warn(`[${config.brand}] Requisição bloqueada: ${url}`);
        return new Response(null, { status: 403 });
      }
      return origFetch(...args);
    };

    const origXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (...args) {
      const url = args[1];
      if (config.blockPatterns.some(rx => rx.test(url))) {
        console.warn(`[${config.brand}] Requisição XHR bloqueada: ${url}`);
        return;
      }
      return origXhrOpen.apply(this, args);
    };

    // Anti-adblock: simular elementos visíveis
    setInterval(() => {
      document.querySelectorAll('[data-arx-hidden]').forEach(el => {
        Object.defineProperty(el, 'offsetHeight', { configurable: true, value: 100 });
        Object.defineProperty(el, 'offsetWidth', { configurable: true, value: 100 });
      });
    }, 1000);

    // Monitorar visibilidade
    setInterval(() => {
      if (document.visibilityState === 'hidden' && !document.hasFocus()) {
        console.warn(`[${config.brand}] Redirecionamento oculto detectado`);
        window.stop();
      }
    }, 500);
  }

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(async () => {
        await limparAds();
        await acceptCookies();
      }, 250);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });
  }

  limparAds();
  setTimeout(() => acceptCookies(), 1000);
  setTimeout(() => acceptCookies(), 3000);
  observarMutacoes();
  protegerContraPopups();

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo`);
})();
