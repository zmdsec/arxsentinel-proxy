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
      "cookiebar", "cookie-policy", "consent-popup", "gdpr-notice",
      "image-container", "manga-page", "reader-image",
      "reader-area", "chapter-image", "manga-reader", "chapter-container",
      "news", "noticia", "headline"
    ],
    navigationClasses: [
      "nav", "menu", "navbar", "nav-link", "menu-item",
      "chapter-nav", "chapter-link", "next-chapter", "prev-chapter",
      "news-title", "headline-link", "article-link",
      "works-link", "obras-link", "manga-list", "series-link", "manga-menu",
      "main-nav", "series-menu", "category-link", "nav-item", "menu-link"
    ],
    trustedPaths: [
      /\/obras/, /\/manga/, /\/chapter/, /\/noticia/, /\/politica/,
      /\/series/, /\/works/, /\/home/, /\/index/, /\/catalog/, /\/library/,
      /\/mangas/, /\/archive/
    ],
    keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
    trustedDomains: [
      /webtoons\.com$/, /mangakakalot\.com$/, /readmanganato\.com$/,
      /mangadex\.org$/, /cdn\./, /cloudflare\.com$/, /akamai\.net$/,
      /cookiebot\.com$/, /onetrust\.com$/, /consensu\.org$/, /cmp\./,
      /img\./, /images\./, /static\./,
      /manhastro\.net$/, /cdn\.manhastro\.net$/, /media\.manhastro\.net$/,
      /content\.manhastro\.net$/, /assets\.manhastro\.net$/,
      /img\.manhastro\.net$/, /chapter\.manhastro\.net$/,
      /media2\.manhastro\.net$/, /images\.manhastro\.net$/,
      /g1\.globo\.com$/, /globo\.com$/, /noticias\.globo\.com$/
    ],
    maliciousPatterns: [
      /eval\(/i,
      /Function\(/i,
      /document\.createElement\s*\(\s*['"]script['"]/i,
      /window\.open/i,
      /document\.write/i,
      /requestAnimationFrame/i,
      /Promise\.resolve/i
    ],
    proxyBase: 'https://arxsentinel-proxy.onrender.com/proxy?url=',
    secretKey: 'arx_intel_secret_2025',
    version: '1.4.15',
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
      const src = el.src || el.getAttribute('href') || el.getAttribute('data-href') || "";
      const cacheKey = simpleHash(`${tag}_${className}_${txt.slice(0, 50)}`);

      if (scoreCache.has(cacheKey)) return scoreCache.get(cacheKey);

      if (src && (src.startsWith('data:image/') || config.trustedDomains.some(rx => rx.test(new URL(src, window.location.href).hostname)) || config.trustedPaths.some(rx => rx.test(src)))) {
        return config.heuristicWeights.trustedDomain;
      }
      if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy') || txt.includes('aceitar')) return 0;
      if (config.whitelist.some(w => className.includes(w))) return 0;
      if (tag === 'a' && (config.navigationClasses.some(c => className.includes(c)) || config.trustedPaths.some(rx => rx.test(src)))) return 0;

      let score = 0;
      if (config.keywords.some(w => txt.includes(w))) score += config.heuristicWeights.keywords;
      if (config.heuristicWeights.tags[tag]) score += config.heuristicWeights.tags[tag];
      if ([...el.attributes].some(a => /on(load|click|mouseover|error|focus|blur|unload|beforeunload|pagehide)/.test(a.name))) score += config.heuristicWeights.events;
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
    const elements = root.querySelectorAll('iframe, script, aside, a');
    let blockedCount = 0;
    for (const el of elements) {
      const className = el.className?.toLowerCase?.() || "";
      const href = el.getAttribute('href') || '';
      if (config.whitelist.some(w => className.includes(w))) continue;
      if (el.tagName.toLowerCase() === 'a' && (config.navigationClasses.some(c => className.includes(c)) || config.trustedPaths.some(rx => rx.test(href)))) {
        const decodedHref = decodeURIComponent(href);
        const urlObj = new URL(decodedHref, window.location.href);
        const newHref = config.proxyBase + encodeURIComponent(urlObj.href);
        el.href = newHref;
        console.log(`[${config.brand}] Link preservado e reescrito para proxy: ${href} -> ${newHref}`);
        continue;
      }

      const score = await scoreElemento(el);
      if (score >= 5) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
        console.log(`[${config.brand}] Elemento bloqueado: ${el.tagName.toLowerCase()} - ${href || el.src || 'inline'} (score: ${score})`);
      }
    }
    console.log(`[${config.brand}] Bloqueados ${blockedCount} elementos`);

    document.querySelectorAll('img').forEach(img => {
      img.onerror = () => {
        console.warn(`[${config.brand}] Falha ao carregar imagem: ${img.src}`);
      };
      img.onload = () => {
        console.log(`[${config.brand}] Imagem carregada com sucesso: ${img.src}`);
      };
      if (img.hasAttribute('data-src') || img.hasAttribute('data-lazy-src')) {
        const src = img.getAttribute('data-src') || img.getAttribute('data-lazy-src');
        img.src = src;
        console.log(`[${config.brand}] Lazy-loading forçado: ${src}`);
      }
    });
  }

  async function acceptCookies() {
    try {
      const selectors = [
        'button[class*="cookie"], button[class*="consent"], button[class*="accept"], button[class*="gdpr"], button[class*="privacy"], button[class*="cookie-accept"], button[class*="accept-all"], button[class*="cookie-btn"]',
        'a[class*="cookie"], a[class*="consent"], a[class*="accept"]',
        'div[class*="cookie"][role="button"], div[class*="consent"][role="button"]',
        'button:contains("Aceitar"), button:contains("Accept"), button:contains("Consent"), button:contains("OK"), button:contains(" Agree"), button:contains("Confirmar")',
        '[aria-label*="cookie"], [aria-label*="consent"], [aria-label*="accept"]',
        '[data-consent], [data-cookie], [data-gdpr], [data-privacy]'
      ].join(', ');

      const cookieButtons = document.querySelectorAll(selectors);
      let clicked = false;
      for (const btn of cookieButtons) {
        try {
          setTimeout(() => {
            btn.click();
            console.log(`[${config.brand}] Botão de cookies clicado: ${btn.outerHTML.slice(0, 50)}...`);
          }, Math.random() * 300 + 50);
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
    window.IntersectionObserver = class {
      constructor(callback) {
        this.callback = callback;
      }
      observe(target) {
        this.callback([{ isIntersecting: true, target }]);
      }
      unobserve() {}
      disconnect() {}
    };

    const origOpen = window.open;
    window.open = function (...args) {
      const url = args[0];
      if (!url || config.blockPatterns.some(rx => rx.test(url)) || !config.trustedDomains.some(rx => rx.test(new URL(url, window.location.href).hostname))) {
        console.warn(`[${config.brand}] Popup bloqueado: ${url || 'desconhecido'}`);
        return null;
      }
      const newUrl = config.proxyBase + encodeURIComponent(url);
      console.log(`[${config.brand}] Redirecionando popup pelo proxy: ${url} -> ${newUrl}`);
      return origOpen(newUrl);
    };

    ['href', 'assign', 'replace'].forEach(prop => {
      const descriptor = Object.getOwnPropertyDescriptor(window.location, prop) || Object.getOwnPropertyDescriptor(Location.prototype, prop);
      Object.defineProperty(window.location, prop, {
        configurable: true,
        set(value) {
          const urlObj = new URL(value, window.location.href);
          if (config.blockPatterns.some(rx => rx.test(value)) || (!config.trustedDomains.some(rx => rx.test(urlObj.hostname)) && !config.trustedPaths.some(rx => rx.test(urlObj.pathname)))) {
            console.warn(`[${config.brand}] Redirecionamento bloqueado: ${value}`);
            return;
          }
          const newUrl = config.proxyBase + encodeURIComponent(urlObj.href);
          console.log(`[${config.brand}] Redirecionando pelo proxy: ${value} -> ${newUrl}`);
          descriptor.set.call(window.location, newUrl);
        },
        get: descriptor.get
      });
    });

    document.addEventListener('click', e => {
      const target = e.target.closest('a[href], [onclick], [data-href]');
      if (target) {
        let href = target.getAttribute('href') || target.getAttribute('data-href');
        const onclick = target.getAttribute('onclick') || '';
        if (onclick) {
          const match = onclick.match(/['"]([^'"]+)['"]/i) || onclick.match(/location\.(?:href|assign|replace)\s*=\s*['"]([^'"]+)['"]/i);
          if (match) href = match[1];
        }
        if (href && !href.startsWith('javascript:') && !href.startsWith('#') && !href.startsWith('data:')) {
          const decodedHref = decodeURIComponent(href);
          const urlObj = new URL(decodedHref, window.location.href);
          if (config.trustedDomains.some(rx => rx.test(urlObj.hostname)) || config.trustedPaths.some(rx => rx.test(urlObj.pathname))) {
            const newHref = config.proxyBase + encodeURIComponent(urlObj.href);
            if (target.tagName.toLowerCase() === 'a') {
              e.preventDefault();
              e.stopPropagation();
              window.location.href = newHref;
              console.log(`[${config.brand}] Link clicado reescrito para proxy: ${decodedHref} -> ${newHref}`);
            } else if (onclick) {
              e.preventDefault();
              e.stopPropagation();
              window.location.href = newHref;
              console.log(`[${config.brand}] Evento onclick reescrito para proxy: ${decodedHref} -> ${newHref}`);
            }
          } else {
            e.preventDefault();
            e.stopPropagation();
            console.log(`[${config.brand}] Ação externa bloqueada: ${decodedHref} (motivo: domínio não confiável ou padrão de bloqueio)`);
          }
        }
      }
    }, { capture: true, passive: false });

    const origSetTimeout = window.setTimeout;
    const origSetInterval = window.setInterval;
    const origRequestAnimationFrame = window.requestAnimationFrame;
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
    window.requestAnimationFrame = function (fn) {
      const code = fn.toString();
      if (config.maliciousPatterns.some(rx => rx.test(code))) {
        console.warn(`[${config.brand}] AnimationFrame malicioso bloqueado: ${code.slice(0, 50)}...`);
        return;
      }
      return origRequestAnimationFrame(fn);
    };
    const origPromise = Promise.resolve;
    Promise.resolve = function (...args) {
      if (args[0]?.toString()?.match(/location|window\.open/i)) {
        console.warn(`[${config.brand}] Promise maliciosa bloqueada`);
        return Promise.reject('Blocked by ArxCortex');
      }
      return origPromise.apply(Promise, args);
    };

    const origFetch = window.fetch;
    window.fetch = async function (...args) {
      const url = args[0];
      if (typeof url === 'string') {
        const decodedUrl = decodeURIComponent(url);
        const urlObj = new URL(decodedUrl, window.location.href);
        if (config.blockPatterns.some(rx => rx.test(decodedUrl)) && !config.trustedDomains.some(rx => rx.test(urlObj.hostname))) {
          console.warn(`[${config.brand}] Requisição bloqueada: ${decodedUrl}`);
          return new Response(null, { status: 403 });
        }
        if (config.trustedDomains.some(rx => rx.test(urlObj.hostname)) || config.trustedPaths.some(rx => rx.test(urlObj.pathname))) {
          console.log(`[${config.brand}] Requisição de imagem ou script permitida: ${decodedUrl}`);
          return origFetch(decodedUrl, args[1]);
        }
      }
      return origFetch(...args);
    };

    const origXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (...args) {
      const url = args[1];
      if (typeof url === 'string') {
        const decodedUrl = decodeURIComponent(url);
        const urlObj = new URL(decodedUrl, window.location.href);
        if (config.blockPatterns.some(rx => rx.test(decodedUrl)) && !config.trustedDomains.some(rx => rx.test(urlObj.hostname))) {
          console.warn(`[${config.brand}] Requisição XHR bloqueada: ${decodedUrl}`);
          return;
        }
        if (config.trustedDomains.some(rx => rx.test(urlObj.hostname)) || config.trustedPaths.some(rx => rx.test(urlObj.pathname))) {
          console.log(`[${config.brand}] Requisição XHR permitida: ${decodedUrl}`);
          return origXhrOpen.apply(this, [args[0], decodedUrl, ...args.slice(2)]);
        }
      }
      return origXhrOpen.apply(this, args);
    };

    setInterval(() => {
      document.querySelectorAll('[data-arx-hidden], [data-arx-blocked]').forEach(el => {
        Object.defineProperty(el, 'offsetHeight', { configurable: true, value: 100 });
        Object.defineProperty(el, 'offsetWidth', { configurable: true, value: 100 });
        Object.defineProperty(el, 'style', { configurable: true, get: () => ({ display: 'block', visibility: 'visible', opacity: '1' }) });
        Object.defineProperty(el, 'hidden', { configurable: true, value: false });
        Object.defineProperty(el, 'clientHeight', { configurable: true, value: 100 });
        Object.defineProperty(el, 'clientWidth', { configurable: true, value: 100 });
        Object.defineProperty(el, 'getBoundingClientRect', {
          configurable: true,
          value: () => ({ width: 100, height: 100, top: 0, left: 0, bottom: 100, right: 100 })
        });
        if (el.tagName.toLowerCase() === 'img') {
          Object.defineProperty(el, 'naturalWidth', { configurable: true, value: 100 });
          Object.defineProperty(el, 'naturalHeight', { configurable: true, value: 100 });
          Object.defineProperty(el, 'complete', { configurable: true, value: true });
        }
      });
    }, 200);
  }

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(async () => {
        await limparAds();
        await acceptCookies();
      }, 1000);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });
  }

  setTimeout(() => limparAds(), 500);
  setTimeout(() => acceptCookies(), 1000);
  setTimeout(() => acceptCookies(), 2000);
  setTimeout(() => acceptCookies(), 4000);
  observarMutacoes();
  protegerContraPopups();

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo`);
})();
