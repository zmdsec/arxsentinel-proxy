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
      "main",
      "content",
      "article",
      "body",
      "texto",
      "chapter-content",
      "manga-image",
      "reader",
      "comic",
      "cookie-consent",
      "cookie-notice",
      "accept-cookies",
      "consent-banner",
      "gdpr",
      "privacy-policy",
      "cookie-popup",
      "accept-all"
    ],
    keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
    trustedDomains: [
      /webtoons\.com$/,
      /mangakakalot\.com$/,
      /readmanganato\.com$/,
      /mangadex\.org$/,
      /cdn\./,
      /cloudflare\.com$/,
      /akamai\.net$/,
      /cookiebot\.com$/,
      /onetrust\.com$/,
      /consensu\.org$/
    ],
    secretKey: 'arx_intel_secret_2025',
    version: '1.3.3',
    brand: 'Arx Intel',
    feedbackTTL: 30 * 24 * 60 * 60 * 1000,
    maxFeedbackEntries: 1000
  };

  const scoreCache = new Map();
  let userFeedback = {};

  function simpleHash(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  try {
    const stored = localStorage.getItem('arxCortexFeedback');
    if (stored) {
      const parsed = JSON.parse(stored);
      if (parsed.hash === simpleHash(JSON.stringify(parsed.feedback) + config.secretKey)) {
        const now = Date.now();
        for (const id in parsed.feedback) {
          if (parsed.feedback[id].timestamp >= now - config.feedbackTTL) {
            userFeedback[id] = parsed.feedback[id];
          }
        }
      } else {
        console.warn(`[${config.brand}] Feedback corrompido no localStorage.`);
      }
    }
  } catch (e) {
    console.warn(`[${config.brand}] Erro ao carregar feedback do localStorage:`, e);
  }

  function saveFeedback() {
    try {
      const feedbackCount = Object.keys(userFeedback).length;
      if (feedbackCount > config.maxFeedbackEntries) {
        const oldest = Object.keys(userFeedback).sort((a, b) =>
          userFeedback[a].timestamp - userFeedback[b].timestamp)[0];
        delete userFeedback[oldest];
      }
      const data = {
        feedback: userFeedback,
        hash: simpleHash(JSON.stringify(userFeedback) + config.secretKey)
      };
      localStorage.setItem('arxCortexFeedback', JSON.stringify(data));
    } catch (e) {
      console.error(`[${config.brand}] Erro ao salvar feedback:`, e);
    }
  }

  async function loadExternalBlockList() {
    try {
      const cacheKey = 'arxCortexBlockList';
      const cachedList = localStorage.getItem(cacheKey);
      if (cachedList) {
        config.blockPatterns.push(...JSON.parse(cachedList).map(s => new RegExp(s, 'i')));
        console.log(`[${config.brand}] Carregadas ${config.blockPatterns.length} regras do cache`);
        return;
      }
      const response = await fetch('https://easylist.to/easylist/easylist.txt');
      const lines = (await response.text()).split('\n');
      const newPatterns = lines
        .filter(line => line && !line.startsWith('!') && line.includes('||'))
        .map(line => new RegExp(line.replace('||', '').split('^')[0].replace('.', '\\.'), 'i'));
      config.blockPatterns.push(...newPatterns);
      localStorage.setItem(cacheKey, JSON.stringify(newPatterns.map(rx => rx.source)));
      console.log(`[${config.brand}] Carregadas ${newPatterns.length} regras externas`);
    } catch (e) {
      console.warn(`[${config.brand}] Falha ao carregar listas externas:`, e);
    }
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

      // Preservar elementos de cookies e domínios confiáveis
      if (src && config.trustedDomains.some(rx => rx.test(new URL(src, window.location.href).hostname))) {
        return 0;
      }
      if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy') || txt.includes('aceitar')) {
        return 0;
      }

      let score = 0;
      if (config.keywords.some(w => txt.includes(w))) score += 3;
      if (["iframe", "aside", "section"].includes(tag)) score += 2;
      if (["script"].includes(tag)) score += 0.5; // Peso ainda mais reduzido para scripts
      if ([...el.attributes].some(a => /onload|onclick|onmouseover|onerror/.test(a.name))) score += 1;
      const style = window.getComputedStyle(el);
      if (parseInt(style.zIndex) > 100 || style.position === "fixed") score += 2;
      if (el.offsetHeight < 120 || el.offsetWidth < 300) score += 2;
      if (config.blockPatterns.some(rx => rx.test(html))) score += 4;

      const elID = cacheKey;
      if (userFeedback[elID]?.tipo === 'ad') score += 5;
      if (userFeedback[elID]?.tipo === 'ok') score -= 3;

      scoreCache.set(cacheKey, score);
      return score;
    } catch (e) {
      console.warn(`[${config.brand}] Erro ao pontuar elemento:`, e);
      return 0;
    }
  }

  async function limparAds(root = document) {
    const elements = root.querySelectorAll('iframe, script, div, aside, section');
    let blockedCount = 0;

    for (const el of elements) {
      try {
        const className = el.className?.toLowerCase?.() || "";
        if (config.whitelist.some(w => className.includes(w))) continue;

        const score = await scoreElemento(el);
        if (score >= 5) {
          el.setAttribute("data-arx-hidden", "true");
          el.style.display = "none";
          blockedCount++;
        }
      } catch (e) {
        console.warn(`[${config.brand}] Falha ao processar elemento:`, e);
      }
    }

    console.log(`[${config.brand}] Bloqueados ${blockedCount} elementos nesta varredura`);
  }

  async function acceptCookies() {
    try {
      const selectors = [
        'button[class*="cookie"], button[class*="consent"], button[class*="accept"], button[class*="gdpr"], button[class*="privacy"]',
        'a[class*="cookie"], a[class*="consent"], a[class*="accept"], a[class*="gdpr"], a[class*="privacy"]',
        'div[class*="cookie"][role="button"], div[class*="consent"][role="button"], div[class*="accept"][role="button"]',
        'button:contains("Aceitar"), button:contains("Accept"), button:contains("Consent"), button:contains("OK")'
      ].join(', ');
      
      const cookieButtons = document.querySelectorAll(selectors);
      let clicked = false;
      for (const btn of cookieButtons) {
        try {
          btn.click();
          console.log(`[${config.brand}] Botão de cookies clicado: ${btn.outerHTML.slice(0, 50)}...`);
          clicked = true;
        } catch (e) {
          console.warn(`[${config.brand}] Falha ao clicar no botão de cookies:`, e);
        }
      }
      if (clicked) {
        // Reexecutar limpeza após aceitar cookies
        setTimeout(() => limparAds(), 500);
      }
      return clicked;
    } catch (e) {
      console.warn(`[${config.brand}] Erro ao aceitar cookies:`, e);
      return false;
    }
  }

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(async () => {
        await limparAds();
        await acceptCookies(); // Tentar aceitar cookies em mutações
      }, 200);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  let lastFeedbackTime = 0;
  window.ArxCortex = {
    feedback: async (texto, tipo) => {
      if (!['ad', 'ok'].includes(tipo)) {
        console.warn(`[${config.brand}] Tipo de feedback inválido:`, tipo);
        return;
      }
      const now = Date.now();
      if (now - lastFeedbackTime < 1000) {
        console.warn(`[${config.brand}] Feedback muito frequente.`);
        return;
      }
      lastFeedbackTime = now;
      const id = simpleHash(texto.slice(0, 50));
      userFeedback[id] = { tipo, timestamp: now };
      saveFeedback();
      scoreCache.delete(id);
      console.log(`[${config.brand}] Feedback registrado: ${tipo} para ID ${id}`);
      // Reexecutar limpeza após feedback
      await limparAds();
    },
    getStats: () => ({
      blockedCount: scoreCache.size,
      feedbackCount: Object.keys(userFeedback).length
    }),
    version: config.version,
    limparAds,
    acceptCookies
  };
  Object.defineProperty(window, 'ArxCortex', { value: window.ArxCortex, writable: false });

  if (window.localStorage) {
    loadExternalBlockList();
    limparAds();
    setTimeout(() => acceptCookies(), 1000); // Tentar aceitar cookies após 1s
    observarMutacoes();
  } else {
    console.warn(`[${config.brand}] localStorage não disponível. Feedback desativado.`);
    limparAds();
    observarMutacoes();
  }

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo no navegador`);
})();
