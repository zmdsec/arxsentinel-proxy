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
    heuristicWeights: {
      keywords: 3,
      tags: { iframe: 1.5, aside: 1.5, section: 1.5, script: 0.3 },
      events: 1,
      styles: 1.5,
      size: 1.5,
      patterns: 4
    },
    secretKey: 'arx_intel_secret_2025',
    version: '1.3.5',
    brand: 'Arx Intel',
    feedbackTTL: 30 * 24 * 60 * 60 * 1000,
    maxFeedbackEntries: 1000
  };

  const scoreCache = new Map();
  let userFeedback = {};
  let dynamicWeights = { ...config.heuristicWeights }; // Pesos ajustáveis

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
      if (config.keywords.some(w => txt.includes(w))) score += dynamicWeights.keywords;
      if (dynamicWeights.tags[tag]) score += dynamicWeights.tags[tag];
      if ([...el.attributes].some(a => /onload|onclick|onmouseover|onerror/.test(a.name))) score += dynamicWeights.events;
      const style = window.getComputedStyle(el);
      if (parseInt(style.zIndex) > 100 || style.position === "fixed") score += dynamicWeights.styles;
      if (el.offsetHeight < 120 || el.offsetWidth < 300) score += dynamicWeights.size;
      if (config.blockPatterns.some(rx => rx.test(html))) score += dynamicWeights.patterns;

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
        'button[class*="cookie"], button[class*="consent"], button[class*="accept"], button[class*="gdpr"], button[class*="privacy"], button[class*="cookie-accept"], button[class*="accept-all"], button[class*="cookie-btn"]',
        'a[class*="cookie"], a[class*="consent"], a[class*="accept"], a[class*="gdpr"], a[class*="privacy"]',
        'div[class*="cookie"][role="button"], div[class*="consent"][role="button"], div[class*="accept"][role="button"]',
        'button:contains("Aceitar"), button:contains("Accept"), button:contains("Consent"), button:contains("OK"), button:contains("Agree"), button:contains("Allow"), button:contains("Confirmar")'
      ].join(', ');

      const cookieButtons = document.querySelectorAll(selectors);
      let clicked = false;
      for (const btn of cookieButtons) {
        try {
          // Adicionar delay aleatório para simular clique humano
          setTimeout(() => {
            btn.click();
            console.log(`[${config.brand}] Botão de cookies clicado: ${btn.outerHTML.slice(0, 50)}...`);
          }, Math.random() * 100 + 50);
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
    } detch (e) {
      console.warn(`[${config.brand}] Erro ao aceitar cookies:`, e);
      return false;
    }
  }

  function ajustarPesos(feedbackType, tag) {
    // Ajustar pesos dinamicamente com base no feedback
    if (feedbackType === 'ok' && dynamicWeights.tags[tag]) {
      dynamicWeights.tags[tag] = Math.max(0.1, dynamicWeights.tags[tag] - 0.1); // Reduz peso
      console.log(`[${config.brand}] Peso ajustado para tag ${tag}: ${dynamicWeights.tags[tag]}`);
    } else if (feedbackType === 'ad' && dynamicWeights.tags[tag]) {
      dynamicWeights.tags[tag] += 0.2; // Aumenta peso
      console.log(`[${config.brand}] Peso ajustado para tag ${tag}: ${dynamicWeights.tags[tag]}`);
    }
  }

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(async () => {
        await limparAds();
        await acceptCookies();
      }, 200);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });
  }

  let lastFeedbackTime = 0;
  window.ArxCortex = {
    feedback: async (texto, tipo, tag = null) => {
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
      userFeedback[id] = { tipo, timestamp: now, tag };
      saveFeedback();
      scoreCache.delete(id);
      if (tag) ajustarPesos(tipo, tag.toLowerCase());
      console.log(`[${config.brand}] Feedback registrado: ${tipo} para ID ${id} (tag: ${tag || 'nenhuma'})`);
      await limparAds();
      await acceptCookies();
    },
    getStats: () => ({
      blockedCount: scoreCache.size,
      feedbackCount: Object.keys(userFeedback).length,
      weights: { ...dynamicWeights }
    }),
    version: config.version,
    limparAds,
    acceptCookies
  };
  Object.defineProperty(window, 'ArxCortex', { value: window.ArxCortex, writable: false });

  if (window.localStorage) {
    loadExternalBlockList();
    limparAds();
    setTimeout(() => acceptCookies(), 1000);
    setTimeout(() => acceptCookies(), 3000);
    setTimeout(() => acceptCookies(), 5000); // Tentar em 5s para banners muito lentos
    observarMutacoes();
  } else {
    console.warn(`[${config.brand}] localStorage não disponível. Feedback desativado.`);
    limparAds();
    observarMutacoes();
  }

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo no navegador`);
})();
