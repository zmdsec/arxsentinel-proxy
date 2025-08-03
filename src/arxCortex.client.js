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
    whitelist: ["main", "content", "article", "body", "texto"],
    keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
    secretKey: 'arx_intel_secret_2025',
    version: '1.3',
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

  async function scoreElemento(el) {
    try {
      const html = el.outerHTML || "";
      const txt = el.textContent?.toLowerCase() || "";
      const tag = el.tagName?.toLowerCase() || "";
      const className = el.className?.toLowerCase?.() || "";
      const cacheKey = simpleHash(`${tag}_${className}_${txt.slice(0, 50)}`);

      if (scoreCache.has(cacheKey)) return scoreCache.get(cacheKey);

      let score = 0;
      if (config.keywords.some(w => txt.includes(w))) score += 3;
      if (["iframe", "script", "aside", "section"].includes(tag)) score += 2;
      if ([...el.attributes].some(a => /onload|onclick|onmouseover|onerror/.test(a.name))) score += 2;
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

  function observarMutacoes() {
    const observer = new MutationObserver(() => {
      clearTimeout(window.__arxDelay);
      window.__arxDelay = setTimeout(() => limparAds(), 150);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  let lastFeedbackTime = 0;
  window.ArxCortex = {
    feedback: async (texto, tipo) => {
      if (!['ad', 'ok'].includes(tipo)) return;
      const now = Date.now();
      if (now - lastFeedbackTime < 1000) return;

      lastFeedbackTime = now;
      const id = simpleHash(texto.slice(0, 50));
      userFeedback[id] = { tipo, timestamp: now };
      saveFeedback();
      scoreCache.delete(id);
      console.log(`[${config.brand}] Feedback registrado para "${tipo}"`);
    },
    getStats: () => ({
      blockedCount: scoreCache.size,
      feedbackCount: Object.keys(userFeedback).length
    }),
    version: config.version,
    limparAds
  };

  if (window.localStorage) {
    limparAds();
    observarMutacoes();
  }

  console.log(`🧠 ArxCortex v${config.version} by ${config.brand} - Ativo no navegador`);
})();
