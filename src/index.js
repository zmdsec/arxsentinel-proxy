// src/index.js
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { JSDOM } = require('jsdom');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const fs = require('fs');
const URL = require('url-parse');

const app = express();
const PORT = process.env.PORT || 3000;
const cache = new NodeCache({ stdTTL: 600 });

// Segurança
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: '*', methods: ['GET'] }));

// Regras de bloqueio
const blockPatterns = [
  /googlesyndication/i,
  /doubleclick/i,
  /adsystem/i,
  /taboola/i,
  /outbrain/i,
  /facebook.net/i,
  /analytics/i,
  /track|ad|sponsored|banner|pixel|beacon|impression|click/i
];
const whiteClassHints = ["main", "content", "article", "body", "texto"];

// Heurística de bloqueio
function scoreElemento(el) {
  try {
    let score = 0;
    const html = el.outerHTML || "";
    const txt = el.textContent?.toLowerCase() || "";
    const tag = el.tagName?.toLowerCase() || "";
    const keywords = ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"];

    if (keywords.some(w => txt.includes(w))) score += 3;
    if (["iframe", "script", "aside", "section"].includes(tag)) score += 2;
    if (el.getAttributeNames?.()?.some(a => /onload|onclick|onmouseover|onerror/.test(a))) score += 2;
    const style = el.style || {};
    if (style.zIndex > 100 || style.position === "fixed") score += 2;
    if (el.offsetHeight < 120 || el.offsetWidth < 300) score += 2;
    if (blockPatterns.some(rx => rx.test(html))) score += 4;

    return score;
  } catch {
    return 0;
  }
}

// Limpeza do HTML + script da IA
function sanitizeHTML(html, targetUrl) {
  const dom = new JSDOM(html);
  const { document } = dom.window;

  // BLOQUEIO: não bloqueia <img>, só tags críticas
  document.querySelectorAll('iframe, script, div, aside, section').forEach(el => {
    try {
      const className = el.className?.toLowerCase?.() || "";
      if (whiteClassHints.some(hint => className.includes(hint))) return;
      const score = scoreElemento(el);
      if (score >= 5) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
      }
    } catch { }
  });

  // Corrigir links <a> para continuar dentro do proxy
  const baseProxy = 'https://arxsentinel-proxy.onrender.com/proxy?url=';
  const baseOrigin = new URL(targetUrl).origin;
  document.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (href && !href.startsWith('http') && !href.startsWith('#')) {
      const absolute = new URL(href, baseOrigin).href;
      a.setAttribute('href', `${baseProxy}${encodeURIComponent(absolute)}`);
    } else if (href?.startsWith('http')) {
      a.setAttribute('href', `${baseProxy}${encodeURIComponent(href)}`);
    }
  });

  // Script do lado cliente (ArxCortex IA)
  const cortexScript = fs.readFileSync(__dirname + '/arxCortex.client.js', 'utf8');
  const script = `<script>${cortexScript}</script>`;
  return dom.serialize().replace('</body>', `${script}</body>`);
}

// Rota principal
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('URL não fornecida.');
  const urlObj = new URL(url);
  if (!['http:', 'https:'].includes(urlObj.protocol)) return res.status(400).send('Protocolo inválido.');

  const cacheKey = `arx_${url}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.send(cached);

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      headers: { 'User-Agent': 'ArxSentinel/1.9' }
    });
    const cleaned = sanitizeHTML(response.data, url);
    cache.set(cacheKey, cleaned);
    res.send(cleaned);
  } catch (err) {
    console.error("Erro:", err.message);
    res.status(500).send('Erro ao buscar ou processar o conteúdo.');
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ ArxSentinel Proxy v1.9 rodando em http://localhost:${PORT}`);
});
