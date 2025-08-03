// src/index.js (ArxSentinel v1.8 + ArxCortex v1.3 corrigido)

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { JSDOM } = require('jsdom');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const URL = require('url-parse');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const cache = new NodeCache({ stdTTL: 600 });

app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: '*', methods: ['GET'] }));

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
  } catch (e) {
    return 0;
  }
}

function sanitizeHTML(html) {
  const dom = new JSDOM(html);
  const { document } = dom.window;

  document.querySelectorAll('iframe, script, div, aside, section').forEach(el => {
    try {
      const className = el.className?.toLowerCase?.() || "";
      if (whiteClassHints.some(hint => className.includes(hint))) return;
      const score = scoreElemento(el);
      if (score >= 8) { // menos agressivo
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
      }
    } catch (e) {}
  });

  // Injeta script da IA (ArxCortex)
  const scriptPath = path.join(__dirname, 'arxCortex.client.js');
  let clientScript = '';
  try {
    clientScript = fs.readFileSync(scriptPath, 'utf8');
  } catch (e) {
    console.warn("[WARN] Não foi possível carregar ArxCortex.client.js");
  }

  const serialized = dom.serialize();
  if (!serialized.includes('</body>')) return serialized + `<script>${clientScript}</script>`;
  return serialized.replace('</body>', `<script>${clientScript}</script></body>`);
}

app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('URL não fornecida.');
  const urlObj = new URL(url);
  if (!['http:', 'https:'].includes(urlObj.protocol)) return res.status(400).send('Protocolo inválido.');

  const cacheKey = `arx_${url}`;
  const cachedResponse = cache.get(cacheKey);
  if (cachedResponse) return res.send(cachedResponse);

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      headers: { 'User-Agent': 'ArxSentinel/1.8' }
    });
    const clean = sanitizeHTML(response.data);
    cache.set(cacheKey, clean);
    res.send(clean);
  } catch (err) {
    console.error("Erro ao processar:", err.message);
    res.status(500).send('Erro ao buscar ou processar o conteúdo.');
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ ArxSentinel + ArxCortex rodando em http://localhost:${PORT}`);
});
