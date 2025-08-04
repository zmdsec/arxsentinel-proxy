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
  whiteClassHints: [
    "main", "content", "article", "body", "texto",
    "chapter-content", "manga-image", "reader", "comic",
    "wrapper", "container", "root"
  ],
  keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
  trustedDomains: [
    /webtoons\.com$/, /mangakakalot\.com$/, /readmanganato\.com$/,
    /cdn\./, /cloudflare\.com$/, /akamai\.net$/
  ],
  brand: {
    name: 'Arx Intel',
    version: '1.9.2',
    website: 'https://arxintel.com'
  }
};

// Segurança leve (CSP desativado para compatibilidade)
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: '*', methods: ['GET'] }));
app.use('/client', express.static(__dirname));

function scoreElemento(el, targetUrl) {
  try {
    let score = 0;
    const html = el.outerHTML || "";
    const txt = el.textContent?.toLowerCase() || "";
    const tag = el.tagName?.toLowerCase() || "";
    const src = el.src || el.getAttribute('href') || "";

    if (src && config.trustedDomains.some(rx => rx.test(new URL(src, targetUrl).hostname))) return 0;
    if (config.keywords.some(w => txt.includes(w))) score += 3;
    if (["iframe", "aside", "section", "script"].includes(tag)) score += 1.5;
    if (el.getAttributeNames?.()?.some(a => /on(load|click|mouseover|error)/.test(a))) score += 1;
    const style = el.style || {};
    if (style.position === "fixed" || parseInt(style.zIndex) > 100) score += 1.5;
    if (el.offsetHeight < 120 || el.offsetWidth < 300) score += 1.5;
    if (config.blockPatterns.some(rx => rx.test(html))) score += 4;

    return score;
  } catch {
    return 0;
  }
}

function sanitizeHTML(html, targetUrl) {
  const dom = new JSDOM(html);
  const { document } = dom.window;
  const baseProxy = 'https://arxsentinel-proxy.onrender.com/proxy?url=';
  const baseOrigin = new URL(targetUrl).origin;

  // IA: bloqueia apenas elementos com score >= 8
  let blockedCount = 0;
  document.querySelectorAll('iframe, script, div, aside, section').forEach(el => {
    try {
      const className = el.className?.toLowerCase?.() || "";
      if (config.whiteClassHints.some(hint => className.includes(hint))) return;
      const score = scoreElemento(el, targetUrl);
      if (score >= 8) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
      }
    } catch { }
  });

  // Reescreve apenas <a> e <img>
  ['a[href]', 'img[src]'].forEach(selector => {
    document.querySelectorAll(selector).forEach(el => {
      const attr = el.hasAttribute('href') ? 'href' : 'src';
      let url = el.getAttribute(attr);
      if (!url) return;
      if (url.startsWith('http')) {
        el.setAttribute(attr, `${baseProxy}${encodeURIComponent(url)}`);
      } else if (!url.startsWith('#') && !url.startsWith('javascript:')) {
        const absolute = new URL(url, baseOrigin).href;
        el.setAttribute(attr, `${baseProxy}${encodeURIComponent(absolute)}`);
      }
    });
  });

  // Base tag para resolver caminhos relativos
  const baseTag = document.createElement('base');
  baseTag.href = baseOrigin;
  document.head.appendChild(baseTag);

  // IA cliente (opcional)
  let cortexScript = '';
  try {
    cortexScript = fs.readFileSync(__dirname + '/arxCortex.client.js', 'utf8');
  } catch (e) {
    console.error(`[${config.brand.name}] Falha ao carregar arxCortex.client.js`);
  }
  const script = `<script>${cortexScript}</script>`;
  console.log(`[${config.brand.name}] Bloqueados ${blockedCount} elementos no servidor (${targetUrl})`);
  return dom.serialize().replace('</head>', `${script}</head>`);
}

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
      headers: {
        'User-Agent': `ArxSentinel/${config.brand.version}`,
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.5'
      }
    });
    const cleaned = sanitizeHTML(response.data, url);
    cache.set(cacheKey, cleaned);
    res.send(cleaned);
  } catch (err) {
    console.error(`[${config.brand.name}] Erro ao processar ${url}:`, err.message);
    res.status(500).send('Erro ao buscar ou processar o conteúdo.');
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ ArxSentinel Proxy ${config.brand.version} rodando: http://localhost:${PORT}`);
});
