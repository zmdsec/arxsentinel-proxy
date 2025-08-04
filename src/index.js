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

// Configurações da Arx Intel
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
  whiteClassHints: ["main", "content", "article", "body", "texto", "chapter-content", "manga-image", "reader", "comic"],
  keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
  trustedDomains: [/webtoons\.com$/, /mangakakalot\.com$/, /readmanganato\.com$/, /cdn\./, /cloudflare\.com$/, /akamai\.net$/],
  externalBlockLists: ['https://easylist.to/easylist/easylist.txt'],
  brand: {
    name: 'Arx Intel',
    version: '1.9.1',
    website: 'https://arxintel.com'
  }
};

// Segurança
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "*.arxintel.com"],
      imgSrc: ["'self'", "data:", "*"],
      connectSrc: ["'self'", "*.arxintel.com", "*.webtoons.com", "*.mangakakalot.com", "*.readmanganato.com"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: ['http://localhost:3000', 'https://arxintel.com', '*'], methods: ['GET'] }));

// Servir ArxCortex.js
app.use('/client', express.static(__dirname));

// Carregar listas externas
async function loadExternalBlockList() {
  for (const url of config.externalBlockLists) {
    try {
      const response = await axios.get(url, { timeout: 10000 });
      const lines = response.data.split('\n');
      const newPatterns = lines
        .filter(line => line && !line.startsWith('!') && line.includes('||'))
        .map(line => new RegExp(line.replace('||', '').split('^')[0].replace('.', '\\.'), 'i'));
      config.blockPatterns.push(...newPatterns);
      console.log(`[${config.brand.name}] Carregadas ${newPatterns.length} regras de ${url}`);
    } catch (e) {
      console.error(`[${config.brand.name}] Erro ao carregar ${url}:`, e.message);
    }
  }
}

// Heurística de bloqueio
function scoreElemento(el, targetUrl) {
  try {
    let score = 0;
    const html = el.outerHTML || "";
    const txt = el.textContent?.toLowerCase() || "";
    const tag = el.tagName?.toLowerCase() || "";
    const src = el.src || el.getAttribute('href') || "";

    // Evitar bloquear recursos de domínios confiáveis
    if (src && config.trustedDomains.some(rx => rx.test(new URL(src, targetUrl).hostname))) {
      return 0;
    }

    if (config.keywords.some(w => txt.includes(w))) score += 3;
    if (["iframe", "aside", "section"].includes(tag)) score += 2;
    if (["script"].includes(tag)) score += 1; // Reduzir peso de scripts
    if (el.getAttributeNames?.()?.some(a => /onload|onclick|onmouseover|onerror/.test(a))) score += 2;
    const style = el.style || {};
    if (style.zIndex > 100 || style.position === "fixed") score += 2;
    if (el.offsetHeight < 120 || el.offsetWidth < 300) score += 2;
    if (config.blockPatterns.some(rx => rx.test(html))) score += 4;

    return score;
  } catch {
    return 0;
  }
}

// Limpeza do HTML + script da IA
function sanitizeHTML(html, targetUrl) {
  const dom = new JSDOM(html);
  const { document } = dom.window;
  const baseProxy = 'https://arxsentinel-proxy.onrender.com/proxy?url=';
  const baseOrigin = new URL(targetUrl).origin;

  // BLOQUEIO: não bloqueia <img>, só tags críticas
  let blockedCount = 0;
  document.querySelectorAll('iframe, script, div, aside, section').forEach(el => {
    try {
      const className = el.className?.toLowerCase?.() || "";
      if (config.whiteClassHints.some(hint => className.includes(hint))) return;
      const score = scoreElemento(el, targetUrl);
      if (score >= 5) {
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
      }
    } catch { }
  });

  // Reescrever URLs em <a>, <img>, <script>, <link>, <source>
  ['a[href]', 'img[src]', 'script[src]', 'link[href]', 'source[src]'].forEach(selector => {
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

  // Adicionar base tag para resolver URLs relativas
  const baseTag = document.createElement('base');
  baseTag.href = baseOrigin;
  document.head.appendChild(baseTag);

  // Script do lado cliente (ArxCortex IA)
  let cortexScript;
  try {
    cortexScript = fs.readFileSync(__dirname + '/arxCortex.client.js', 'utf8');
  } catch (e) {
    console.error(`[${config.brand.name}] Erro ao carregar arxCortex.client.js:`, e.message);
    cortexScript = '';
  }
  const script = `<script>${cortexScript}</script>`;
  console.log(`[${config.brand.name}] Bloqueados ${blockedCount} elementos no servidor para ${targetUrl}`);
  return dom.serialize().replace('</head>', `${script}</head>`);
}

// Rota principal
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('URL não fornecida.');
  const urlObj = new URL(url);
  if (!['http:', 'https:'].includes(urlObj.protocol)) return res.status(400).send('Protocolo inválido.');

  const cacheKey = `arx_${url}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    console.log(`[${config.brand.name}] Retornando resposta do cache para: ${url}`);
    return res.send(cached);
  }

  try {
    const response = await axios.get(url, {
      timeout: 10000,
      headers: {
        'User-Agent': `ArxSentinel/${config.brand.version} by ${config.brand.name}`,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
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

// Inicializar servidor
async function startServer() {
  await loadExternalBlockList();
  app.listen(PORT, () => {
    console.log(`🛡️ ArxSentinel Proxy v${config.brand.version} by ${config.brand.name} rodando em http://localhost:${PORT}`);
  });
}

startServer();
