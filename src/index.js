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
const cache = new NodeCache({ stdTTL: 300 });

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
    "wrapper", "container", "root",
    "cookie-consent", "cookie-notice", "accept-cookies",
    "consent-banner", "gdpr", "privacy-policy", "cookie-popup",
    "image-container", "manga-page", "reader-image",
    "reader-area", "chapter-image", "manga-reader", "chapter-container",
    "news", "noticia", "headline" // Adicionado pra G1
  ],
  keywords: ["anuncio", "publicidade", "patrocinado", "promo", "oferta", "adchoices"],
  trustedDomains: [
    /webtoons\.com$/, /mangakakalot\.com$/, /readmanganato\.com$/,
    /mangadex\.org$/, /cdn\./, /cloudflare\.com$/, /akamai\.net$/,
    /cookiebot\.com$/, /onetrust\.com$/, /consensu\.org$/, /cmp\./,
    /img\./, /images\./, /static\./,
    /manhastro\.net$/, /cdn\.manhastro\.net$/, /media\.manhastro\.net$/,
    /g1\.globo\.com$/ // Adicionado pra G1
  ],
  maliciousPatterns: [
    /eval\(/i,
    /Function\(/i,
    /window\.location\s*=\s*['"]http/i,
    /window\.open/i,
    /document\.write/i,
    /requestAnimationFrame/i,
    /Promise\.resolve/i
  ],
  brand: {
    name: 'Arx Intel',
    version: '1.9.8',
    website: 'https://arxintel.com'
  }
};

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
    const src = el.src || el.getAttribute('href') || el.getAttribute('data-href') || "";

    if (src && (src.startsWith('data:image/') || config.trustedDomains.some(rx => rx.test(new URL(src, targetUrl).hostname)))) return 0;
    if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy') || txt.includes('aceitar')) return 0;
    if (config.whiteClassHints.some(hint => el.className?.toLowerCase?.().includes(hint))) return 0;

    if (config.keywords.some(w => txt.includes(w))) score += 3;
    if (["iframe", "aside", "script"].includes(tag)) score += 1.5;
    if (["a"].includes(tag)) score += 0.5; // Reduzido pra links
    if (["section", "div", "img"].includes(tag)) score += 0; // Ignorar div, section, img
    if (el.getAttributeNames?.()?.some(a => /on(load|click|mouseover|error|focus|blur|unload|beforeunload|pagehide)/.test(a))) score += 1;
    const style = el.style || {};
    if (style.position === "fixed" || parseInt(style.zIndex) > 100) score += 1.5;
    if (el.offsetHeight < 120 || el.offsetWidth < 300) score += 1.5;
    if (config.blockPatterns.some(rx => rx.test(html))) score += 4;
    if (config.maliciousPatterns.some(rx => rx.test(html))) score += 12;

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

  // Bloquear scripts e links maliciosos
  let blockedCount = 0;
  document.querySelectorAll('script, iframe, aside').forEach(el => {
    try {
      const className = el.className?.toLowerCase?.() || "";
      if (config.whiteClassHints.some(hint => className.includes(hint))) return;

      const score = scoreElemento(el, targetUrl);
      if (score >= 5) {
        if (el.tagName.toLowerCase() === 'script') {
          const src = el.src || el.textContent;
          if (config.maliciousPatterns.some(rx => rx.test(src)) || config.blockPatterns.some(rx => rx.test(src))) {
            el.remove();
            blockedCount++;
            return;
          }
          if (src && /manhastro\.net|g1\.globo\.com/.test(new URL(src, targetUrl).hostname)) return;
        }
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
      }
    } catch { }
  });

  // Preservar divs, sections e imagens
  document.querySelectorAll('div, section, img').forEach(el => {
    const className = el.className?.toLowerCase?.() || "";
    if (config.whiteClassHints.some(hint => className.includes(hint))) {
      el.removeAttribute('data-arx-hidden');
      el.style.display = '';
    }
  });

  // Reescreve URLs, preservando relativas em domínios confiáveis
  ['a[href]', 'img[src]', 'script[src]'].forEach(selector => {
    document.querySelectorAll(selector).forEach(el => {
      const attr = el.hasAttribute('href') ? 'href' : 'src';
      let url = el.getAttribute(attr);
      if (!url) return;
      if (url.startsWith('data:image/')) return;
      if (url.startsWith('http')) {
        const urlObj = new URL(url, targetUrl);
        if (config.trustedDomains.some(rx => rx.test(urlObj.hostname))) {
          el.setAttribute(attr, url); // Preservar URL original
        } else {
          el.setAttribute(attr, `${baseProxy}${encodeURIComponent(url)}`);
        }
      } else if (!url.startsWith('#') && !url.startsWith('javascript:')) {
        try {
          const absolute = new URL(url, baseOrigin).href;
          if (config.trustedDomains.some(rx => rx.test(new URL(absolute, targetUrl).hostname))) {
            el.setAttribute(attr, absolute); // Usar URL absoluta
          } else {
            el.setAttribute(attr, `${baseProxy}${encodeURIComponent(absolute)}`);
          }
        } catch (e) {
          console.warn(`[${config.brand.name}] Falha ao reescrever URL: ${url}`);
          el.setAttribute(attr, url); // Preservar URL original
        }
      }
    });
  });

  // Neutralizar eventos inline, exceto em domínios confiáveis
  document.querySelectorAll('[onclick], [onmouseover], [onfocus], [onblur], [onunload], [onbeforeunload], [onpagehide]').forEach(el => {
    const events = ['onclick', 'onmouseover', 'onfocus', 'onblur', 'onunload', 'onbeforeunload', 'onpagehide'];
    const urlObj = new URL(targetUrl);
    if (config.trustedDomains.some(rx => rx.test(urlObj.hostname))) return;
    events.forEach(event => {
      const code = el.getAttribute(event);
      if (code && config.maliciousPatterns.some(rx => rx.test(code))) {
        el.removeAttribute(event);
        el.setAttribute('data-arx-blocked', 'true');
        blockedCount++;
      }
    });
  });

  // Base tag
  const baseTag = document.createElement('base');
  baseTag.href = baseOrigin;
  document.head.appendChild(baseTag);

  // Injetar ArxCortex
  let cortexScript = '';
  try {
    cortexScript = fs.readFileSync(__dirname + '/arxCortex.client.js', 'utf8');
  } catch (e) {
    console.error(`[${config.brand.name}] Falha ao carregar arxCortex.client.js:`, e);
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
      timeout: 20000,
      headers: {
        'User-Agent': `ArxSentinel/${config.brand.version}`,
        'Accept': 'text/html,application/xhtml+xml,image/webp,image/apng,image/*,*/*;q=0.8',
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
