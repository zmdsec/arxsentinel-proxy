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
    "main-nav", "series-menu", "category-link", "nav-item", "menu-link",
    "site-nav", "top-menu", "chapter-list", "manga-nav" // Adicionados
  ],
  trustedPaths: [
    /\/obras/, /\/manga/, /\/chapter/, /\/noticia/, /\/politica/,
    /\/series/, /\/works/, /\/home/, /\/index/, /\/catalog/, /\/library/,
    /\/mangas/, /\/archive/, /\/manga-list/, /\/chapter-list/, /\/series-list/ // Adicionados
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
  brand: {
    name: 'Arx Intel',
    version: '1.9.18',
    website: 'https://arxintel.com'
  },
  heuristicWeights: {
    keywords: 4,
    tags: { iframe: 2, aside: 2, script: 0.8, a: 0.3, img: 0, div: 0.1, section: 0.1 },
    events: 1,
    styles: 1.5,
    size: 1.5,
    patterns: 5,
    malicious: 15,
    trustedDomain: -3
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
    const className = el.className?.toLowerCase?.() || "";

    if (src && (src.startsWith('data:image/') || config.trustedDomains.some(rx => rx.test(new URL(src, targetUrl).hostname)) || config.trustedPaths.some(rx => rx.test(src)))) {
      return config.heuristicWeights.trustedDomain;
    }
    if (txt.includes('cookie') || txt.includes('consent') || txt.includes('privacy') || txt.includes('aceitar')) return 0;
    if (config.whiteClassHints.some(hint => className.includes(hint))) return 0;
    if (tag === 'a' && (config.navigationClasses.some(c => className.includes(c)) || config.trustedPaths.some(rx => rx.test(src)))) return 0;

    if (config.keywords.some(w => txt.includes(w))) score += config.heuristicWeights.keywords;
    if (["iframe", "aside"].includes(tag)) score += config.heuristicWeights.tags[tag] || 0;
    if (["a"].includes(tag)) score += config.heuristicWeights.tags.a;
    if (["section", "div", "img"].includes(tag)) score += 0;
    if (el.getAttributeNames?.()?.some(a => /on(load|click|mouseover|error|focus|blur|unload|beforeunload|pagehide)/.test(a))) score += config.heuristicWeights.events;
    const style = el.style || {};
    if (style.position === "fixed" || parseInt(style.zIndex) > 100) score += config.heuristicWeights.styles;
    if (el.offsetHeight < 120 || el.offsetWidth < 300) score += config.heuristicWeights.size;
    if (config.blockPatterns.some(rx => rx.test(html))) score += config.heuristicWeights.patterns;
    if (config.maliciousPatterns.some(rx => rx.test(html))) score += config.heuristicWeights.malicious;

    return score;
  } catch {
    return 0;
  }
}

function sanitizeHTML(html, targetUrl) {
  const dom = new JSDOM(html);
  const { document } = dom.window;
  const baseOrigin = new URL(targetUrl).origin;

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
            console.log(`[${config.brand.name}] Script bloqueado: ${src || 'inline'} (motivo: padrão malicioso ou de anúncio)`);
            return;
          }
          if (src && /reader\.js|lazyload\.js|image-loader|manga-loader|navigation\.js|menu\.js|chapter-loader|site-nav|main-nav|manga-nav|page-nav/.test(src)) {
            console.log(`[${config.brand.name}] Script essencial permitido: ${src}`);
            return;
          }
        }
        el.setAttribute("data-arx-hidden", "true");
        el.style.display = "none";
        blockedCount++;
      }
    } catch { }
  });

  document.querySelectorAll('div, section, img').forEach(el => {
    const className = el.className?.toLowerCase?.() || "";
    if (config.whiteClassHints.some(hint => className.includes(hint))) {
      el.removeAttribute('data-arx-hidden');
      el.style.display = '';
    }
    if (el.tagName.toLowerCase() === 'img' && (el.hasAttribute('data-src') || el.hasAttribute('data-lazy-src'))) {
      const src = el.getAttribute('data-src') || el.getAttribute('data-lazy-src');
      el.setAttribute('src', src);
      console.log(`[${config.brand.name}] Lazy-loading forçado no servidor: ${src}`);
    }
  });

  document.querySelectorAll('a[href]').forEach(el => {
    let url = el.getAttribute('href');
    if (!url || url.startsWith('javascript:') || url.startsWith('#') || url.startsWith('data:')) return;
    try {
      const decodedUrl = decodeURIComponent(url);
      const urlObj = new URL(decodedUrl, targetUrl);
      const hostname = urlObj.hostname;
      const pathname = urlObj.pathname;
      if (config.trustedDomains.some(rx => rx.test(hostname)) || config.trustedPaths.some(rx => rx.test(pathname))) {
        const newUrl = config.proxyBase + encodeURIComponent(urlObj.href);
        el.setAttribute('href', newUrl);
        console.log(`[${config.brand.name}] Link reescrito para proxy: ${url} -> ${newUrl}`);
      } else {
        el.setAttribute('href', 'javascript:void(0)');
        el.setAttribute('data-arx-blocked', 'true');
        blockedCount++;
        console.log(`[${config.brand.name}] Link bloqueado: ${url} (motivo: domínio não confiável ou padrão de bloqueio)`);
      }
    } catch (e) {
      console.warn(`[${config.brand.name}] Falha ao reescrever URL: ${url} - ${e.message}`);
      el.setAttribute('href', url);
    }
  });

  document.querySelectorAll('[onclick]').forEach(el => {
    const className = el.className?.toLowerCase?.() || "";
    const href = el.getAttribute('href') || '';
    const onclick = el.getAttribute('onclick') || '';
    if ((config.trustedDomains.some(rx => rx.test(new URL(targetUrl).hostname)) || config.trustedPaths.some(rx => rx.test(href))) &&
        (config.navigationClasses.some(c => className.includes(c)) || config.trustedPaths.some(rx => rx.test(href)) || /window\.location|location\.href|location\.assign|location\.replace/.test(onclick))) {
      const match = onclick.match(/['"]([^'"]+)['"]/i) || onclick.match(/location\.(?:href|assign|replace)\s*=\s*['"]([^'"]+)['"]/i);
      if (match) {
        const url = match[1];
        try {
          const urlObj = new URL(url, targetUrl);
          if (config.trustedDomains.some(rx => rx.test(urlObj.hostname)) || config.trustedPaths.some(rx => rx.test(urlObj.pathname))) {
            const newUrl = config.proxyBase + encodeURIComponent(urlObj.href);
            el.setAttribute('onclick', `window.location.href='${newUrl}'`);
            console.log(`[${config.brand.name}] Evento onclick reescrito para proxy: ${url} -> ${newUrl}`);
          } else {
            el.removeAttribute('onclick');
            el.setAttribute('data-arx-blocked', 'true');
            blockedCount++;
            console.log(`[${config.brand.name}] Evento onclick bloqueado: ${onclick.slice(0, 50)}... (motivo: domínio não confiável)`);
          }
        } catch (e) {
          console.warn(`[${config.brand.name}] Falha ao reescrever onclick: ${onclick} - ${e.message}`);
        }
      }
      return;
    }
    if (config.maliciousPatterns.some(rx => rx.test(onclick))) {
      el.removeAttribute('onclick');
      el.setAttribute('data-arx-blocked', 'true');
      blockedCount++;
      console.log(`[${config.brand.name}] Evento onclick bloqueado: ${onclick.slice(0, 50)}... (motivo: padrão malicioso)`);
    }
  });

  const baseTag = document.createElement('base');
  baseTag.href = baseOrigin;
  document.head.appendChild(baseTag);

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
  let url = req.query.url;
  if (!url) return res.status(400).send('URL não fornecida.');
  try {
    url = decodeURIComponent(url);
  } catch (e) {
    console.warn(`[${config.brand.name}] Falha ao decodificar URL: ${url} - ${e.message}`);
    return res.status(400).send('URL inválida.');
  }
  const urlObj = new URL(url);
  if (!['http:', 'https:'].includes(urlObj.protocol)) return res.status(400).send('Protocolo inválido.');

  const cacheKey = `arx_${url}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.send(cached);

  if (config.trustedDomains.some(rx => rx.test(urlObj.hostname)) || config.trustedPaths.some(rx => rx.test(urlObj.pathname))) {
    console.log(`[${config.brand.name}] URL confiável permitida: ${url}`);
  } else if (config.blockPatterns.some(rx => rx.test(url))) {
    console.log(`[${config.brand.name}] URL bloqueada: ${url} (motivo: padrão de bloqueio)`);
    return res.status(403).send('URL bloqueada pelo ArxSentinel.');
  }

  try {
    const response = await axios.get(url, {
      timeout: 90000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,image/webp,image/apng,image/*,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': urlObj.origin,
        'Origin': urlObj.origin,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Origin, X-Requested-With, Content-Type, Accept',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
      }
    });
    const cleaned = sanitizeHTML(response.data, url);
    cache.set(cacheKey, cleaned);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.send(cleaned);
  } catch (err) {
    console.error(`[${config.brand.name}] Erro ao carregar a página: ${url} - ${err.message}${err.response ? ` (HTTP ${err.response.status})` : ''}`);
    if (err.message.includes('CORS') || err.response?.status === 403) {
      console.warn(`[${config.brand.name}] Tentando sem proxy devido a CORS: ${url}`);
      try {
        const response = await axios.get(url, {
          timeout: 90000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
          }
        });
        console.log(`[${config.brand.name}] Fallback sem proxy bem-sucedido: ${url}`);
        const cleaned = sanitizeHTML(response.data, url);
        cache.set(cacheKey, cleaned);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.send(cleaned);
      } catch (fallbackErr) {
        console.error(`[${config.brand.name}] Fallback sem proxy falhou: ${url} - ${fallbackErr.message}`);
        res.status(500).send('Erro ao buscar ou processar o conteúdo.');
      }
    } else {
      res.status(500).send('Erro ao buscar ou processar o conteúdo.');
    }
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ ArxSentinel Proxy ${config.brand.version} rodando: http://localhost:${PORT}`);
});
