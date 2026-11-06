'use strict';

/**
 * FR-1: Local Target Crawler & DOM Resource Extractor
 * Validates target URLs against the local allowlist (SSRF protection), fetches HTML & headers,
 * parses DOM resources using Cheerio, computes SHA-256 hashes for inline scripts/styles,
 * and identifies dangerous XSS sinks and inline event handlers.
 */

const crypto = require('node:crypto');
const cheerio = require('cheerio');
const { ERROR_CODES, DEFAULT_SYSTEM_CONFIG, AppError } = require('../contracts/schemas');

const INLINE_EVENT_ATTRIBUTES = [
  'onclick',
  'onload',
  'onerror',
  'onmouseover',
  'onmouseout',
  'onmouseenter',
  'onmouseleave',
  'onsubmit',
  'onfocus',
  'onblur',
  'onchange',
  'oninput',
  'onkeydown',
  'onkeyup',
  'onkeypress',
  'ondblclick',
  'oncontextmenu',
];

const EVAL_OR_DYNAMIC_CODE_REGEX = /\b(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`])/i;
const XSS_SINK_PATTERNS = [
  { name: 'document.write', regex: /\bdocument\.write(?:ln)?\s*\(/i },
  { name: 'innerHTML assignment', regex: /\.\s*innerHTML\s*=/i },
  { name: 'outerHTML assignment', regex: /\.\s*outerHTML\s*=/i },
  { name: 'location.hash sink', regex: /\blocation\.(?:hash|search|href)\b/i },
  { name: 'insertAdjacentHTML', regex: /\.\s*insertAdjacentHTML\s*\(/i },
];

/**
 * Computes a CSP-formatted SHA-256 base64 digest (`sha256-...`) for a given string.
 * @param {string} content
 * @returns {string}
 */
function computeSha256CspHash(content) {
  const digest = crypto.createHash('sha256').update(content, 'utf8').digest('base64');
  return `sha256-${digest}`;
}

/**
 * Resolves a potentially relative `/fixtures/...` path against `baseUrl` or returns `targetUrl`.
 * @param {string} targetUrl
 * @param {string} [baseUrl]
 * @returns {string}
 */
function resolveTargetUrl(targetUrl, baseUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new AppError(
      ERROR_CODES.ERR_VALIDATION_FAILED,
      'A valid targetUrl string is required for crawling.',
      400
    );
  }
  const trimmed = targetUrl.trim();
  if (!trimmed) {
    throw new AppError(
      ERROR_CODES.ERR_VALIDATION_FAILED,
      'A non-empty targetUrl string is required for crawling.',
      400
    );
  }
  if (trimmed.startsWith('/')) {
    const fallbackBase = baseUrl || 'http://localhost:3000';
    try {
      return new URL(trimmed, fallbackBase).toString();
    } catch (_err) {
      throw new AppError(
        ERROR_CODES.ERR_VALIDATION_FAILED,
        `Malformed relative target URL: ${trimmed}`,
        400
      );
    }
  }
  return trimmed;
}

/**
 * Validates a target URL against format rules, protocol restrictions, credential prohibitions,
 * and the administrator-configured local allowlist (SSRF protection).
 *
 * @param {string} targetUrl
 * @param {object} [systemConfig]
 * @param {string} [baseUrl]
 * @returns {{ parsedUrl: URL, normalizedUrl: string, normalizedOrigin: string }}
 */
function validateTargetUrl(targetUrl, systemConfig = DEFAULT_SYSTEM_CONFIG, baseUrl) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const resolvedInput = resolveTargetUrl(targetUrl, baseUrl);

  let parsed;
  try {
    parsed = new URL(resolvedInput);
  } catch (_err) {
    throw new AppError(
      ERROR_CODES.ERR_VALIDATION_FAILED,
      `Invalid URL syntax: "${targetUrl}". Provide a valid http:// or https:// URL.`,
      400,
      { targetUrl }
    );
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new AppError(
      ERROR_CODES.ERR_ALLOWLIST_DENIED,
      `Disallowed URL scheme "${parsed.protocol}". Only http: and https: targets on the local allowlist are permitted.`,
      403,
      { targetUrl, protocol: parsed.protocol }
    );
  }

  if (parsed.username || parsed.password) {
    throw new AppError(
      ERROR_CODES.ERR_ALLOWLIST_DENIED,
      'Embedded credentials in target URLs are forbidden to prevent SSRF and credential smuggling.',
      403,
      { targetUrl, hostname: parsed.hostname }
    );
  }

  const allowlist = Array.isArray(config.allowlist) && config.allowlist.length > 0
    ? config.allowlist.map((h) => String(h).toLowerCase().trim())
    : DEFAULT_SYSTEM_CONFIG.allowlist;

  const hostname = parsed.hostname.toLowerCase();

  // Explicit check against metadata/link-local/private SSRF ranges and non-allowlisted hosts
  if (!allowlist.includes(hostname)) {
    throw new AppError(
      ERROR_CODES.ERR_ALLOWLIST_DENIED,
      `Target host "${hostname}" is not on the approved local allowlist (${allowlist.join(', ')}). External and SSRF targets are strictly blocked.`,
      403,
      { targetUrl, hostname, allowlist }
    );
  }

  return {
    parsedUrl: parsed,
    normalizedUrl: parsed.toString(),
    normalizedOrigin: parsed.origin,
  };
}

/**
 * Resolves a resource attribute URL relative to the crawled page origin.
 * @param {string} rawAttr
 * @param {string} pageUrl
 * @returns {string|null}
 */
function normalizeResourceUrl(rawAttr, pageUrl) {
  if (!rawAttr || typeof rawAttr !== 'string') return null;
  const trimmed = rawAttr.trim();
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('#')) {
    return trimmed || null;
  }
  try {
    return new URL(trimmed, pageUrl).toString();
  } catch (_err) {
    return trimmed;
  }
}

/**
 * Extracts origin from a full URL string, or null if data/inline/invalid.
 * @param {string} urlStr
 * @returns {string|null}
 */
function extractOrigin(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return null;
  if (urlStr.startsWith('data:') || urlStr.startsWith('blob:') || urlStr.startsWith('javascript:')) {
    return urlStr.split(':')[0] + ':';
  }
  try {
    const u = new URL(urlStr);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.origin;
    }
    return null;
  } catch (_err) {
    return null;
  }
}

/**
 * Performs FR-1 local crawling and DOM security analysis.
 * Supports either fetching a live allowlisted URL via Node `fetch` or analyzing pre-supplied `rawHtml`/`rawHeaders`.
 *
 * @param {object} params
 * @param {string} params.targetUrl
 * @param {string} [params.rawHtml]
 * @param {object} [params.rawHeaders]
 * @param {string} [params.baseUrl]
 * @param {object} [systemConfig]
 * @returns {Promise<object>} Normalized FR-1 crawlResult payload
 */
async function crawlTarget(params = {}, systemConfig = DEFAULT_SYSTEM_CONFIG) {
  const config = { ...DEFAULT_SYSTEM_CONFIG, ...(systemConfig || {}) };
  const { targetUrl, rawHtml, rawHeaders, baseUrl } = params;

  const { normalizedUrl, normalizedOrigin, parsedUrl } = validateTargetUrl(
    targetUrl,
    config,
    baseUrl
  );

  const maxBytes = Number(config.maxCrawlSizeBytes) || DEFAULT_SYSTEM_CONFIG.maxCrawlSizeBytes;
  let htmlContent = '';
  let normalizedHeaders = {};
  let httpStatus = 200;

  if (typeof rawHtml === 'string') {
    if (Buffer.byteLength(rawHtml, 'utf8') > maxBytes) {
      throw new AppError(
        ERROR_CODES.ERR_PAYLOAD_TOO_LARGE,
        `Crawled HTML payload exceeds maximum permitted size of ${maxBytes} bytes.`,
        413,
        { maxCrawlSizeBytes: maxBytes }
      );
    }
    htmlContent = rawHtml;
    if (rawHeaders && typeof rawHeaders === 'object') {
      for (const [k, v] of Object.entries(rawHeaders)) {
        normalizedHeaders[String(k).toLowerCase()] = String(v);
      }
    }
  } else {
    let response;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      try {
        response = await fetch(normalizedUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'CSP-Architect-LocalCrawler/1.0',
            Accept: 'text/html,application/xhtml+xml,*/*',
          },
        });
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (err) {
      throw new AppError(
        ERROR_CODES.ERR_TARGET_UNREACHABLE,
        `Unable to reach local target URL "${normalizedUrl}": ${err.message}`,
        502,
        { targetUrl: normalizedUrl }
      );
    }

    httpStatus = response.status;
    response.headers.forEach((value, key) => {
      normalizedHeaders[String(key).toLowerCase()] = String(value);
    });

    const contentLengthHeader = normalizedHeaders['content-length'];
    if (contentLengthHeader && Number(contentLengthHeader) > maxBytes) {
      throw new AppError(
        ERROR_CODES.ERR_PAYLOAD_TOO_LARGE,
        `Target response Content-Length (${contentLengthHeader} bytes) exceeds maximum limit of ${maxBytes} bytes.`,
        413,
        { contentLength: Number(contentLengthHeader), maxCrawlSizeBytes: maxBytes }
      );
    }

    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength > maxBytes) {
      throw new AppError(
        ERROR_CODES.ERR_PAYLOAD_TOO_LARGE,
        `Target response body (${buffer.byteLength} bytes) exceeds maximum limit of ${maxBytes} bytes.`,
        413,
        { actualBytes: buffer.byteLength, maxCrawlSizeBytes: maxBytes }
      );
    }
    htmlContent = buffer.toString('utf8');
  }

  const $ = cheerio.load(htmlContent);

  const externalScripts = [];
  const inlineScripts = [];
  const inlineEventHandlers = [];
  const externalStyles = [];
  const inlineStyles = [];
  const images = [];
  const frames = [];
  const forms = [];
  const objectsAndEmbeds = [];
  const xssSinks = [];
  const connectOriginsSet = new Set();
  let usesEvalOrFunction = false;

  // 1. Extract <script> tags
  let inlineScriptIdx = 0;
  $('script').each((_i, el) => {
    const src = $(el).attr('src');
    if (src) {
      const resolvedSrc = normalizeResourceUrl(src, normalizedUrl);
      if (resolvedSrc) {
        externalScripts.push(resolvedSrc);
      }
    } else {
      const rawCode = $(el).html() || '';
      const trimmedCode = rawCode.trim();
      if (trimmedCode.length > 0) {
        // Compute hash over the exact script text node content as browsers do, plus trimmed reference
        const sha256 = computeSha256CspHash(rawCode);
        const trimmedSha256 = computeSha256CspHash(trimmedCode);
        const hasEval = EVAL_OR_DYNAMIC_CODE_REGEX.test(rawCode);
        if (hasEval) {
          usesEvalOrFunction = true;
        }

        const detectedSinks = [];
        for (const pattern of XSS_SINK_PATTERNS) {
          if (pattern.regex.test(rawCode)) {
            detectedSinks.push(pattern.name);
            xssSinks.push({
              location: `inline-script[${inlineScriptIdx}]`,
              sink: pattern.name,
              snippet: trimmedCode.slice(0, 120),
            });
          }
        }

        const isUnsafe = hasEval || detectedSinks.length > 0;

        inlineScripts.push({
          index: inlineScriptIdx,
          preview: trimmedCode.slice(0, 140),
          codeLength: rawCode.length,
          sha256,
          trimmedSha256,
          usesEval: hasEval,
          detectedSinks,
          isUnsafe,
        });
        inlineScriptIdx += 1;
      }
    }
  });

  // 2. Extract inline event handler attributes across all DOM elements
  $('*').each((_i, el) => {
    const tagName = (el.tagName || el.name || 'unknown').toLowerCase();
    const attribs = el.attribs || {};
    for (const [attrName, attrVal] of Object.entries(attribs)) {
      const lowerAttr = attrName.toLowerCase();
      if (lowerAttr.startsWith('on') && (INLINE_EVENT_ATTRIBUTES.includes(lowerAttr) || /^on[a-z]+$/.test(lowerAttr))) {
        const code = String(attrVal || '').trim();
        if (EVAL_OR_DYNAMIC_CODE_REGEX.test(code)) {
          usesEvalOrFunction = true;
        }
        for (const pattern of XSS_SINK_PATTERNS) {
          if (pattern.regex.test(code)) {
            xssSinks.push({
              location: `<${tagName} ${lowerAttr}="...">`,
              sink: pattern.name,
              snippet: code.slice(0, 120),
            });
          }
        }
        inlineEventHandlers.push({
          tag: tagName,
          attr: lowerAttr,
          code: code.slice(0, 140),
        });
      }
    }
  });

  // 3. Extract external stylesheets (<link rel="stylesheet" href="...">)
  $('link').each((_i, el) => {
    const rel = ($(el).attr('rel') || '').toLowerCase();
    const href = $(el).attr('href');
    if (rel.includes('stylesheet') && href) {
      const resolvedHref = normalizeResourceUrl(href, normalizedUrl);
      if (resolvedHref) {
        externalStyles.push(resolvedHref);
      }
    }
  });

  // 4. Extract inline <style> tags and style="..." attributes
  let inlineStyleIdx = 0;
  $('style').each((_i, el) => {
    const rawCss = $(el).html() || '';
    const trimmedCss = rawCss.trim();
    if (trimmedCss.length > 0) {
      inlineStyles.push({
        index: inlineStyleIdx,
        type: 'style-tag',
        preview: trimmedCss.slice(0, 120),
        sha256: computeSha256CspHash(rawCss),
        trimmedSha256: computeSha256CspHash(trimmedCss),
      });
      inlineStyleIdx += 1;
    }
  });

  // 5. Extract images (<img src="...">)
  $('img').each((_i, el) => {
    const src = $(el).attr('src');
    if (src) {
      const resolvedSrc = normalizeResourceUrl(src, normalizedUrl);
      if (resolvedSrc) {
        images.push(resolvedSrc);
      }
    }
  });

  // 6. Extract frames (<iframe src="...">, <frame src="...">)
  $('iframe, frame').each((_i, el) => {
    const src = $(el).attr('src');
    if (src) {
      const resolvedSrc = normalizeResourceUrl(src, normalizedUrl);
      if (resolvedSrc) {
        frames.push(resolvedSrc);
      }
    }
  });

  // 7. Extract forms (<form action="..." method="...">)
  $('form').each((_i, el) => {
    const action = $(el).attr('action') || '';
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const resolvedAction = action ? normalizeResourceUrl(action, normalizedUrl) : normalizedUrl;
    forms.push({
      action: action || normalizedUrl,
      resolvedAction,
      method,
    });
  });

  // 8. Extract legacy plugin tags (<object data="...">, <embed src="...">, <applet>)
  $('object, embed, applet').each((_i, el) => {
    const tagName = (el.tagName || el.name || 'object').toLowerCase();
    const rawUrl = $(el).attr('data') || $(el).attr('src') || '';
    const typeAttr = $(el).attr('type') || '';
    const resolvedUrl = rawUrl ? normalizeResourceUrl(rawUrl, normalizedUrl) : '';
    objectsAndEmbeds.push({
      tag: tagName,
      url: resolvedUrl || rawUrl,
      type: typeAttr,
    });
  });

  // Build explainable evidence items
  const evidence = [
    {
      code: 'CRAWL-ALLOWLIST-OK',
      severity: 'INFO',
      message: `Target host ${parsedUrl.host} verified against local allowlist (${(config.allowlist || []).join(', ')}).`,
    },
  ];

  if (externalScripts.length > 0) {
    const thirdPartyScripts = externalScripts.filter((u) => {
      const orig = extractOrigin(u);
      return orig && orig !== normalizedOrigin;
    });
    if (thirdPartyScripts.length > 0) {
      evidence.push({
        code: 'CRAWL-THIRD-PARTY-SCRIPT',
        severity: 'HIGH',
        message: `Detected ${thirdPartyScripts.length} external third-party script resource(s): ${thirdPartyScripts.join(', ')}.`,
      });
    } else {
      evidence.push({
        code: 'CRAWL-EXTERNAL-SCRIPT-SAME-ORIGIN',
        severity: 'INFO',
        message: `Discovered ${externalScripts.length} same-origin external script(s).`,
      });
    }
  }

  if (inlineScripts.length > 0) {
    const unsafeCount = inlineScripts.filter((s) => s.isUnsafe).length;
    const safeCount = inlineScripts.length - unsafeCount;
    if (safeCount > 0) {
      evidence.push({
        code: 'CRAWL-INLINE-SCRIPT-HASHED',
        severity: 'MEDIUM',
        message: `Extracted and computed SHA-256 hashes for ${safeCount} inline <script> block(s).`,
      });
    }
    if (unsafeCount > 0) {
      evidence.push({
        code: 'CRAWL-UNSAFE-INLINE-SCRIPT',
        severity: 'CRITICAL',
        message: `Detected ${unsafeCount} inline <script> block(s) containing dangerous XSS sinks or dynamic code evaluation.`,
      });
    }
  }

  if (inlineEventHandlers.length > 0) {
    evidence.push({
      code: 'CRAWL-INLINE-EVENT-HANDLERS',
      severity: 'HIGH',
      message: `Discovered ${inlineEventHandlers.length} inline DOM event handler attribute(s) (${inlineEventHandlers.map((h) => `${h.tag}[${h.attr}]`).join(', ')}) requiring refactoring or blocking.`,
    });
  }

  if (usesEvalOrFunction) {
    evidence.push({
      code: 'CRAWL-DYNAMIC-EVAL-DETECTED',
      severity: 'CRITICAL',
      message: 'Detected dynamic code evaluation (eval / new Function / string timer) which requires blocking unsafe-eval.',
    });
  }

  if (xssSinks.length > 0) {
    evidence.push({
      code: 'CRAWL-DOM-XSS-SINK',
      severity: 'CRITICAL',
      message: `Detected ${xssSinks.length} dangerous DOM XSS sink(s): ${xssSinks.map((s) => `${s.sink} in ${s.location}`).join('; ')}.`,
    });
  }

  if (objectsAndEmbeds.length > 0) {
    evidence.push({
      code: 'CRAWL-LEGACY-OBJECT-EMBED',
      severity: 'HIGH',
      message: `Detected ${objectsAndEmbeds.length} legacy plugin element(s) (<object>/<embed>) requiring object-src 'none'.`,
    });
  }

  const ambiguousScripts = externalScripts.filter((s) => /\.(txt|jpg|png|gif|csv|json|html)(\?|$)/i.test(s));
  if (ambiguousScripts.length > 0) {
    evidence.push({
      code: 'CRAWL-AMBIGUOUS-SCRIPT-MIME',
      severity: 'HIGH',
      message: `Detected script tag loading non-script file extension (${ambiguousScripts.join(', ')}), creating a MIME-sniffing execution risk if X-Content-Type-Options: nosniff is absent.`,
    });
  }

  if (forms.length > 0) {
    evidence.push({
      code: 'CRAWL-FORMS-DISCOVERED',
      severity: 'INFO',
      message: `Discovered ${forms.length} HTML form(s) (${forms.map((f) => `${f.method} ${f.action}`).join(', ')}).`,
    });
  }

  return {
    stage: 'FR-1_CRAWLER',
    status: 'COMPLETED',
    targetUrl: normalizedUrl,
    normalizedOrigin,
    httpStatus,
    rawHeaders: normalizedHeaders,
    resources: {
      externalScripts,
      inlineScripts,
      inlineEventHandlers,
      usesEvalOrFunction,
      xssSinks,
      externalStyles,
      inlineStyles,
      images,
      frames,
      forms,
      objectsAndEmbeds,
      ambiguousScripts,
      connectOrigins: Array.from(connectOriginsSet),
    },
    evidence,
  };
}

module.exports = {
  validateTargetUrl,
  crawlTarget,
  computeSha256CspHash,
  extractOrigin,
};
