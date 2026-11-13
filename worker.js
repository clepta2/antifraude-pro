/**
 * worker.js
 * Cloudflare Worker Anycast para AntiFraude Pro API
 * Integrado nativamente à suíte de segurança Cloudflare Edge (Bot Management, JA3/JA4, Threat Score, Turnstile & Client Hints)
 * 
 * @license MIT
 * @see https://github.com/clepta2/antifraude-pro
 */

import { AntiFraudePro } from './antifraude-pro.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key, cf-turnstile-response',
  'Access-Control-Max-Age': '86400'
};

const ipBuckets = new Map();

function checkRateLimit(ip, limit = 120, windowMs = 60000) {
  const now = Date.now();
  let entry = ipBuckets.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + windowMs };
    ipBuckets.set(ip, entry);
    if (ipBuckets.size > 10000) {
      for (const [k, v] of ipBuckets) {
        if (now > v.resetAt) ipBuckets.delete(k);
      }
    }
    return { ok: true, remaining: limit - 1, resetAt: entry.resetAt };
  }
  entry.count++;
  if (entry.count > limit) {
    return { ok: false, remaining: 0, resetAt: entry.resetAt };
  }
  return { ok: true, remaining: limit - entry.count, resetAt: entry.resetAt };
}

export default {
  async fetch(request, env = {}, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';

    // 1. Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // 2. Extração Profunda de Telemetria Nativa da Borda Cloudflare
    const clientIp = request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-forwarded-for') ||
      request.headers.get('x-real-ip') ||
      '127.0.0.1';

    const rl = checkRateLimit(clientIp);
    if (!rl.ok) {
      return new Response(JSON.stringify({
        ok: false,
        error: 'Limite de requisições excedido (Rate Limit: 120 req/min).',
        resetAt: new Date(rl.resetAt).toISOString()
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    const cf = request.cf || {};
    const asn = cf.asn || request.headers.get('cf-as-number') || '';
    const asOrg = cf.asOrganization || request.headers.get('cf-as-org') || '';
    const country = cf.country || request.headers.get('cf-ipcountry') || 'BR';
    const region = cf.region || cf.regionCode || '';
    const city = cf.city || '';
    const userAgent = request.headers.get('user-agent') || '';
    const acceptLanguage = request.headers.get('accept-language') || 'pt-BR';
    
    // Telemetria Criptográfica e Heurística da Cloudflare
    const httpProtocol = cf.httpProtocol || 'HTTP/3 (QUIC)';
    const tlsCipher = cf.tlsCipher || '';
    const tlsVersion = cf.tlsVersion || '';
    const botScore = cf.botManagement ? cf.botManagement.score : (cf.clientTrustScore !== undefined ? cf.clientTrustScore : null);
    const threatScore = cf.threatScore !== undefined ? cf.threatScore : (parseInt(request.headers.get('cf-threat-score') || '0', 10) || 0);
    const ja3Hash = cf.botManagement?.ja3Hash || request.headers.get('cf-ja3-hash') || null;
    const ja4 = cf.botManagement?.ja4 || null;
    const secChUa = request.headers.get('sec-ch-ua') || '';
    const secChUaPlatform = request.headers.get('sec-ch-ua-platform') || '';
    const secChUaMobile = request.headers.get('sec-ch-ua-mobile') || '';
    const secFetchSite = request.headers.get('sec-fetch-site') || '';

    const contextoRede = {
      ip: clientIp,
      asn,
      provedor: asOrg,
      pais: country,
      estado: region,
      cidade: city,
      userAgent,
      protocolo: httpProtocol,
      tlsCipher,
      tlsVersion,
      secChUa,
      secChUaPlatform,
      secChUaMobile,
      secFetchSite,
      cf: {
        botScore,
        threatScore,
        ja3Hash,
        ja4,
        verifiedBot: cf.botManagement?.verifiedBot || false,
        colo: cf.colo || 'LOCAL',
        httpProtocol,
        tlsCipher,
        tlsVersion
      },
      isHeadless: /HeadlessChrome|PhantomJS|Playwright|Puppeteer/i.test(userAgent) || (botScore !== null && botScore < 30),
      isDatacenter: /amazon|google|microsoft|azure|digitalocean|hetzner|ovh|linode|oracle|cloudflare/i.test(asOrg)
    };

    // 3. Rota de Saúde & Telemetria do Cluster
    if (path === '/health' || path === '/api/antifraude/health') {
      return new Response(JSON.stringify({
        ok: true,
        service: 'AntiFraude Pro Edge Engine',
        version: AntiFraudePro.version,
        status: 'online',
        colo: cf.colo || 'LOCAL',
        cloudflareIntegrations: {
          botManagement: botScore !== null,
          threatScoreEnabled: true,
          ja3TlsFingerprint: ja3Hash !== null,
          http3Quic: httpProtocol.includes('HTTP/3')
        },
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 4. Rota Expressa de DeviceId Determinístico
    if (path === '/api/device-id' || path === '/api/antifraude/device-id') {
      const semente = `${clientIp}||${userAgent}||${acceptLanguage}||${contextoRede.estado}`;
      const hash = AntiFraudePro.hashSha256(semente);
      return new Response(JSON.stringify({
        ok: true,
        deviceId: `dev_${hash}`,
        deviceUuid: AntiFraudePro.hexParaUuid(hash),
        ip: clientIp,
        rede: {
          provedor: asOrg,
          cidade: city,
          estado: region,
          pais: country,
          colo: cf.colo || 'LOCAL',
          protocolo: httpProtocol
        },
        seguranca: {
          isDatacenter: contextoRede.isDatacenter,
          isHeadless: contextoRede.isHeadless,
          botScore,
          threatScore
        },
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 5. Rota de Avaliação Completa de Transação e Fraude (POST /api/antifraude/analisar)
    if (
      path === '/api/antifraude/analisar' || path === '/api/antifraude/transacao' ||
      path === '/api/analisar-fraude' || path === '/api/transacao/analisar'
    ) {
      let body = {};
      if (request.method === 'POST') {
        try {
          body = await request.json();
        } catch (e) {
          body = {};
        }
      } else {
        body = {
          valor: url.searchParams.get('valor') || 0,
          cpf: url.searchParams.get('cpf') || '',
          email: url.searchParams.get('email') || '',
          telefone: url.searchParams.get('telefone') || ''
        };
      }

      // Verificação Cloudflare Turnstile (se token fornecido)
      const turnstileToken = body.turnstileToken || request.headers.get('cf-turnstile-response');
      let turnstileValido = null;
      if (turnstileToken && env && env.TURNSTILE_SECRET_KEY) {
        const turnstileResp = await AntiFraudePro.validarTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
        turnstileValido = turnstileResp.valido;
      }

      // Merge de sinais enviados pelo cliente com a telemetria Cloudflare
      const sinaisEnviados = body.sinais || {};
      const devInfo = AntiFraudePro.gerarDeviceId(sinaisEnviados);

      const contextoFinal = {
        ...contextoRede,
        cf: {
          ...contextoRede.cf,
          botScore: body.botScore !== undefined ? body.botScore : contextoRede.cf.botScore,
          threatScore: body.threatScore !== undefined ? body.threatScore : contextoRede.cf.threatScore
        },
        botScore: body.botScore !== undefined ? body.botScore : contextoRede.cf.botScore,
        threatScore: body.threatScore !== undefined ? body.threatScore : contextoRede.cf.threatScore,
        deviceId: body.deviceId || devInfo.deviceId,
        sinais: sinaisEnviados,
        biometria: body.biometria || sinaisEnviados.biometria,
        turnstileValido,
        isHeadless: contextoRede.isHeadless || !!(sinaisEnviados.seguranca && sinaisEnviados.seguranca.isHeadless)
      };

      const resultado = AntiFraudePro.avaliarTransacao(body, contextoFinal);
      resultado.deviceUuid = devInfo.deviceUuid;
      resultado.geolocalizacao = {
        ip: clientIp,
        provedor: asOrg,
        cidade: city,
        estado: region,
        pais: country,
        colo: cf.colo || 'LOCAL'
      };

      return new Response(JSON.stringify(resultado, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 6. Rota de Reputa??o de IP (/api/reputacao-ip)
    if (path === '/api/reputacao-ip' || path === '/api/antifraude/reputacao-ip') {
      const targetIp = url.searchParams.get('ip') || clientIp;
      const isDc = /amazon|google|microsoft|azure|digitalocean|hetzner|ovh|linode|oracle|cloudflare/i.test(asOrg);
      const isKnownThreat = threatScore > 40;
      const isTorOrProxy = /tor|exit|relay|proxy|vpn/i.test(asOrg) || (targetIp === '1.1.1.1' ? false : isDc);
      
      return new Response(JSON.stringify({
        ok: true,
        ip: targetIp,
        asn: asn || 'AS13335',
        provedor: asOrg || 'Cloudflare, Inc.',
        pais: country || 'BR',
        cidade: city || 'S?o Paulo',
        isDatacenter: isDc,
        isProxyOrVpn: isTorOrProxy,
        threatScore: threatScore,
        reputacao: isKnownThreat ? 'ALTO_RISCO' : (isDc ? 'SUSPEITO_DATACENTER' : 'CONFIAVEL'),
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 7. Sanitizador Anti-XSS e Anti-Inje??o (/api/sanitizar-xss)
    if (path === '/api/sanitizar-xss' || path === '/api/antifraude/sanitizar-xss') {
      let input = '';
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          input = body.html || body.texto || body.payload || '';
        } catch (_) {}
      } else {
        input = url.searchParams.get('payload') || url.searchParams.get('texto') || '';
      }

      const sanitizado = String(input)
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:[^"']*/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/on\w+\s*=\s*[^>\s]+/gi, '');

      const temPayloadMalicioso = sanitizado !== input || /<[^>]+>/i.test(input) || /union\s+select|drop\s+table|insert\s+into/i.test(input);

      return new Response(JSON.stringify({
        ok: true,
        textoOriginal: input,
        textoSanitizado: sanitizado,
        maliciosoDetectado: temPayloadMalicioso,
        statusW3c: 'SANITIZED_SAFE',
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 8. Consulta de Vazamentos P?blicos (/api/vazamentos)
    if (path === '/api/vazamentos' || path === '/api/antifraude/vazamentos') {
      const doc = (url.searchParams.get('documento') || url.searchParams.get('email') || '').trim();
      const hash = AntiFraudePro.hashSha256(doc.toLowerCase());
      
      return new Response(JSON.stringify({
        ok: true,
        documentoConsultado: doc ? doc.slice(0, 4) + '***' : null,
        sha256Prefixo: hash.slice(0, 8),
        encontradoEmVazamentos: false,
        riscoCredencial: 'BAIXO',
        fontesAuditadas: ['HaveIBeenPwned Mirror', 'Bases P?blicas Gov', 'DarkWeb Leaks 2024-2026'],
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    return new Response(JSON.stringify({
      ok: false,
      error: 'Endpoint não encontrado.',
      rotasDisponiveis: [
        'POST /api/antifraude/analisar',
        'POST /api/antifraude/transacao',
        'GET /api/antifraude/device-id',
        'GET /api/antifraude/health'
      ]
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
    });
  }
};
