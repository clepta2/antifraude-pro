/**
 * worker.js
 * Cloudflare Worker Anycast para AntiFraude Pro API
 * 
 * @license MIT
 * @see https://github.com/clepta2/antifraude-pro
 */

import { AntiFraudePro } from './antifraude-pro.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
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
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';

    // 1. Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // 2. Extração de Sinais de Conexão na Borda Cloudflare
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
    const isBotManagement = cf.botManagement && cf.botManagement.score < 30;

    const contextoRede = {
      ip: clientIp,
      asn,
      provedor: asOrg,
      pais: country,
      estado: region,
      cidade: city,
      userAgent,
      isHeadless: /HeadlessChrome|PhantomJS|Playwright|Puppeteer/i.test(userAgent) || isBotManagement,
      isDatacenter: /amazon|google|microsoft|azure|digitalocean|hetzner|ovh|linode|oracle|cloudflare/i.test(asOrg)
    };

    // 3. Rota de Saúde
    if (path === '/health' || path === '/api/antifraude/health') {
      return new Response(JSON.stringify({
        ok: true,
        service: 'AntiFraude Pro Edge Engine',
        version: AntiFraudePro.version,
        status: 'online',
        colo: cf.colo || 'LOCAL',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 4. Rota Rápida de Obtenção de DeviceId
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
          pais: country
        },
        seguranca: {
          isDatacenter: contextoRede.isDatacenter,
          isHeadless: contextoRede.isHeadless
        },
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 5. Rota de Avaliação Completa de Transação e Fraude (POST /api/antifraude/analisar ou POST /api/antifraude/transacao)
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
        // Suporte a query params em GET para testes rápidos
        body = {
          valor: url.searchParams.get('valor') || 0,
          cpf: url.searchParams.get('cpf') || '',
          email: url.searchParams.get('email') || '',
          telefone: url.searchParams.get('telefone') || ''
        };
      }

      // Merge de sinais enviados pelo cliente
      const sinaisEnviados = body.sinais || {};
      const devInfo = AntiFraudePro.gerarDeviceId(sinaisEnviados);

      const contextoFinal = {
        ...contextoRede,
        deviceId: body.deviceId || devInfo.deviceId,
        sinais: sinaisEnviados,
        isHeadless: contextoRede.isHeadless || !!(sinaisEnviados.seguranca && sinaisEnviados.seguranca.isHeadless)
      };

      const resultado = AntiFraudePro.avaliarTransacao(body, contextoFinal);
      resultado.deviceUuid = devInfo.deviceUuid;
      resultado.geolocalizacao = {
        ip: clientIp,
        provedor: asOrg,
        cidade: city,
        estado: region,
        pais: country
      };

      return new Response(JSON.stringify(resultado, null, 2), {
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
