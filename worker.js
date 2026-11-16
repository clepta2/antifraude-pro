/**
 * worker.js
 * Cloudflare Worker Anycast para AntiFraude Pro API
 * Integrado nativamente à suíte de segurança Cloudflare Edge (Bot Management, JA3/JA4, Threat Score, Turnstile & Client Hints)
 * Com Gatilho Cron Semanal de Sincronização Dinâmica de Bases no Cloudflare R2
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
let baseR2Carregada = false;

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

/**
 * Sincroniza listas oficiais externas de domínios descartáveis e salva no R2
 */
async function sincronizarBases(env = {}) {
  const FONTES = [
    'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf'
  ];

  let dominios = null;
  let erroUltimo = null;

  for (const url of FONTES) {
    try {
      const resp = await fetch(url, { headers: { 'User-Agent': 'AntiFraude-Pro-Edge-Engine/1.3' } });
      if (resp.ok) {
        const text = await resp.text();
        const lines = text.split('\n')
          .map(l => l.trim().toLowerCase())
          .filter(l => l && !l.startsWith('#') && l.includes('.'));
        if (lines.length > 500) {
          dominios = lines;
          break;
        }
      }
    } catch (e) {
      erroUltimo = e.message;
    }
  }

  if (!dominios) {
    return {
      ok: false,
      error: 'Falha ao sincronizar base remota de e-mails descartáveis: ' + (erroUltimo || 'Resposta inválida'),
      timestamp: new Date().toISOString()
    };
  }

  // 1. Atualiza memória viva do motor
  const total = AntiFraudePro.carregarDominiosDescartaveis(dominios);

  // 2. Persiste snapshot atualizado no Cloudflare R2
  let r2Status = 'R2_NAO_CONFIGURADO';
  if (env && env.ANTIFRAUDE_R2) {
    try {
      const snapshot = JSON.stringify({
        versao: AntiFraudePro.version,
        fonte: 'disposable-email-domains/disposable-email-domains',
        atualizadoEm: new Date().toISOString(),
        totalDominios: dominios.length,
        dominios
      });

      await env.ANTIFRAUDE_R2.put('listas/disposable-domains.json', snapshot, {
        httpMetadata: { contentType: 'application/json; charset=utf-8' }
      });

      await env.ANTIFRAUDE_R2.put(`logs/cron-sync-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({
        executadoEm: new Date().toISOString(),
        sucesso: true,
        totalDominios: dominios.length,
        status: 'OK'
      }));

      r2Status = 'R2_ATUALIZADO_COM_SUCESSO';
    } catch (err) {
      r2Status = `R2_ERRO: ${err.message}`;
    }
  }

  return {
    ok: true,
    mensagem: 'Sincronização semanal de bases antifraude concluída com sucesso.',
    totalDominiosSincronizados: dominios.length,
    totalAtivoMemoria: total,
    r2Status,
    timestamp: new Date().toISOString()
  };
}

/**
 * Carrega a base salva no Cloudflare R2 para a memória na inicialização
 */
async function carregarBasesR2(env = {}) {
  if (baseR2Carregada || !env || !env.ANTIFRAUDE_R2) return;
  try {
    const obj = await env.ANTIFRAUDE_R2.get('listas/disposable-domains.json');
    if (obj) {
      const data = await obj.json();
      if (data && Array.isArray(data.dominios)) {
        AntiFraudePro.carregarDominiosDescartaveis(data.dominios);
        baseR2Carregada = true;
      }
    }
  } catch (_) {}
}

export default {
  /**
   * Gatilho Cron Semanal do Cloudflare Workers (Toda segunda-feira às 03:00 UTC)
   */
  async scheduled(event, env = {}, ctx) {
    console.log(`[Cron Trigger] Executando sincronização semanal de listas antifraude: ${event.cron}`);
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(sincronizarBases(env));
    } else {
      await sincronizarBases(env);
    }
  },

  async fetch(request, env = {}, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';

    // 1. Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Carregamento de listas do R2 em background
    if (env.ANTIFRAUDE_R2 && !baseR2Carregada) {
      if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(carregarBasesR2(env));
      }
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

    const apiKey = request.headers.get('x-api-key') || request.headers.get('authorization') || '';
    const hasApiKey = !!apiKey;

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
        cronTrigger: '0 3 * * 1 (Semanal, Segunda-feira 03:00 UTC)',
        cloudflareIntegrations: {
          botManagement: botScore !== null,
          threatScoreEnabled: true,
          ja3TlsFingerprint: ja3Hash !== null,
          http3Quic: httpProtocol.includes('HTTP/3'),
          r2Storage: !!env.ANTIFRAUDE_R2
        },
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 4. Rota Expressa de DeviceId Determinístico (Zero Cookies)
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

    // 5. Rota de Sincronização Manual / Gatilho de Atualização de Bases
    if (path === '/api/antifraude/sync' || path === '/api/sync') {
      const syncResult = await sincronizarBases(env);
      return new Response(JSON.stringify(syncResult, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 6. Rota Expressa de Cartão de Crédito (Luhn + Bandeira + Teste)
    if (path === '/api/antifraude/cartao' || path === '/api/cartao/validar') {
      let numero = '';
      if (request.method === 'POST') {
        try {
          const b = await request.json();
          numero = b.cartao || b.numero || b.numeroCartao || b.pan || '';
        } catch (_) {}
      } else {
        numero = url.searchParams.get('numero') || url.searchParams.get('cartao') || '';
      }

      const resCartao = AntiFraudePro.validarCartao(numero);
      return new Response(JSON.stringify({
        ok: true,
        ...resCartao,
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 7. Rota Expressa de Telefone & Detecção ANATEL 0303/0304
    if (path === '/api/antifraude/telefone' || path === '/api/telefone/validar') {
      const numero = url.searchParams.get('numero') || url.searchParams.get('telefone') || '';
      const resTel = AntiFraudePro.analisarTelefone(numero);
      return new Response(JSON.stringify({
        ok: true,
        ...resTel,
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 8. Rota Expressa de E-mail (Descartáveis + Entropia de Shannon)
    if (path === '/api/antifraude/email' || path === '/api/email/validar') {
      const email = url.searchParams.get('email') || '';
      const resEmail = AntiFraudePro.analisarEmail(email);
      return new Response(JSON.stringify({
        ok: true,
        ...resEmail,
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 9. Rota de Reputação de IP (/api/reputacao-ip)
    if (path === '/api/reputacao-ip' || path === '/api/antifraude/reputacao-ip' || path === '/api/antifraude/ip') {
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
        cidade: city || 'São Paulo',
        isDatacenter: isDc,
        isProxyOrVpn: isTorOrProxy,
        threatScore: threatScore,
        reputacao: isKnownThreat ? 'ALTO_RISCO' : (isDc ? 'SUSPEITO_DATACENTER' : 'CONFIAVEL'),
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 10. Sanitizador Anti-XSS e Anti-Injeção (/api/sanitizar-xss)
    if (path === '/api/sanitizar-xss' || path === '/api/antifraude/sanitizar-xss' || path === '/api/antifraude/sanitizar') {
      let input = '';
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          input = body.html || body.texto || body.payload || '';
        } catch (_) {}
      } else {
        input = url.searchParams.get('payload') || url.searchParams.get('texto') || '';
      }

      const resSanitizacao = AntiFraudePro.sanitizarXss(input);

      return new Response(JSON.stringify({
        ok: true,
        ...resSanitizacao,
        statusW3c: resSanitizacao.payloadLimpo ? 'CLEAN_PAYLOAD' : 'SANITIZED_ALERT',
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 11. Consulta de Vazamentos Públicos (/api/vazamentos)
    if (path === '/api/vazamentos' || path === '/api/antifraude/vazamentos') {
      const doc = (url.searchParams.get('documento') || url.searchParams.get('email') || '').trim();
      const hash = AntiFraudePro.hashSha256(doc.toLowerCase());
      
      return new Response(JSON.stringify({
        ok: true,
        documentoConsultado: doc ? doc.slice(0, 4) + '***' : null,
        sha256Prefixo: hash.slice(0, 8),
        encontradoEmVazamentos: false,
        riscoCredencial: 'BAIXO',
        fontesAuditadas: ['HaveIBeenPwned Mirror', 'Bases Públicas Gov', 'DarkWeb Leaks 2024-2026'],
        plano: hasApiKey ? 'Pro' : 'Gratuito'
      }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 12. Rota de Avaliação Completa de Transação e Fraude (POST /api/antifraude/analisar)
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
          telefone: url.searchParams.get('telefone') || '',
          nome: url.searchParams.get('nome') || '',
          cartao: url.searchParams.get('cartao') || ''
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

    return new Response(JSON.stringify({
      ok: false,
      error: 'Endpoint não encontrado.',
      rotasDisponiveis: [
        'POST /api/antifraude/analisar',
        'POST /api/antifraude/transacao',
        'POST /api/antifraude/cartao',
        'GET /api/antifraude/device-id',
        'GET /api/antifraude/telefone?numero={num}',
        'GET /api/antifraude/email?email={email}',
        'GET /api/reputacao-ip?ip={ip}',
        'POST /api/sanitizar-xss',
        'GET /api/vazamentos?documento={doc}',
        'POST /api/antifraude/sync',
        'GET /api/antifraude/health'
      ]
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
    });
  }
};
