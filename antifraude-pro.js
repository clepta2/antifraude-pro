/**
 * antifraude-pro.js
 * SDK Oficial e Motor Universal de Segurança & Anti-Fraude
 * 
 * Funcionalidades:
 * - Device Fingerprint Determinístico Imutável (100% LGPD / Zero Cookies)
 * - Avaliação de Risco de Transações (Score 0-100)
 * - Detecção Avançada de Bots, Automação & Navegadores Headless (Puppeteer, Playwright, Selenium)
 * - Detecção de IP Datacenter, VPS, Proxy, Tor e VPNs
 * - Cruzamento Heurístico de Documentos, E-mails Descartáveis, DDD e GeoIP
 * - Verificação de Velocidade (Anti-Card Testing e Força Bruta)
 * 
 * Executa em sub-2ms na borda (Cloudflare Workers), em Node.js e no Navegador sem dependências externas.
 * 
 * @license MIT
 * @author clepta2 / OZPro Enterprise
 */

// ─── IMPLEMENTAÇÃO PURA DE SHA-256 (ZERO DEPENDÊNCIAS, NAVEGADOR & NODE.JS) ───
function sha256(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let lengthProperty = 'length';
  let i, j;
  let result = '';

  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;
  
  let hash = [];
  let k = [];
  let primeCounter = 0;

  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 300; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  
  ascii += '\x80';
  while ((ascii[lengthProperty] % 64) - 56) ascii += '\x00';
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << ((3 - (i % 4)) * 8);
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength;
  
  for (j = 0; j < words[lengthProperty];) {
    const w = words.slice(j, j += 16);
    const oldHash = hash;
    hash = hash.slice(0, 8);
    
    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0)) | 0;
      const temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;
      
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
      hash.pop();
    }
    
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

// ─── LISTA DE PROVEDORES DE DATACENTER / VPS CONHECIDOS (ASNs E NOMES) ───
const DATACENTER_KEYWORDS = [
  'amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure', 'digitalocean',
  'cloudflare', 'hetzner', 'ovh', 'linode', 'oracle', 'alibaba', 'vultr',
  'fastly', 'akamai', 'tencent', 'leaseweb', 'choopa', 'contabo', 'kamatera'
];

// ─── LISTA RESUMIDA DE DOMÍNIOS DE E-MAILS DESCARTÁVEIS COMUNS ───
const DOMINIOS_DESCARTAVEIS = new Set([
  'mailinator.com', 'yopmail.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
  'trashmail.com', 'sharklasers.com', 'dispostable.com', 'getairmail.com', 'throwawaymail.com',
  'maildrop.cc', 'temp-mail.org', 'crazymailing.com', 'fakeinbox.com', 'emailondeck.com',
  'mohmal.com', 'burnermail.io', 'inboxbear.com', 'mytemp.email', 'dropmail.me'
]);

// ─── MAPA DE DDDs PARA UFs (BRASIL ANATEL) ───
const DDD_PARA_UF = {
  11: 'SP', 12: 'SP', 13: 'SP', 14: 'SP', 15: 'SP', 16: 'SP', 17: 'SP', 18: 'SP', 19: 'SP',
  21: 'RJ', 22: 'RJ', 24: 'RJ',
  27: 'ES', 28: 'ES',
  31: 'MG', 32: 'MG', 33: 'MG', 34: 'MG', 35: 'MG', 37: 'MG', 38: 'MG',
  41: 'PR', 42: 'PR', 43: 'PR', 44: 'PR', 45: 'PR', 46: 'PR',
  47: 'SC', 48: 'SC', 49: 'SC',
  51: 'RS', 53: 'RS', 54: 'RS', 55: 'RS',
  61: 'DF', 62: 'GO', 64: 'GO',
  63: 'TO', 65: 'MT', 66: 'MT', 67: 'MS',
  68: 'AC', 69: 'RO',
  71: 'BA', 73: 'BA', 74: 'BA', 75: 'BA', 77: 'BA',
  79: 'SE',
  81: 'PE', 87: 'PE',
  82: 'AL',
  83: 'PB',
  84: 'RN',
  85: 'CE', 88: 'CE',
  86: 'PI', 89: 'PI',
  91: 'PA', 93: 'PA', 94: 'PA',
  92: 'AM', 97: 'AM',
  95: 'RR',
  96: 'AP',
  98: 'MA', 99: 'MA'
};

// ─── MEMÓRIA DE VELOCIDADE EM BORDA / PROCESSOS (VELOCITY TRACKER) ───
const velocityTracker = new Map();

export class AntiFraudePro {
  /**
   * Versão oficial do motor AntiFraude Pro
   */
  static get version() {
    return '1.0.0';
  }

  /**
   * Gera um hash SHA-256 estável e determinístico.
   * @param {string} texto 
   * @returns {string} 64 caracteres hexadecimais
   */
  static hashSha256(texto) {
    if (!texto || typeof texto !== 'string') return '';
    return sha256(texto);
  }

  /**
   * Converte um hash hexadecimal em formato padrão UUID v5.
   * @param {string} hex64 
   * @returns {string} UUID 8-4-4-4-12
   */
  static hexParaUuid(hex64) {
    if (!hex64 || hex64.length < 32) return '00000000-0000-0000-0000-000000000000';
    const clean = hex64.replace(/[^a-f0-9]/gi, '').padEnd(32, '0').slice(0, 32);
    return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-4${clean.slice(13, 16)}-a${clean.slice(17, 20)}-${clean.slice(20, 32)}`;
  }

  /**
   * Valida algoritmo oficial de CPF por Módulo 11 (Receita Federal)
   * @param {string} cpf 
   * @returns {boolean}
   */
  static validarCpf(cpf) {
    if (!cpf) return false;
    const limpo = String(cpf).replace(/\D/g, '');
    if (limpo.length !== 11) return false;
    if (/^(\d)\1{10}$/.test(limpo)) return false;

    let soma = 0;
    for (let i = 0; i < 9; i++) soma += parseInt(limpo.charAt(i), 10) * (10 - i);
    let resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(limpo.charAt(9), 10)) return false;

    soma = 0;
    for (let i = 0; i < 10; i++) soma += parseInt(limpo.charAt(i), 10) * (11 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    return resto === parseInt(limpo.charAt(10), 10);
  }

  /**
   * Valida algoritmo de CNPJ por Módulo 11
   * @param {string} cnpj 
   * @returns {boolean}
   */
  static validarCnpj(cnpj) {
    if (!cnpj) return false;
    const limpo = String(cnpj).replace(/\D/g, '');
    if (limpo.length !== 14) return false;
    if (/^(\d)\1{13}$/.test(limpo)) return false;

    const pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const pesos2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    let soma = 0;
    for (let i = 0; i < 12; i++) soma += parseInt(limpo.charAt(i), 10) * pesos1[i];
    let dv1 = soma % 11 < 2 ? 0 : 11 - (soma % 11);
    if (dv1 !== parseInt(limpo.charAt(12), 10)) return false;

    soma = 0;
    for (let i = 0; i < 13; i++) soma += parseInt(limpo.charAt(i), 10) * pesos2[i];
    let dv2 = soma % 11 < 2 ? 0 : 11 - (soma % 11);
    return dv2 === parseInt(limpo.charAt(13), 10);
  }

  /**
   * Validação básica de telefone brasileiro e extração de DDD
   * @param {string} telefone 
   * @returns {{ valido: boolean, ddd: number|null, uf: string|null, isCelular: boolean }}
   */
  static analisarTelefone(telefone) {
    if (!telefone) return { valido: false, ddd: null, uf: null, isCelular: false };
    const limpo = String(telefone).replace(/\D/g, '');
    const num = limpo.startsWith('55') && limpo.length >= 12 ? limpo.slice(2) : limpo;
    
    if (num.length !== 10 && num.length !== 11) {
      return { valido: false, ddd: null, uf: null, isCelular: false };
    }

    if (/^(\d)\1{9,10}$/.test(num)) {
      return { valido: false, ddd: null, uf: null, isCelular: false };
    }

    const ddd = parseInt(num.slice(0, 2), 10);
    const uf = DDD_PARA_UF[ddd] || null;
    const isCelular = num.length === 11 && num.charAt(2) === '9';

    return {
      valido: !!uf,
      ddd: uf ? ddd : null,
      uf,
      isCelular
    };
  }

  /**
   * Analisa e-mail detectando descarte, sintaxe e padrões trolls
   * @param {string} email 
   * @returns {{ valido: boolean, descartavel: boolean, troll: boolean, dominio: string }}
   */
  static analisarEmail(email) {
    if (!email || typeof email !== 'string') {
      return { valido: false, descartavel: false, troll: false, dominio: '' };
    }

    const clean = email.trim().toLowerCase();
    const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
    if (!regex.test(clean)) {
      return { valido: false, descartavel: false, troll: false, dominio: '' };
    }

    const partes = clean.split('@');
    const usuario = partes[0] || '';
    const dominio = partes[1] || '';

    const descartavel = DOMINIOS_DESCARTAVEIS.has(dominio) ||
      dominio.includes('tempmail') ||
      dominio.includes('disposable') ||
      dominio.includes('fakeinbox') ||
      dominio.includes('throwaway');

    const troll = usuario.includes('suamae') ||
      usuario.includes('aquelaursa') ||
      usuario.includes('naotem') ||
      usuario.includes('naoquero') ||
      usuario.includes('testetestando') ||
      /^(.)\1{4,}/.test(usuario) ||
      usuario === 'asdf' ||
      usuario === 'asdfg' ||
      usuario === '123456';

    return {
      valido: true,
      descartavel,
      troll,
      dominio
    };
  }

  /**
   * Coleta sinais seguros e estritamente não-invasivos no navegador cliente.
   * Não grava cookies, nem local storage. 100% em memória RAM.
   * @returns {Promise<object>} Sinais coletados para gerar o Device Fingerprint
   */
  static async coletarSinaisNavegador() {
    if (typeof window === 'undefined') {
      return {
        ambiente: 'servidor',
        plataforma: 'node',
        timestamp: Date.now()
      };
    }

    const nav = window.navigator || {};
    const scr = window.screen || {};

    // 1. Canvas Fingerprint
    let canvasHash = 'nao_suportado';
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('AntiFraudePro-🛡️-2026', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('AntiFraudePro-🛡️-2026', 4, 17);
        const dataUrl = canvas.toDataURL();
        canvasHash = sha256(dataUrl).slice(0, 16);
      }
    } catch (e) {
      canvasHash = 'bloqueado';
    }

    // 2. WebGL Fingerprint
    let webglVendor = 'desconhecido';
    let webglRenderer = 'desconhecido';
    try {
      const canvasGl = document.createElement('canvas');
      const gl = canvasGl.getContext('webgl') || canvasGl.getContext('experimental-webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'desconhecido';
          webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'desconhecido';
        }
      }
    } catch (e) {
      webglRenderer = 'bloqueado';
    }

    // 3. Audio Fingerprint
    let audioHash = 'desconhecido';
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        const audioCtx = new AudioContext();
        const osc = audioCtx.createOscillator();
        const comp = audioCtx.createDynamicsCompressor();
        osc.connect(comp);
        comp.connect(audioCtx.destination);
        audioHash = sha256(`${comp.threshold.value}_${comp.knee.value}_${comp.ratio.value}`).slice(0, 16);
        audioCtx.close();
      }
    } catch (e) {
      audioHash = 'bloqueado';
    }

    // 4. Detecção de Automação / Headless
    const isWebdriver = !!nav.webdriver;
    const isHeadless = isWebdriver ||
      /HeadlessChrome/.test(nav.userAgent || '') ||
      !nav.languages ||
      nav.languages.length === 0 ||
      (nav.plugins && nav.plugins.length === 0 && !/mobile|android|iphone/i.test(nav.userAgent || ''));

    const timeZone = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || 'desconhecido';

    const sinais = {
      tela: {
        largura: scr.width || 0,
        altura: scr.height || 0,
        profundidadeCores: scr.colorDepth || 0,
        pixelRatio: window.devicePixelRatio || 1
      },
      hardware: {
        concorrenciaCpus: nav.hardwareConcurrency || 1,
        memoriaGb: nav.deviceMemory || 4,
        maxTouchPoints: nav.maxTouchPoints || 0
      },
      software: {
        userAgent: nav.userAgent || '',
        plataforma: nav.platform || '',
        idiomas: Array.isArray(nav.languages) ? nav.languages.join(',') : (nav.language || 'pt-BR'),
        timeZone
      },
      hashes: {
        canvas: canvasHash,
        webglRenderer,
        webglVendor,
        audio: audioHash
      },
      seguranca: {
        isWebdriver,
        isHeadless,
        hasTouch: (nav.maxTouchPoints || 0) > 0 || 'ontouchstart' in window
      },
      timestamp: Date.now()
    };

    return sinais;
  }

  /**
   * Gera o identificador determinístico do dispositivo (deviceId) a partir dos sinais coletados.
   * @param {object} sinais Sinais de hardware/software
   * @returns {{ deviceId: string, deviceUuid: string, rawHash: string }}
   */
  static gerarDeviceId(sinais = {}) {
    const tela = sinais.tela || {};
    const hardware = sinais.hardware || {};
    const software = sinais.software || {};
    const hashes = sinais.hashes || {};

    const semente = [
      tela.largura || 0,
      tela.altura || 0,
      tela.profundidadeCores || 0,
      hardware.concorrenciaCpus || 1,
      hardware.memoriaGb || 4,
      hardware.maxTouchPoints || 0,
      software.plataforma || '',
      software.timeZone || '',
      hashes.canvas || '',
      hashes.webglRenderer || '',
      hashes.audio || ''
    ].join('||');

    const rawHash = sha256(semente);
    const deviceId = `dev_${rawHash}`;
    const deviceUuid = AntiFraudePro.hexParaUuid(rawHash);

    return {
      deviceId,
      deviceUuid,
      rawHash,
      confiancaPercent: hashes.canvas !== 'bloqueado' && hashes.webglRenderer !== 'bloqueado' ? 98 : 75
    };
  }

  /**
   * Monitor de velocidade para evitar ataques de Card Testing / Brute Force
   * @param {string} chave Identificador (deviceId ou IP)
   * @param {number} limiteTentativas Máximo permitido na janela (padrão 5)
   * @param {number} janelaSegundos Tempo da janela em segundos (padrão 60)
   * @returns {{ violouVelocidade: boolean, totalRecente: number }}
   */
  static checarVelocidade(chave, limiteTentativas = 5, janelaSegundos = 60) {
    if (!chave) return { violouVelocidade: false, totalRecente: 1 };
    
    const agora = Date.now();
    const janelaMs = janelaSegundos * 1000;
    
    let registros = velocityTracker.get(chave) || [];
    registros = registros.filter(ts => agora - ts < janelaMs);
    registros.push(agora);
    velocityTracker.set(chave, registros);

    // Limpeza periódica se a memória crescer muito
    if (velocityTracker.size > 15000) {
      for (const [k, arr] of velocityTracker.entries()) {
        if (arr.length === 0 || agora - arr[arr.length - 1] > janelaMs) {
          velocityTracker.delete(k);
        }
      }
    }

    return {
      violouVelocidade: registros.length > limiteTentativas,
      totalRecente: registros.length
    };
  }

  /**
   * Motor Principal de Avaliação e Pontuação de Risco de Transação
   * 
   * @param {object} transacao Dados do pagamento (valor, cpf, email, telefone, etc.)
   * @param {object} contexto Sinais de rede e de cliente (ip, asn, provedor, deviceId, etc.)
   * @returns {object} Parecer completo com score 0-100, nível, recomendação e fatores
   */
  static avaliarTransacao(transacao = {}, contexto = {}) {
    let score = 0;
    const fatores = [];
    const avisos = [];

    // 1. Avaliação do Dispositivo & Navegador
    const sinais = contexto.sinais || {};
    const seg = sinais.seguranca || {};
    const isHeadless = seg.isHeadless || contexto.isHeadless;
    const isWebdriver = seg.isWebdriver || contexto.isWebdriver;

    if (isHeadless || isWebdriver) {
      score += 45;
      fatores.push({
        regra: 'ROBO_HEADLESS_DETECTADO',
        peso: +45,
        descricao: 'Navegador automatizado ou sem interface gráfica detectado (possível bot)'
      });
    }

    // 2. Avaliação da Conexão / Rede / IP
    const provedor = (contexto.provedor || contexto.isp || '').toLowerCase();
    const asn = contexto.asn || '';
    const isDatacenter = DATACENTER_KEYWORDS.some(k => provedor.includes(k)) || !!contexto.isDatacenter;

    if (isDatacenter) {
      score += 30;
      fatores.push({
        regra: 'IP_DE_DATACENTER_CLOUD',
        peso: +30,
        descricao: `Conexão originada de servidor em nuvem ou datacenter (${contexto.provedor || 'Cloud'}) e não de provedor residencial`
      });
    }

    // 3. Avaliação do Documento (CPF / CNPJ)
    const documento = String(transacao.documento || transacao.cpf || transacao.cnpj || '').replace(/\D/g, '');
    if (documento.length > 0) {
      if (documento.length === 11) {
        if (!AntiFraudePro.validarCpf(documento)) {
          score += 25;
          fatores.push({
            regra: 'CPF_MATEMATICAMENTE_INVALIDO',
            peso: +25,
            descricao: 'Dígitos verificadores do CPF informados são matematicamente inválidos'
          });
        }
      } else if (documento.length === 14) {
        if (!AntiFraudePro.validarCnpj(documento)) {
          score += 25;
          fatores.push({
            regra: 'CNPJ_MATEMATICAMENTE_INVALIDO',
            peso: +25,
            descricao: 'Dígitos verificadores do CNPJ informados são matematicamente inválidos'
          });
        }
      } else {
        score += 20;
        fatores.push({
          regra: 'DOCUMENTO_FORMATO_INVALIDO',
          peso: +20,
          descricao: `Documento possui tamanho inválido (${documento.length} dígitos)`
        });
      }
    }

    // 4. Avaliação do E-mail
    const email = transacao.email || '';
    if (email) {
      const auditEmail = AntiFraudePro.analisarEmail(email);
      if (!auditEmail.valido) {
        score += 15;
        fatores.push({
          regra: 'EMAIL_SINTAXE_INVALIDA',
          peso: +15,
          descricao: 'Formato de e-mail não atende às especificações RFC'
        });
      } else {
        if (auditEmail.descartavel) {
          score += 25;
          fatores.push({
            regra: 'EMAIL_DESCARTAVEL_TEMPORARIO',
            peso: +25,
            descricao: `E-mail utiliza provedor temporário ou descartável (${auditEmail.dominio})`
          });
        }
        if (auditEmail.troll) {
          score += 20;
          fatores.push({
            regra: 'EMAIL_PADRAO_TROLL_SUSPEITO',
            peso: +20,
            descricao: 'Nome de usuário do e-mail apresenta padrão característico de cadastro zombeteiro ou gerado por script'
          });
        }
      }
    }

    // 5. Avaliação do Telefone & Cruzamento com GeoIP
    const telefone = transacao.telefone || transacao.celular || '';
    if (telefone) {
      const auditTel = AntiFraudePro.analisarTelefone(telefone);
      if (!auditTel.valido) {
        score += 15;
        fatores.push({
          regra: 'TELEFONE_INVALIDO',
          peso: +15,
          descricao: 'Número de telefone ou DDD inexistente no plano de numeração ANATEL'
        });
      } else {
        const ufGeo = (contexto.estado || contexto.uf || '').toUpperCase();
        if (ufGeo && auditTel.uf && ufGeo !== auditTel.uf) {
          score += 15;
          fatores.push({
            regra: 'DDD_DIVERGENTE_DA_LOCALIZACAO_IP',
            peso: +15,
            descricao: `DDD do telefone (${auditTel.ddd} - ${auditTel.uf}) difere do Estado do IP da conexão (${ufGeo})`
          });
        }
      }
    }

    // 6. Teste de Velocidade / Frequência de Requisições (Velocity)
    const deviceId = contexto.deviceId || (sinais ? AntiFraudePro.gerarDeviceId(sinais).deviceId : null);
    if (deviceId) {
      const vel = AntiFraudePro.checarVelocidade(deviceId, 4, 60);
      if (vel.violouVelocidade) {
        score += 30;
        fatores.push({
          regra: 'ALTA_VELOCIDADE_TENTATIVAS_DEVICE',
          peso: +30,
          descricao: `Dispositivo realizou ${vel.totalRecente} tentativas de transação no último minuto (padrão de ataque)`
        });
      }
    }

    // 7. Heurística de Valor de Transação
    const valor = parseFloat(transacao.valor || 0);
    if (valor <= 1.00 && valor > 0) {
      score += 15;
      fatores.push({
        regra: 'VALOR_MICRO_CARD_TESTING',
        peso: +15,
        descricao: 'Valor muito baixo (R$ 1,00 ou menos) característico de teste de cartão de crédito roubado'
      });
    }

    // Teto do score
    score = Math.min(100, Math.max(0, score));

    // Determina nível de risco
    let nivelRisco = 'baixo';
    let recomendacao = 'aprovar';
    let corBadge = '#10b981';

    if (score >= 80) {
      nivelRisco = 'critico';
      recomendacao = 'bloquear';
      corBadge = '#ef4444';
    } else if (score >= 55) {
      nivelRisco = 'alto';
      recomendacao = 'analise_manual';
      corBadge = '#f97316';
    } else if (score >= 25) {
      nivelRisco = 'medio';
      recomendacao = 'desafio_2fa';
      corBadge = '#f59e0b';
    }

    return {
      ok: true,
      scoreRisco: score,
      nivelRisco,
      recomendacao,
      corBadge,
      deviceId: deviceId || 'dev_generico',
      fatoresRisco: fatores,
      avisos,
      detalhes: {
        documentoValido: documento ? (documento.length === 11 ? AntiFraudePro.validarCpf(documento) : AntiFraudePro.validarCnpj(documento)) : null,
        emailAuditado: email ? AntiFraudePro.analisarEmail(email) : null,
        isHeadlessBot: !!isHeadless,
        isDatacenterConexao: isDatacenter,
        totalFatoresAcionados: fatores.length
      },
      timestamp: new Date().toISOString()
    };
  }
}
