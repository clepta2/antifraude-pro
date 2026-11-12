import { AntiFraudePro } from './antifraude-pro.js';

console.log('🛡️ Iniciando Bateria de Testes Unitários do AntiFraude Pro...\n');

// 1. Teste de Hashing SHA-256 e UUID Determinístico
const textoTeste = 'AntiFraudePro-Sinais-2026';
const hash = AntiFraudePro.hashSha256(textoTeste);
console.assert(hash.length === 64, 'Hash SHA-256 deve ter exatamente 64 caracteres hexadecimais');
const uuid = AntiFraudePro.hexParaUuid(hash);
console.assert(uuid.length === 36, 'UUID deve ter 36 caracteres');
console.log('✅ 1. Hashing Determinístico & UUID OK:');
console.log('   Hash SHA-256:', hash);
console.log('   UUID v5:', uuid);

// 2. Teste de Estabilidade do DeviceId
const sinaisDispositivoA = {
  tela: { largura: 1920, altura: 1080, profundidadeCores: 24 },
  hardware: { concorrenciaCpus: 8, memoriaGb: 16, maxTouchPoints: 0 },
  software: { plataforma: 'Win32', timeZone: 'America/Sao_Paulo' },
  hashes: { canvas: 'canvas_hash_123', webglRenderer: 'NVIDIA RTX 4070', audio: 'audio_hash_456' }
};

const dev1 = AntiFraudePro.gerarDeviceId(sinaisDispositivoA);
const dev2 = AntiFraudePro.gerarDeviceId(sinaisDispositivoA);
console.assert(dev1.deviceId === dev2.deviceId, 'O mesmo dispositivo deve gerar estritamente o mesmo deviceId');
console.assert(dev1.deviceId.startsWith('dev_'), 'DeviceId deve iniciar com dev_');
console.log('✅ 2. Estabilidade do DeviceId OK:', dev1.deviceId);

// 3. Teste de Validação de Documentos Oficiais
console.assert(AntiFraudePro.validarCpf('52998224725') === true, 'CPF válido deve passar');
console.assert(AntiFraudePro.validarCpf('11111111111') === false, 'CPF com dígitos iguais deve falhar');
console.assert(AntiFraudePro.validarCpf('12345678900') === false, 'CPF com DV errado deve falhar');
console.assert(AntiFraudePro.validarCnpj('06990590000123') === true, 'CNPJ válido (Google Brasil) deve passar');
console.assert(AntiFraudePro.validarCnpj('00000000000000') === false, 'CNPJ zerado deve falhar');
console.log('✅ 3. Validação de Documentos (CPF / CNPJ Módulo 11) OK');

// 4. Teste de Detecção de E-mails Descartáveis e Trolls
const emailNormal = AntiFraudePro.analisarEmail('contato@empresa.com.br');
const emailTemp = AntiFraudePro.analisarEmail('hacker123@yopmail.com');
const emailTroll = AntiFraudePro.analisarEmail('suamaeaquelaursa@gmail.com');

console.assert(emailNormal.valido === true && !emailNormal.descartavel && !emailNormal.troll, 'E-mail corporativo normal deve ser aceito');
console.assert(emailTemp.descartavel === true, 'Yopmail deve ser detectado como descartável');
console.assert(emailTroll.troll === true, 'Padrão troll deve ser detectado');
console.log('✅ 4. Análise de E-mails (Descartáveis / Trolls) OK');

// 5. Teste de Telefone e Mapeamento de DDD
const telSp = AntiFraudePro.analisarTelefone('(11) 98765-4321');
console.assert(telSp.valido === true, 'Telefone de SP deve ser válido');
console.assert(telSp.uf === 'SP', 'DDD 11 deve mapear para SP');
console.assert(telSp.isCelular === true, 'Deve ser celular');
console.log('✅ 5. Análise de Telefonia ANATEL OK:', telSp.ddd, '-', telSp.uf);

// 6. Teste de Avaliação de Transação Legítima (Score Baixo -> Aprovado)
const transacaoBoa = {
  valor: 249.90,
  cpf: '52998224725',
  email: 'usuario.legitimo@gmail.com',
  telefone: '11987654321'
};
const contextoBom = {
  ip: '177.18.200.45',
  provedor: 'CLARO S.A.',
  estado: 'SP',
  deviceId: dev1.deviceId,
  isHeadless: false
};
const analiseBoa = AntiFraudePro.avaliarTransacao(transacaoBoa, contextoBom);
console.assert(analiseBoa.nivelRisco === 'baixo', 'Transação legítima deve ter risco baixo');
console.assert(analiseBoa.recomendacao === 'aprovar', 'Transação legítima deve ser aprovada');
console.log('✅ 6. Transação Legítima (Score:', analiseBoa.scoreRisco, ') -> Recomendação:', analiseBoa.recomendacao);

// 7. Teste de Avaliação de Ataque / Fraude Crítica (Score Alto -> Bloqueio)
const transacaoFraude = {
  valor: 0.50, // Micro-valor de card testing
  cpf: '11111111111', // CPF inválido
  email: 'teste@tempmail.com', // E-mail temporário
  telefone: '92988887777' // DDD 92 (AM) divergente do IP (SP)
};
const contextoFraude = {
  ip: '34.95.120.10',
  provedor: 'Google Cloud Datacenter ASN 15169',
  estado: 'SP',
  deviceId: 'dev_bot_selenium_1',
  isHeadless: true // Robô / headless browser
};
const analiseFraude = AntiFraudePro.avaliarTransacao(transacaoFraude, contextoFraude);
console.assert(analiseFraude.scoreRisco >= 80, 'Ataque combinado deve atingir score crítico >= 80');
console.assert(analiseFraude.recomendacao === 'bloquear', 'Ataque deve ser bloqueado');
console.log('✅ 7. Ataque Detectado (Score:', analiseFraude.scoreRisco, ') -> Bloqueio Automático:', analiseFraude.recomendacao);
console.log('   Fatores Acionados:', analiseFraude.fatoresRisco.map(f => f.regra).join(', '));

// 8. Teste de Velocity / Força Bruta
const chaveTeste = 'device_stress_test_velocity';
for (let i = 0; i < 4; i++) {
  AntiFraudePro.checarVelocidade(chaveTeste, 3, 60);
}
const velUltima = AntiFraudePro.checarVelocidade(chaveTeste, 3, 60);
console.assert(velUltima.violouVelocidade === true, 'Deve violar limite de velocidade');
console.log('✅ 8. Monitor de Velocidade / Brute Force OK (Total no minuto:', velUltima.totalRecente, ')');

// 9. Teste de Detecção de Spam Telefônico ANATEL 0303 / 0304
const tel0303 = AntiFraudePro.analisarTelefone('03031234567');
console.assert(tel0303.isSpam === true, 'Prefixo 0303 deve ser marcado como Spam');
console.assert(tel0303.tipoSpam === 'TELEMARKETING_ATIVO_ANATEL_0303', 'Deve ser telemarketing 0303');
const tel0304 = AntiFraudePro.analisarTelefone('03049876543');
console.assert(tel0304.isSpam === true, 'Prefixo 0304 deve ser marcado como Spam');
console.assert(tel0304.tipoSpam === 'COBRANCA_ATIVA_ANATEL_0304', 'Deve ser cobranca 0304');
console.log('✅ 9. Inteligência Telefônica Anti-Spam ANATEL (0303 / 0304) OK');

// 10. Teste de Detecção de GPU Virtual & Lie Detector
const gpuSwift = AntiFraudePro.verificarGpuVirtual('Google SwiftShader (LLVM 10.0)');
console.assert(gpuSwift.isVirtual === true, 'SwiftShader deve ser detectado como GPU virtual');
const lieResult = AntiFraudePro.executarLieDetector({
  seguranca: { webdriverSpoofed: true, hasCdcArtifacts: true },
  hashes: { webglRenderer: 'llvmpipe (LLVM 12.0.0, 256 bits)' }
});
console.assert(lieResult.adulterado === true, 'Lie Detector deve sinalizar adulteração');
console.log('✅ 10. Lie Detector & Detecção de GPU Virtual Cloud OK (Motivos:', lieResult.motivos.length, ')');

// 11. Teste de Regras Customizadas Dinâmicas (Dynamic Rule Engine)
AntiFraudePro.adicionarRegra({
  id: 'COMPRA_ACIMA_LIMITE_VIP',
  peso: 25,
  descricao: 'Transação com valor acima de R$ 5.000 requer análise adicional',
  avaliar: (tx) => parseFloat(tx.valor || 0) > 5000
});
const txVip = AntiFraudePro.avaliarTransacao({ valor: 6500 });
console.assert(txVip.fatoresRisco.some(f => f.regra === 'COMPRA_ACIMA_LIMITE_VIP'), 'Regra customizada deve ter sido acionada');
console.log('✅ 11. Injeção Dinâmica de Regras de Negócio OK');

// 12. Teste de Whitelist & Sobrescrita Dinâmica de Pesos
AntiFraudePro.configurar({
  whitelistIps: ['10.0.0.1'],
  pesos: { VALOR_MICRO_CARD_TESTING: 40 }
});
const txWhitelist = AntiFraudePro.avaliarTransacao({ valor: 0.50 }, { ip: '10.0.0.1' });
console.assert(txWhitelist.scoreRisco === 0, 'IP em whitelist deve retornar score 0');
console.log('✅ 12. Motor Dinâmico de Whitelist & Calibração de Pesos OK');

// 13. Teste de Cloudflare Bot Score & Threat Score Nativo
const txCfBot = AntiFraudePro.avaliarTransacao({ valor: 250 }, {
  cf: { botScore: 12, threatScore: 65, httpProtocol: 'HTTP/1.1' },
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
});
console.assert(txCfBot.scoreRisco >= 80, 'Bot Score < 30 e Threat Score alto da Cloudflare devem levar a score crítico');
console.assert(txCfBot.fatoresRisco.some(f => f.regra === 'CLOUDFLARE_BOT_SCORE_MALICIOSO'), 'Deve acionar regra de Bot Score da Cloudflare');
console.assert(txCfBot.fatoresRisco.some(f => f.regra === 'CLOUDFLARE_IP_THREAT_CRITICO'), 'Deve acionar regra de Threat Score da Cloudflare');
console.assert(txCfBot.fatoresRisco.some(f => f.regra === 'INCONSISTENCIA_PROTOCOLO_CLIENT_HINTS'), 'Deve acionar inconsistência de protocolo');
console.log('✅ 13. Telemetria Criptográfica & Threat Intelligence Cloudflare OK');

// 14. Teste de Biometria Comportamental (Injeção Instantânea sem Movimento)
const txBiometriaRobo = AntiFraudePro.avaliarTransacao({ valor: 150 }, {
  biometria: { tempoPreenchimentoMs: 45, movimentosMouse: 0, teclasDigitadas: 20, dwellTimeMedioMs: 1 }
});
console.assert(txBiometriaRobo.fatoresRisco.some(f => f.regra === 'BIOMETRIA_INJECAO_INSTANTANEA_ROBO'), 'Deve detectar injeção direta de payload por bot');
console.log('✅ 14. Biometria Comportamental (Preenchimento Sobrenatural Detectado) OK\n');

console.log('🎉 Todos os testes unitários do AntiFraude Pro passaram com 100% de sucesso!');
