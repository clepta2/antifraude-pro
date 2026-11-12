# 🛡️ AntiFraude Pro — SDK & Documentação de Integração

> **Cliente SDK e Documentação Oficial de Integração da API AntiFraude Pro.**  
> 🔒 **Solução Soberana de Segurança:** Device Fingerprint Determinístico sem cookies (100% LGPD/GDPR), Detecção de Bots/Headless, Reputação de Rede e Motor de Score de Risco para Checkouts e E-commerces na Borda Cloudflare Anycast (<2ms).

[![Status](https://img.shields.io/badge/Status-Cloudflare%20Edge%20API-success.svg)](#)
[![CI/CD Tests](https://github.com/clepta2/antifraude-pro/actions/workflows/test.yml/badge.svg)](https://github.com/clepta2/antifraude-pro/actions)
[![Privacidade](https://img.shields.io/badge/Privacidade-100%25%20LGPD%20%2F%20Zero%20Cookies-emerald.svg)](#)
[![Algoritmo](https://img.shields.io/badge/Algoritmo-SHA--256%20%2B%20Heurística%20Cruzada-blue.svg)](#)
[![Velocidade](https://img.shields.io/badge/Latência-Sub--2ms%20RAM-purple.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ⚡ O que é o AntiFraude Pro?

O **AntiFraude Pro** é uma solução de infraestrutura leve desenvolvida para:
- **Device Fingerprint Determinístico (Zero Cookies):** Identifica com precisão unívoca navegadores e dispositivos a partir de assinaturas de hardware (Canvas, WebGL GPU, AudioContext, tela, CPUs e Client Hints) sem violar a privacidade do usuário.
- **Detecção Avançada de Bots & Automação:** Detecta `navigator.webdriver`, Puppeteer, Playwright, Selenium, ambientes headless e emuladores.
- **Auditoria de Rede e IPs de Datacenter:** Identifica conexões originadas de VPS, VPNs, proxies e datacenters de nuvem (AWS, GCP, DigitalOcean, Hetzner, Oracle, etc.).
- **Motor de Score de Risco de Transações (0 a 100):** Cruzamento inteligente de dados de pagamento (valor, CPF/CNPJ Módulo 11, e-mails descartáveis/trolls, telefones ANATEL e divergência geográfica entre DDD e IP).
- **Proteção contra Testes de Cartão e Força Bruta (Velocity Checks):** Monitora picos de requisições por dispositivo em janelas de tempo configuráveis.

A validação pode rodar **100% no cliente em memória RAM (0ms de latência de rede)** ou via **API Oficial na nuvem**.

---

## 🚀 Como Integrar em seu Projeto

### 1. Instalação

```bash
npm install antifraude-pro
```

*(Ou utilize o arquivo `antifraude-pro.js` diretamente no navegador ou Node.js sem necessidade de build ou dependências externas)*.

### 2. Uso Rápido no Navegador (Frontend / Checkout)

```javascript
import { AntiFraudePro } from 'antifraude-pro';

// 1. Coleta instantânea de sinais em memória RAM (<2ms)
const sinais = await AntiFraudePro.coletarSinaisNavegador();

// 2. Geração do DeviceId único
const { deviceId, deviceUuid } = AntiFraudePro.gerarDeviceId(sinais);

console.log('ID do Dispositivo:', deviceId); // "dev_2243ac15ce31f069f3a701440e0fa6b38fd0694a28ffdb0a930d58018d7e834d"
console.log('UUID v5:', deviceUuid);         // "2243ac15-ce31-4069-af3a-701440e0fa6b"

// 3. Envia os sinais junto com a transação para o seu backend
await fetch('/api/pagamento', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    valor: 249.90,
    cpf: '52998224725',
    email: 'cliente@gmail.com',
    deviceId,
    sinais
  })
});
```

### 3. Uso no Backend (Node.js / Cloudflare Workers)

```javascript
import { AntiFraudePro } from 'antifraude-pro';

// Avaliação completa de risco de checkout
const resultado = AntiFraudePro.avaliarTransacao({
  valor: 249.90,
  cpf: '52998224725',
  email: 'usuario@empresa.com.br',
  telefone: '11987654321'
}, {
  ip: '177.18.200.45',
  provedor: 'CLARO S.A.',
  estado: 'SP',
  deviceId: 'dev_2243ac15ce31...'
});

console.log(resultado.scoreRisco);   // 0 a 100
console.log(resultado.nivelRisco);   // 'baixo' | 'medio' | 'alto' | 'critico'
console.log(resultado.recomendacao); // 'aprovar' | 'desafio_2fa' | 'analise_manual' | 'bloquear'

if (resultado.recomendacao === 'bloquear') {
  throw new Error('Transação recusada por suspeita de fraude.');
}
```

---

## 📊 Tabela de Níveis de Risco e Recomendações

| Faixa de Score | Classificação | Cor | Ação Recomendada | Exemplo de Cenário |
| :---: | :---: | :---: | :---: | :--- |
| **0 – 24** | **Baixo Risco** | 🟢 Verde | **Aprovar Automaticamente** | Dados autênticos, IP residencial, navegador legítimo |
| **25 – 54** | **Médio Risco** | 🟡 Amarelo | **Exigir Confirmação 2FA / WhatsApp** | DDD do telefone divergente da localização do IP |
| **55 – 79** | **Alto Risco** | 🟠 Laranja | **Encaminhar para Análise Manual** | E-mail temporário/descartável, IP de VPN |
| **80 – 100** | **Risco Crítico** | 🔴 Vermelho | **Bloquear Transação Imediatamente** | Bot headless, CPF fraudulento, micro-valor de card testing |

---

## 🛡️ Principais Regras e Fatores de Auditoria

| Regra | Penalidade | Descrição |
| :--- | :---: | :--- |
| `TENTATIVA_EVASAO_STEALTH_SPOOFING` | **+50 pts** | Lie Detector: Manipulação de prototype (`navigator.webdriver`) ou artefatos CDP |
| `ROBO_HEADLESS_DETECTADO` | **+45 pts** | Navegador automatizado (Puppeteer, Selenium, Playwright) |
| `TELEFONE_SPAM_ANATEL` | **+40 pts** | Prefixo oficial 0303 (Telemarketing) ou 0304 (Cobrança Ativa) |
| `GPU_VIRTUAL_EMULADA_OU_SOFTWARE` | **+35 pts** | Renderizador de software virtual (Google SwiftShader, llvmpipe, Mesa) |
| `IP_DE_DATACENTER_CLOUD` | **+30 pts** | Conexão vinda de VPS/Nuvem (AWS, GCP, DigitalOcean, Oracle) |
| `ALTA_VELOCIDADE_TENTATIVAS_DEVICE` | **+30 pts** | Múltiplas tentativas de pagamento por minuto no mesmo aparelho |
| `CPF_MATEMATICAMENTE_INVALIDO` | **+25 pts** | Dígitos verificadores do CPF falsos ou inexistentes |
| `EMAIL_DESCARTAVEL_TEMPORARIO` | **+25 pts** | E-mail pertencente a provedores de descarte (Yopmail, TempMail) |
| `EMAIL_PADRAO_TROLL_SUSPEITO` | **+20 pts** | E-mail com padrões zombeteiros ou gerados por scripts |
| `VALOR_MICRO_CARD_TESTING` | **+15 pts** | Valor atipicamente baixo (≤ R$ 1,00) característico de teste de cartão |
| `DDD_DIVERGENTE_DA_LOCALIZACAO_IP` | **+15 pts** | DDD do telefone difere geograficamente do Estado do IP |

---

## 🌐 Endpoints REST na Nuvem (Ponte APIs)

- `POST https://ponte.ozpro.com.br/api/antifraude/analisar` — Avaliação completa de transação
- `GET https://ponte.ozpro.com.br/api/antifraude/device-id` — Obtenção expressa de DeviceId
- `GET https://ponte.ozpro.com.br/api/antifraude/health` — Telemetria operacional do serviço

---

## 📄 Licença

Distribuído sob licença MIT. Consulte o arquivo [LICENSE](LICENSE) para obter mais informações.
