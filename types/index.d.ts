/**
 * AntiFraude Pro - Declaração de Tipos TypeScript
 * @license MIT
 */

export interface SinaisCliente {
  tela?: {
    largura: number;
    altura: number;
    profundidadeCores: number;
    pixelRatio: number;
  };
  hardware?: {
    concorrenciaCpus: number;
    memoriaGb: number;
    maxTouchPoints: number;
  };
  software?: {
    userAgent: string;
    plataforma: string;
    idiomas: string;
    timeZone: string;
  };
  hashes?: {
    canvas: string;
    webglRenderer: string;
    webglVendor: string;
    audio: string;
  };
  seguranca?: {
    isWebdriver: boolean;
    webdriverSpoofed?: boolean;
    hasCdcArtifacts?: boolean;
    isZeroDimension?: boolean;
    isVirtualGpu?: boolean;
    hasPluginsInconsistency?: boolean;
    isHeadless: boolean;
    hasTouch: boolean;
  };
}

export interface GpuVirtualResult {
  isVirtual: boolean;
  nome: string | null;
  detalhes: string | null;
}

export interface LieDetectorResult {
  adulterado: boolean;
  motivos: string[];
  confianca: number;
}

export interface TelefoneResult {
  valido: boolean;
  ddd: number | null;
  uf: string | null;
  isCelular: boolean;
  isSpam: boolean;
  tipoSpam: string | null;
  motivoSpam: string | null;
  isGratuito?: boolean;
}

export interface DeviceIdResult {
  deviceId: string;
  deviceUuid: string;
  rawHash: string;
  confiancaPercent: number;
}

export interface FatorRisco {
  regra: string;
  peso: number;
  descricao: string;
}

export interface ParecerRisco {
  ok: boolean;
  scoreRisco: number;
  nivelRisco: 'baixo' | 'medio' | 'alto' | 'critico';
  recomendacao: 'aprovar' | 'desafio_2fa' | 'analise_manual' | 'bloquear';
  corBadge: string;
  deviceId: string;
  fatoresRisco: FatorRisco[];
  avisos: string[];
  detalhes: {
    documentoValido: boolean | null;
    emailAuditado: object | null;
    telefoneAuditado?: TelefoneResult | null;
    gpuVirtualAuditada?: GpuVirtualResult;
    lieDetector?: LieDetectorResult;
    isHeadlessBot: boolean;
    isDatacenterConexao: boolean;
    totalFatoresAcionados: number;
  };
  timestamp: string;
}

export interface AntiFraudeConfig {
  faixas?: {
    critico?: number;
    alto?: number;
    medio?: number;
  };
  velocidade?: {
    limitePadrao?: number;
    janelaSegundosPadrao?: number;
  };
  pesos?: Record<string, number>;
  desabilitar?: string[];
  habilitar?: string[];
  dominiosDescartaveis?: string[];
  whitelistIps?: string[];
  whitelistDeviceIds?: string[];
}

export interface RegraCustomizada {
  id: string;
  peso?: number;
  descricao?: string;
  avaliar: (transacao: Record<string, any>, contexto: Record<string, any>) => boolean | { acionou: boolean; peso?: number; descricao?: string };
}

export declare class AntiFraudePro {
  static get version(): string;
  static config: AntiFraudeConfig;
  static configurar(opcoes?: AntiFraudeConfig): AntiFraudeConfig;
  static adicionarRegra(regra: RegraCustomizada): void;
  static resetarConfiguracao(): void;
  static hashSha256(texto: string): string;
  static hexParaUuid(hex64: string): string;
  static validarCpf(cpf: string): boolean;
  static validarCnpj(cnpj: string): boolean;
  static analisarTelefone(telefone: string): TelefoneResult;
  static analisarEmail(email: string): { valido: boolean; descartavel: boolean; troll: boolean; dominio: string };
  static verificarGpuVirtual(webglRenderer: string): GpuVirtualResult;
  static executarLieDetector(sinais?: SinaisCliente): LieDetectorResult;
  static coletarSinaisNavegador(): Promise<SinaisCliente>;
  static gerarDeviceId(sinais?: SinaisCliente): DeviceIdResult;
  static checarVelocidade(chave: string, limiteTentativas?: number, janelaSegundos?: number): { violouVelocidade: boolean; totalRecente: number };
  static avaliarTransacao(transacao?: Record<string, any>, contexto?: Record<string, any>): ParecerRisco;
}
