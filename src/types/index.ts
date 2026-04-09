// ============================================================
// ClawArmor 核心类型定义
// 继承 ClawAegis 基础类型，并扩展双引擎与语义对齐专属类型
// ============================================================

// ---- 基础日志接口（继承自 ClawAegis）----

export type AegisLogger = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
};

// ---- 回合安全状态（继承自 ClawAegis）----

export type TurnSecurityState = {
  userRiskFlags: string[];
  hasToolResult: boolean;
  toolResultRiskFlags: string[];
  toolResultSuspicious: boolean;
  toolResultOversize: boolean;
  skillRiskFlags: string[];
  riskySkills: string[];
  runtimeRiskFlags: string[];
  prependNeeded: boolean;
  updatedAt: number;
};

// ---- Skill 扫描类型（继承自 ClawAegis）----

export type SkillAssessmentRecord = {
  path: string;
  hash: string;
  size: number;
  trusted: boolean;
  findings: string[];
  skillId: string;
  sourceRoot?: string;
  scannedAt: number;
};

export type TrustedSkillRecord = {
  path: string;
  hash: string;
  size: number;
  sourceRoot?: string;
  scannedAt: number;
};

export type SelfIntegrityRecord = {
  pluginId: string;
  stateDir: string;
  rootDir?: string;
  rootRealPath?: string;
  protectedRoots: string[];
  fingerprints: Record<string, string>;
  updatedAt: number;
};

export type LoopCounterEntry = {
  count: number;
  updatedAt: number;
};

export type PromptSnapshot = {
  prompt: string;
  updatedAt: number;
};

export type ToolCallRecord = {
  runId: string;
  sessionKey?: string;
  toolName: string;
  params: Record<string, unknown>;
  timestamp: number;
  blocked?: boolean;
  blockReason?: string;
};

export type SecretFingerprintRecord = {
  hash: string;
  length: number;
  source: string;
  updatedAt: number;
};

export type ScriptArtifactRecord = {
  path: string;
  hash: string;
  size: number;
  sourceTool: string;
  sessionKey?: string;
  runId: string;
  riskFlags: string[];
  updatedAt: number;
};

export type RunToolCallState = {
  sessionKey?: string;
  calls: ToolCallRecord[];
  updatedAt: number;
};

export type RunSecuritySignalState = {
  sessionKey?: string;
  sourceSignals: string[];
  transformSignals: string[];
  sinkSignals: string[];
  runtimeRiskFlags: string[];
  secretFingerprints: SecretFingerprintRecord[];
  scriptArtifacts: ScriptArtifactRecord[];
  updatedAt: number;
};

export type WorkerHealthState = {
  active: boolean;
  queueSize: number;
  failureTimestamps: number[];
  cooldownUntil?: number;
};

export type ToolResultScanOutcome = {
  hasToolResult: boolean;
  riskFlags: string[];
  suspicious: boolean;
  oversize: boolean;
};

export type UserRiskMatch = {
  flags: string[];
};

export type SkillScanRequest = {
  requestId: string;
  path: string;
  hash: string;
  size: number;
  sourceRoot?: string;
  text: string;
};

export type SkillScanResult = {
  trusted: boolean;
  findings: string[];
};

export type SkillRiskReview = {
  reviewedCount: number;
  rescannedCount: number;
  reusedCount: number;
  riskyAssessments: SkillAssessmentRecord[];
};

export type SkillScanJobResult =
  | { status: "queued" }
  | { status: "already-trusted" }
  | { status: "already-reviewed" }
  | { status: "skipped-backpressure" }
  | { status: "skipped-cooldown" };

// ============================================================
// ClawArmor 专属类型扩展
// ============================================================

// ---- 污点追踪 ----

export type TaintLevel = "clean" | "low" | "medium" | "high";

export type TaintedValue = {
  value: string;
  level: TaintLevel;
  source: string;       // 来源标识（工具名、URL 等）
  timestamp: number;
};

export type TaintRegistry = Map<string, TaintedValue>;

// ---- 意图对齐 ----

export type BaselineIntent = {
  sessionKey: string;
  originalInput: string;
  capturedAt: number;
};

export type IntentAlignmentResult = {
  aligned: boolean;
  confidence: number;       // 0-1
  deviation?: string;       // 偏离原因描述
  verdict: "safe" | "suspect" | "hijacked";
};

// ---- 模型网关 ----

export type ModelGatewayMode = "ollama" | "openai-compat" | "disabled";

export type ModelGatewayRequest = {
  systemPrompt: string;
  userContent: string;
  maxTokens?: number;
};

export type ModelGatewayResponse = {
  content: string;
  model: string;
  latencyMs: number;
};

export type IVerifierModel = {
  verify(request: ModelGatewayRequest): Promise<ModelGatewayResponse>;
  isAvailable(): Promise<boolean>;
};

// ---- 安全违规（统一结构）----

export type ThreatLevel = "info" | "low" | "medium" | "high" | "critical";

export type SecurityViolation = {
  id: string;
  layer: "foundation" | "perception" | "cognitive" | "alignment" | "execution";
  engine: "fast" | "slow";
  threatLevel: ThreatLevel;
  flag: string;
  reason: string;
  blocked: boolean;
  mode: "enforce" | "observe" | "off";
  detectedAt: number;
  meta?: Record<string, unknown>;
};

// ---- 控制流完整性 ----

export type ControlFlowCheckResult = {
  safe: boolean;
  violation?: string;
  taintedArgs: string[];
};

// ---- 数据流熔断 ----

export type DataFlowCheckResult = {
  safe: boolean;
  piiDetected: boolean;
  targetBlocked: boolean;
  matchedPatterns: string[];
};

// ---- ClawArmor 插件配置（扩展 ClawAegis 配置）----

export type ClawArmorSlowEngineConfig = {
  enabled: boolean;
  mode: "ollama" | "openai-compat" | "disabled";
  ollamaBaseUrl: string;
  ollamaModel: string;
  openaiCompatBaseUrl: string;
  openaiCompatModel: string;
  openaiCompatApiKey: string;
  intentAlignmentEnabled: boolean;
  controlFlowCheckEnabled: boolean;
  dataFlowCheckEnabled: boolean;
  timeoutMs: number;
};
