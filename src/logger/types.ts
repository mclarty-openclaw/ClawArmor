// ============================================================
// ClawArmor 日志系统类型定义
// ============================================================

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";

/** 日志级别数值（越大越严重）*/
export const LOG_LEVEL_RANK: Record<LogLevel, number> = {
  trace: 0,
  debug: 1,
  info:  2,
  warn:  3,
  error: 4,
};

/** 结构化日志条目 */
export type LogEntry = {
  /** 单调递增序列号，方便排序 */
  seq: number;
  /** ISO 时间戳 */
  timestamp: string;
  /** Unix 毫秒时间戳（精确计时用）*/
  timestampMs: number;
  level: LogLevel;
  /** 模块名称，如 "engine-fast:shell-analyzer" */
  module: string;
  message: string;
  /** 结构化元数据 */
  meta: Record<string, unknown>;
  /** 会话 ID（跨 Hook 追踪）*/
  sessionKey?: string;
  /** Run ID（跨工具调用追踪）*/
  runId?: string;
  /** 安全事件标记（便于过滤）*/
  securityEvent?: SecurityEventType;
  /** 操作耗时（毫秒，仅计时场景）*/
  durationMs?: number;
};

/** 安全事件类型（结构化告警分类）*/
export type SecurityEventType =
  | "injection-detected"
  | "secret-leak-detected"
  | "shell-threat-detected"
  | "payload-detected"
  | "protected-path-access"
  | "taint-violation"
  | "data-exfiltration"
  | "memory-write-blocked"
  | "intent-hijacked"
  | "intent-suspect"
  | "skill-risk-detected"
  | "tool-result-suspicious"
  | "loop-detected"
  | "output-redacted"
  | "plugin-startup"
  | "plugin-shutdown";

/** 日志传输器接口 */
export type LogTransport = {
  name: string;
  write(entry: LogEntry): void;
  flush?(): Promise<void>;
  close?(): Promise<void>;
};

/** 子 Logger 绑定的上下文 */
export type LoggerContext = {
  module?: string;
  sessionKey?: string;
  runId?: string;
  [key: string]: unknown;
};

/** Logger 配置 */
export type LoggerConfig = {
  /** 最低输出级别（低于此级别的日志被丢弃）*/
  minLevel: LogLevel;
  /** 传输器列表 */
  transports: LogTransport[];
  /** 是否在 meta 中捕获调用栈（仅 error 级别）*/
  captureStack?: boolean;
};
