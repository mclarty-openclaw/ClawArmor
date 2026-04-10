// ============================================================
// ClawArmor 核心日志器
// 特性：
//  - 结构化日志（每条附带 module / sessionKey / runId / securityEvent）
//  - 多传输器（控制台 / 文件 / 内存）
//  - 子 Logger（继承上下文，无需重复传递 sessionKey）
//  - 计时辅助（自动记录操作耗时）
//  - 安全事件标记（独立字段，方便过滤）
//  - 实现 AegisLogger 接口（向后兼容）
// ============================================================

import type {
  LogLevel,
  LogEntry,
  LogTransport,
  LoggerConfig,
  LoggerContext,
  SecurityEventType,
} from "./types.js";
import { LOG_LEVEL_RANK } from "./types.js";

// 全局序列号（单进程内唯一）
let globalSeq = 0;

function nextSeq(): number {
  return ++globalSeq;
}

function nowIso(): string {
  return new Date().toISOString();
}

// ============================================================
// ArmorLogger：核心日志类
// ============================================================

export class ArmorLogger {
  private readonly config: LoggerConfig;
  private readonly context: LoggerContext;

  constructor(config: LoggerConfig, context: LoggerContext = {}) {
    this.config = config;
    this.context = context;
  }

  // ---- 标准日志方法 ----

  trace(message: string, meta: Record<string, unknown> = {}): void {
    this.emit("trace", message, meta);
  }

  debug(message: string, meta: Record<string, unknown> = {}): void {
    this.emit("debug", message, meta);
  }

  info(message: string, meta: Record<string, unknown> = {}): void {
    this.emit("info", message, meta);
  }

  warn(message: string, meta: Record<string, unknown> = {}): void {
    this.emit("warn", message, meta);
  }

  error(message: string, meta: Record<string, unknown> = {}): void {
    let stackMeta = {};
    if (this.config.captureStack) {
      stackMeta = { stack: new Error().stack };
    }
    this.emit("error", message, { ...stackMeta, ...meta });
  }

  // ---- 安全事件专用方法 ----
  // 在普通日志基础上额外写入 securityEvent 字段，便于告警聚合

  securityWarn(
    event: SecurityEventType,
    message: string,
    meta: Record<string, unknown> = {},
  ): void {
    this.emitFull("warn", message, meta, event);
  }

  securityError(
    event: SecurityEventType,
    message: string,
    meta: Record<string, unknown> = {},
  ): void {
    this.emitFull("error", message, meta, event);
  }

  // ---- 计时辅助 ----

  /**
   * 包裹一个异步操作，自动记录耗时
   * @param label  操作名称（写入 message）
   * @param fn     被测量的操作
   * @param level  耗时日志级别，默认 "debug"
   */
  async timed<T>(
    label: string,
    fn: () => Promise<T>,
    level: LogLevel = "debug",
  ): Promise<T> {
    const startMs = Date.now();
    this.emit(level, `⏱ 开始：${label}`, {});
    try {
      const result = await fn();
      const durationMs = Date.now() - startMs;
      this.emitWithDuration(level, `✓ 完成：${label}`, {}, durationMs);
      return result;
    } catch (err) {
      const durationMs = Date.now() - startMs;
      this.emitWithDuration("error", `✗ 失败：${label}`, {
        error: err instanceof Error ? err.message : String(err),
      }, durationMs);
      throw err;
    }
  }

  /**
   * 包裹同步操作，自动记录耗时
   */
  timedSync<T>(
    label: string,
    fn: () => T,
    level: LogLevel = "debug",
  ): T {
    const startMs = Date.now();
    try {
      const result = fn();
      const durationMs = Date.now() - startMs;
      this.emitWithDuration(level, `✓ ${label}`, {}, durationMs);
      return result;
    } catch (err) {
      const durationMs = Date.now() - startMs;
      this.emitWithDuration("error", `✗ ${label}`, {
        error: err instanceof Error ? err.message : String(err),
      }, durationMs);
      throw err;
    }
  }

  // ---- 子 Logger 工厂 ----

  /**
   * 创建子 Logger，继承当前上下文并叠加新字段
   * 适用场景：
   *   - 进入新模块：logger.child({ module: "shell-analyzer" })
   *   - 进入新会话：logger.child({ sessionKey: "sess-abc" })
   *   - 进入新 run：logger.child({ runId: "run-xyz" })
   */
  child(additionalContext: LoggerContext): ArmorLogger {
    return new ArmorLogger(this.config, {
      ...this.context,
      ...additionalContext,
      // 模块名追加（支持 "parent:child" 形式）
      module: additionalContext.module
        ? this.context.module
          ? `${this.context.module}:${additionalContext.module}`
          : additionalContext.module
        : this.context.module,
    });
  }

  /**
   * 创建携带 sessionKey 的子 Logger（最常用场景）
   */
  forSession(sessionKey: string): ArmorLogger {
    return this.child({ sessionKey });
  }

  /**
   * 创建携带 runId 的子 Logger
   */
  forRun(runId: string): ArmorLogger {
    return this.child({ runId });
  }

  // ---- 上下文读取 ----

  getContext(): Readonly<LoggerContext> {
    return { ...this.context };
  }

  getModule(): string {
    return this.context.module ?? "clawarmor";
  }

  // ---- 传输器管理 ----

  /** 动态追加传输器（测试中注入 MemoryTransport 的典型场景）*/
  addTransport(transport: LogTransport): void {
    this.config.transports.push(transport);
  }

  removeTransport(name: string): void {
    const idx = this.config.transports.findIndex((t) => t.name === name);
    if (idx >= 0) this.config.transports.splice(idx, 1);
  }

  /** 刷新所有支持 flush 的传输器（进程退出前调用）*/
  async flush(): Promise<void> {
    await Promise.all(
      this.config.transports.map((t) => t.flush?.() ?? Promise.resolve()),
    );
  }

  async close(): Promise<void> {
    await Promise.all(
      this.config.transports.map((t) => t.close?.() ?? Promise.resolve()),
    );
  }

  // ---- 向后兼容：实现 AegisLogger 接口 ----
  // 使 ArmorLogger 可以直接传入需要 AegisLogger 的地方

  toAegisLogger(): {
    debug: (msg: string, meta?: Record<string, unknown>) => void;
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn: (msg: string, meta?: Record<string, unknown>) => void;
    error: (msg: string, meta?: Record<string, unknown>) => void;
  } {
    return {
      debug: (msg, meta = {}) => this.debug(msg, meta),
      info:  (msg, meta = {}) => this.info(msg, meta),
      warn:  (msg, meta = {}) => this.warn(msg, meta),
      error: (msg, meta = {}) => this.error(msg, meta),
    };
  }

  // ============================================================
  // 私有实现
  // ============================================================

  private emit(
    level: LogLevel,
    message: string,
    meta: Record<string, unknown>,
    securityEvent?: SecurityEventType,
  ): void {
    if (LOG_LEVEL_RANK[level] < LOG_LEVEL_RANK[this.config.minLevel]) return;
    const entry: LogEntry = {
      seq: nextSeq(),
      timestamp: nowIso(),
      timestampMs: Date.now(),
      level,
      module: this.context.module ?? "clawarmor",
      message,
      meta: { ...meta },
      sessionKey: this.context.sessionKey as string | undefined,
      runId: this.context.runId as string | undefined,
      securityEvent,
    };
    for (const transport of this.config.transports) {
      transport.write(entry);
    }
  }

  private emitFull(
    level: LogLevel,
    message: string,
    meta: Record<string, unknown>,
    securityEvent?: SecurityEventType,
  ): void {
    this.emit(level, message, meta, securityEvent);
  }

  private emitWithDuration(
    level: LogLevel,
    message: string,
    meta: Record<string, unknown>,
    durationMs: number,
  ): void {
    if (LOG_LEVEL_RANK[level] < LOG_LEVEL_RANK[this.config.minLevel]) return;
    const entry: LogEntry = {
      seq: nextSeq(),
      timestamp: nowIso(),
      timestampMs: Date.now(),
      level,
      module: this.context.module ?? "clawarmor",
      message,
      meta: { ...meta },
      sessionKey: this.context.sessionKey as string | undefined,
      runId: this.context.runId as string | undefined,
      durationMs,
    };
    for (const transport of this.config.transports) {
      transport.write(entry);
    }
  }
}

// ============================================================
// 工厂函数：创建不同场景的 Logger
// ============================================================

/**
 * 创建标准生产 Logger（控制台 pretty 输出）
 */
export function createLogger(options: {
  module?: string;
  minLevel?: LogLevel;
  format?: "pretty" | "json";
}, transports: LogTransport[]): ArmorLogger {
  return new ArmorLogger(
    {
      minLevel: options.minLevel ?? "info",
      transports,
    },
    { module: options.module ?? "clawarmor" },
  );
}

/**
 * 创建带文件输出的生产 Logger
 */
export function createFileLogger(options: {
  module?: string;
  minLevel?: LogLevel;
}, transports: LogTransport[]): ArmorLogger {
  return new ArmorLogger(
    { minLevel: options.minLevel ?? "info", transports },
    { module: options.module ?? "clawarmor" },
  );
}

/**
 * 将 meta 对象中的关键字段序列化追加到 message 字符串
 * 用于绕过 OpenClaw api.logger 静默丢弃 meta 的问题
 * 超长字符串字段（如 systemPrompt / userContent / response）截断至 200 字符
 */
function buildMessageWithMeta(message: string, meta: Record<string, unknown>): string {
  if (Object.keys(meta).length === 0) return message;

  // 长文本字段截断，避免单行日志过长
  const LONG_FIELDS = new Set(["systemPrompt", "userContent", "response", "stack"]);
  const MAX_FIELD_LEN = 200;

  const compacted: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (v === undefined || v === null || v === "") continue;
    if (LONG_FIELDS.has(k) && typeof v === "string" && v.length > MAX_FIELD_LEN) {
      compacted[k] = v.slice(0, MAX_FIELD_LEN) + "…";
    } else {
      compacted[k] = v;
    }
  }

  if (Object.keys(compacted).length === 0) return message;

  try {
    return `${message} | ${JSON.stringify(compacted)}`;
  } catch {
    return message;
  }
}

/**
 * 从现有 AegisLogger（如 OpenClaw 注入的 logger）创建 ArmorLogger
 * 将第三方 logger 包装成 ArmorLogger，保留结构化能力
 */
export function fromAegisLogger(
  aegisLogger: {
    debug?: (msg: string, meta?: Record<string, unknown>) => void;
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn: (msg: string, meta?: Record<string, unknown>) => void;
    error: (msg: string, meta?: Record<string, unknown>) => void;
  },
  context: LoggerContext = {},
): ArmorLogger {
  // 桥接传输器：将结构化日志转发给 AegisLogger
  // 注意：OpenClaw 的 api.logger 只写 message 字符串，meta 参数被静默丢弃
  // 因此将关键 meta 字段直接序列化追加到 message 中，确保在 gateway.log 可见
  const bridgeTransport: LogTransport = {
    name: "aegis-bridge",
    write(entry: LogEntry): void {
      const meta: Record<string, unknown> = { ...entry.meta };
      if (entry.sessionKey) meta.sessionKey = entry.sessionKey;
      if (entry.runId) meta.runId = entry.runId;
      if (entry.securityEvent) meta.securityEvent = entry.securityEvent;
      if (entry.durationMs !== undefined) meta.durationMs = entry.durationMs;

      // 将 meta 序列化追加到 message，绕过 OpenClaw logger 丢弃 meta 的问题
      const message = buildMessageWithMeta(entry.message, meta);

      switch (entry.level) {
        case "trace":
        case "debug": aegisLogger.debug?.(message, meta); break;
        case "info":  aegisLogger.info(message, meta); break;
        case "warn":  aegisLogger.warn(message, meta); break;
        case "error": aegisLogger.error(message, meta); break;
      }
    },
  };

  return new ArmorLogger(
    { minLevel: "debug", transports: [bridgeTransport] },
    { module: "clawarmor", ...context },
  );
}

// ---- 导出子模块 ----
export type { LogLevel, LogEntry, LogTransport, LoggerConfig, LoggerContext, SecurityEventType } from "./types.js";
export { LOG_LEVEL_RANK } from "./types.js";
