// ============================================================
// ClawArmor 测试日志工具
// 为测试提供零配置的 ArmorLogger + 内存捕获
// ============================================================

import { ArmorLogger } from "../../src/logger/index.js";
import { MemoryTransport } from "../../src/logger/transports.js";
import type { LogEntry, LogLevel, SecurityEventType } from "../../src/logger/types.js";

export type TestLoggerResult = {
  /** 注入到被测模块的 logger 实例 */
  logger: ArmorLogger;
  /** 内存传输器，用于断言 */
  logs: MemoryTransport;
  /**
   * 快速断言辅助集合
   */
  assert: {
    /** 是否有 warn 级别日志 */
    hasWarn(): boolean;
    /** 是否有 error 级别日志 */
    hasError(): boolean;
    /** 是否有指定安全事件 */
    hasSecurityEvent(event: SecurityEventType): boolean;
    /** 是否有包含指定文本的消息 */
    hasMessage(text: string): boolean;
    /** warn/error 条目数量 */
    alertCount(): number;
    /** 获取最后一条日志 */
    lastEntry(): LogEntry | undefined;
    /** 获取第一条 warn 或 error */
    firstAlert(): LogEntry | undefined;
    /** 打印所有日志到控制台（调试用）*/
    dump(): void;
  };
};

/**
 * 创建测试专用 Logger
 *
 * @example
 * ```ts
 * const { logger, logs, assert } = createTestLogger();
 *
 * // 注入到被测模块
 * const engine = new SomeEngine(logger.toAegisLogger());
 * await engine.scan("bad input");
 *
 * // 断言
 * expect(assert.hasWarn()).toBe(true);
 * expect(assert.hasSecurityEvent("injection-detected")).toBe(true);
 * expect(logs.getByLevel("warn")).toHaveLength(1);
 * ```
 */
export function createTestLogger(minLevel: LogLevel = "trace"): TestLoggerResult {
  const memTransport = new MemoryTransport();
  const logger = new ArmorLogger(
    { minLevel, transports: [memTransport] },
    { module: "test" },
  );

  const assert = {
    hasWarn: () => memTransport.getByLevel("warn").length > 0,
    hasError: () => memTransport.getByLevel("error").length > 0,
    hasSecurityEvent: (event: SecurityEventType) => memTransport.hasSecurityEvent(event),
    hasMessage: (text: string) => memTransport.hasMessage(text),
    alertCount: () => memTransport.getAlerts().length,
    lastEntry: () => {
      const all = memTransport.getAll();
      return all.length > 0 ? all[all.length - 1] : undefined;
    },
    firstAlert: () => memTransport.getAlerts()[0],
    dump: () => {
      console.log("\n─── Test Logger Dump ───");
      for (const e of memTransport.getAll()) {
        const seEvent = e.securityEvent ? ` ⚑${e.securityEvent}` : "";
        const dur = e.durationMs !== undefined ? ` +${e.durationMs}ms` : "";
        const meta = Object.keys(e.meta).length > 0 ? ` ${JSON.stringify(e.meta)}` : "";
        console.log(`[${e.level.toUpperCase()}] [${e.module}]${seEvent} ${e.message}${dur}${meta}`);
      }
      console.log("────────────────────────\n");
    },
  };

  return { logger, logs: memTransport, assert };
}

/**
 * 创建 AegisLogger 接口兼容的测试日志（给不接受 ArmorLogger 的模块用）
 */
export function createAegisTestLogger(): {
  aegisLogger: {
    debug: (msg: string, meta?: Record<string, unknown>) => void;
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn: (msg: string, meta?: Record<string, unknown>) => void;
    error: (msg: string, meta?: Record<string, unknown>) => void;
  };
  captured: { level: string; message: string; meta: Record<string, unknown> }[];
} {
  const captured: { level: string; message: string; meta: Record<string, unknown> }[] = [];
  const aegisLogger = {
    debug: (msg: string, meta: Record<string, unknown> = {}) => captured.push({ level: "debug", message: msg, meta }),
    info:  (msg: string, meta: Record<string, unknown> = {}) => captured.push({ level: "info",  message: msg, meta }),
    warn:  (msg: string, meta: Record<string, unknown> = {}) => captured.push({ level: "warn",  message: msg, meta }),
    error: (msg: string, meta: Record<string, unknown> = {}) => captured.push({ level: "error", message: msg, meta }),
  };
  return { aegisLogger, captured };
}
