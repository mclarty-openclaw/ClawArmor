// ============================================================
// ClawArmor 日志传输器实现
// ============================================================

import { promises as fs } from "node:fs";
import path from "node:path";
import type { LogEntry, LogLevel, LogTransport } from "./types.js";

// ---- 颜色 ANSI 码（控制台输出用）----
const ANSI = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  trace:  "\x1b[90m",   // 深灰
  debug:  "\x1b[36m",   // 青色
  info:   "\x1b[32m",   // 绿色
  warn:   "\x1b[33m",   // 黄色
  error:  "\x1b[31m",   // 红色
  module: "\x1b[35m",   // 品红
  key:    "\x1b[34m",   // 蓝色
} as const;

const LEVEL_COLOR: Record<LogLevel, string> = {
  trace: ANSI.trace,
  debug: ANSI.debug,
  info:  ANSI.info,
  warn:  ANSI.warn,
  error: ANSI.error,
};

const LEVEL_LABEL: Record<LogLevel, string> = {
  trace: "TRACE",
  debug: "DEBUG",
  info:  " INFO",
  warn:  " WARN",
  error: "ERROR",
};

// ============================================================
// 1. 控制台传输器
// ============================================================

export type ConsoleTransportOptions = {
  /** "pretty"：彩色可读格式（开发）；"json"：单行 JSON（生产/采集）*/
  format?: "pretty" | "json";
  /** 是否显示时间戳 */
  showTimestamp?: boolean;
  /** 是否显示 seq */
  showSeq?: boolean;
  /** 是否输出颜色（仅 pretty 模式）*/
  useColors?: boolean;
  /** 输出目标：stdout 或 stderr */
  target?: "stdout" | "stderr";
};

export class ConsoleTransport implements LogTransport {
  readonly name = "console";
  private readonly format: "pretty" | "json";
  private readonly showTimestamp: boolean;
  private readonly showSeq: boolean;
  private readonly useColors: boolean;
  private readonly write_: (data: string) => void;

  constructor(opts: ConsoleTransportOptions = {}) {
    this.format = opts.format ?? "pretty";
    this.showTimestamp = opts.showTimestamp ?? true;
    this.showSeq = opts.showSeq ?? false;
    this.useColors = opts.useColors ?? (process.stdout.isTTY ?? false);
    const stream = opts.target === "stderr" ? process.stderr : process.stdout;
    this.write_ = (data) => stream.write(data + "\n");
  }

  write(entry: LogEntry): void {
    if (this.format === "json") {
      this.write_(JSON.stringify(entry));
      return;
    }
    this.write_(this.formatPretty(entry));
  }

  private formatPretty(entry: LogEntry): string {
    const c = this.useColors;
    const levelColor = c ? (LEVEL_COLOR[entry.level] ?? "") : "";
    const reset = c ? ANSI.reset : "";
    const dim = c ? ANSI.dim : "";
    const bold = c ? ANSI.bold : "";
    const modColor = c ? ANSI.module : "";

    const parts: string[] = [];

    // 序列号
    if (this.showSeq) {
      parts.push(`${dim}[${String(entry.seq).padStart(5, "0")}]${reset}`);
    }

    // 时间戳
    if (this.showTimestamp) {
      parts.push(`${dim}${entry.timestamp}${reset}`);
    }

    // 级别标签
    parts.push(`${levelColor}${bold}${LEVEL_LABEL[entry.level]}${reset}`);

    // 模块名
    if (entry.module) {
      parts.push(`${modColor}[${entry.module}]${reset}`);
    }

    // sessionKey / runId（简短形式）
    const ctx: string[] = [];
    if (entry.sessionKey) ctx.push(`sess:${entry.sessionKey.slice(-6)}`);
    if (entry.runId) ctx.push(`run:${entry.runId.slice(-6)}`);
    if (ctx.length > 0) parts.push(`${dim}(${ctx.join(" ")})${reset}`);

    // 安全事件标记
    if (entry.securityEvent) {
      parts.push(`${levelColor}⚑${entry.securityEvent}${reset}`);
    }

    // 消息
    parts.push(`${entry.message}`);

    // 耗时
    if (entry.durationMs !== undefined) {
      parts.push(`${dim}+${entry.durationMs}ms${reset}`);
    }

    let line = parts.join(" ");

    // 元数据（换行展示，缩进）
    const metaKeys = Object.keys(entry.meta);
    if (metaKeys.length > 0) {
      const metaStr = metaKeys
        .map((k) => {
          const v = entry.meta[k];
          const val = typeof v === "object" ? JSON.stringify(v) : String(v);
          return c ? `  ${ANSI.key}${k}${reset}=${val}` : `  ${k}=${val}`;
        })
        .join("\n");
      line += "\n" + metaStr;
    }

    return line;
  }
}

// ============================================================
// 2. 文件传输器（带缓冲写入）
// ============================================================

export type FileTransportOptions = {
  filePath: string;
  /** 格式，默认 "json"（便于日志采集工具解析）*/
  format?: "json" | "pretty";
  /** 最大缓冲行数，达到后自动 flush */
  bufferSize?: number;
  /** 最大文件大小（字节），超过后轮转 */
  maxFileSizeBytes?: number;
};

export class FileTransport implements LogTransport {
  readonly name = "file";
  private buffer: string[] = [];
  private currentSize = 0;
  private readonly format: "json" | "pretty";
  private readonly bufferSize: number;
  private readonly maxFileSizeBytes: number;
  private flushing = false;

  constructor(private readonly opts: FileTransportOptions) {
    this.format = opts.format ?? "json";
    this.bufferSize = opts.bufferSize ?? 50;
    this.maxFileSizeBytes = opts.maxFileSizeBytes ?? 10 * 1024 * 1024; // 10MB
  }

  write(entry: LogEntry): void {
    const line = this.format === "json" ? JSON.stringify(entry) : this.formatLine(entry);
    this.buffer.push(line);
    this.currentSize += line.length + 1;

    if (this.buffer.length >= this.bufferSize) {
      this.flush().catch(() => undefined);
    }
  }

  async flush(): Promise<void> {
    if (this.flushing || this.buffer.length === 0) return;
    this.flushing = true;
    const lines = this.buffer.splice(0);
    try {
      await fs.mkdir(path.dirname(this.opts.filePath), { recursive: true });
      await fs.appendFile(this.opts.filePath, lines.join("\n") + "\n", "utf8");

      // 简单轮转：超过大小则重命名
      try {
        const stat = await fs.stat(this.opts.filePath);
        if (stat.size > this.maxFileSizeBytes) {
          const rotated = `${this.opts.filePath}.${Date.now()}.bak`;
          await fs.rename(this.opts.filePath, rotated);
        }
      } catch { /* 忽略 stat 错误 */ }
    } catch { /* 写入失败不影响主流程 */ } finally {
      this.flushing = false;
    }
  }

  async close(): Promise<void> {
    await this.flush();
  }

  private formatLine(entry: LogEntry): string {
    return `${entry.timestamp} ${LEVEL_LABEL[entry.level]} [${entry.module}] ${entry.message} ${JSON.stringify(entry.meta)}`;
  }
}

// ============================================================
// 3. 内存传输器（测试专用）
// ============================================================

export class MemoryTransport implements LogTransport {
  readonly name = "memory";
  private readonly entries: LogEntry[] = [];

  write(entry: LogEntry): void {
    this.entries.push({ ...entry, meta: { ...entry.meta } });
  }

  // ---- 测试断言辅助方法 ----

  /** 返回所有捕获的日志条目（只读快照）*/
  getAll(): readonly LogEntry[] {
    return [...this.entries];
  }

  /** 按级别过滤 */
  getByLevel(level: LogLevel): LogEntry[] {
    return this.entries.filter((e) => e.level === level);
  }

  /** 按模块过滤 */
  getByModule(module: string): LogEntry[] {
    return this.entries.filter((e) => e.module.includes(module));
  }

  /** 按安全事件类型过滤 */
  getBySecurityEvent(type: string): LogEntry[] {
    return this.entries.filter((e) => e.securityEvent === type);
  }

  /** 查找第一条消息匹配的条目 */
  find(predicate: (entry: LogEntry) => boolean): LogEntry | undefined {
    return this.entries.find(predicate);
  }

  /** 检查是否存在包含指定文本的消息 */
  hasMessage(text: string): boolean {
    return this.entries.some((e) => e.message.includes(text));
  }

  /** 检查是否存在指定安全事件 */
  hasSecurityEvent(type: string): boolean {
    return this.entries.some((e) => e.securityEvent === type);
  }

  /** 返回所有 warn/error 条目（快速安全审计）*/
  getAlerts(): LogEntry[] {
    return this.entries.filter((e) => e.level === "warn" || e.level === "error");
  }

  /** 清空（用于多个测试用例之间重置）*/
  clear(): void {
    this.entries.length = 0;
  }

  /** 条目总数 */
  get count(): number {
    return this.entries.length;
  }
}
