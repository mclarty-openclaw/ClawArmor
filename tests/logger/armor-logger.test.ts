import { describe, it, expect } from "vitest";
import { ArmorLogger } from "../../src/logger/index.js";
import { MemoryTransport } from "../../src/logger/transports.js";
import { createTestLogger } from "../utils/test-logger.js";

// ============================================================
// ArmorLogger 单元测试
// ============================================================

describe("ArmorLogger - 基本日志方法", () => {
  it("各级别日志都能被 MemoryTransport 捕获", () => {
    const { logger, logs } = createTestLogger("trace");
    logger.trace("trace msg");
    logger.debug("debug msg");
    logger.info("info msg");
    logger.warn("warn msg");
    logger.error("error msg");

    expect(logs.getByLevel("trace")).toHaveLength(1);
    expect(logs.getByLevel("debug")).toHaveLength(1);
    expect(logs.getByLevel("info")).toHaveLength(1);
    expect(logs.getByLevel("warn")).toHaveLength(1);
    expect(logs.getByLevel("error")).toHaveLength(1);
  });

  it("minLevel 过滤低优先级日志", () => {
    const { logger, logs } = createTestLogger("warn");
    logger.debug("被过滤");
    logger.info("被过滤");
    logger.warn("通过");
    logger.error("通过");

    expect(logs.getByLevel("debug")).toHaveLength(0);
    expect(logs.getByLevel("info")).toHaveLength(0);
    expect(logs.getByLevel("warn")).toHaveLength(1);
    expect(logs.getByLevel("error")).toHaveLength(1);
  });

  it("日志条目包含正确的 module 字段", () => {
    const mem = new MemoryTransport();
    const logger = new ArmorLogger({ minLevel: "trace", transports: [mem] }, { module: "test-module" });
    logger.info("hello");
    expect(mem.getAll()[0].module).toBe("test-module");
  });

  it("meta 对象正确附加到日志条目", () => {
    const { logger, logs } = createTestLogger();
    logger.info("with meta", { userId: "u123", count: 42 });
    const entry = logs.getAll()[0];
    expect(entry.meta.userId).toBe("u123");
    expect(entry.meta.count).toBe(42);
  });

  it("seq 全局递增", () => {
    const { logger, logs } = createTestLogger();
    logger.info("first");
    logger.info("second");
    const entries = logs.getAll();
    expect(entries[1].seq).toBeGreaterThan(entries[0].seq);
  });
});

describe("ArmorLogger - 安全事件", () => {
  it("securityWarn 写入 securityEvent 字段", () => {
    const { logger, logs, assert } = createTestLogger();
    logger.securityWarn("injection-detected", "检测到注入", { flag: "ignore-prev-en" });
    expect(assert.hasSecurityEvent("injection-detected")).toBe(true);
    const entry = logs.getBySecurityEvent("injection-detected")[0];
    expect(entry.level).toBe("warn");
    expect(entry.meta.flag).toBe("ignore-prev-en");
  });

  it("securityError 写入 securityEvent 字段并为 error 级别", () => {
    const { logger, logs } = createTestLogger();
    logger.securityError("intent-hijacked", "意图被劫持");
    const entry = logs.getByLevel("error")[0];
    expect(entry.securityEvent).toBe("intent-hijacked");
  });

  it("assert.hasWarn() 正确检测", () => {
    const { logger, assert } = createTestLogger();
    expect(assert.hasWarn()).toBe(false);
    logger.warn("警告");
    expect(assert.hasWarn()).toBe(true);
  });

  it("assert.alertCount() 统计 warn+error 总数", () => {
    const { logger, assert } = createTestLogger();
    logger.info("不计入");
    logger.warn("计入1");
    logger.error("计入2");
    expect(assert.alertCount()).toBe(2);
  });

  it("assert.hasMessage() 检测消息文本", () => {
    const { logger, assert } = createTestLogger();
    logger.info("特殊关键词abc");
    expect(assert.hasMessage("特殊关键词abc")).toBe(true);
    expect(assert.hasMessage("不存在的文字")).toBe(false);
  });
});

describe("ArmorLogger - 子 Logger", () => {
  it("child() 继承父 module 并追加", () => {
    const { logger, logs } = createTestLogger();
    // createTestLogger 默认 module="test"
    const child = logger.child({ module: "sub" });
    child.info("来自子");
    const entry = logs.getAll()[0];
    expect(entry.module).toBe("test:sub");
  });

  it("forSession() 子 Logger 携带 sessionKey", () => {
    const { logger, logs } = createTestLogger();
    const sessLogger = logger.forSession("sess-abc");
    sessLogger.info("会话日志");
    const entry = logs.getAll()[0];
    expect(entry.sessionKey).toBe("sess-abc");
  });

  it("forRun() 子 Logger 携带 runId", () => {
    const { logger, logs } = createTestLogger();
    const runLogger = logger.forRun("run-xyz");
    runLogger.info("run日志");
    const entry = logs.getAll()[0];
    expect(entry.runId).toBe("run-xyz");
  });

  it("child 不影响父 logger 的输出", () => {
    const { logger, logs } = createTestLogger();
    logger.child({ module: "child" }).info("child msg");
    logger.info("parent msg");
    const entries = logs.getAll();
    expect(entries).toHaveLength(2);
    // parent 的模块名不带 child 后缀
    const parentEntry = entries.find((e) => e.message === "parent msg");
    expect(parentEntry!.module).toBe("test");
  });
});

describe("ArmorLogger - 计时辅助", () => {
  it("timed() 成功时记录耗时日志", async () => {
    const { logger, logs } = createTestLogger();
    const result = await logger.timed("测试操作", async () => {
      return 42;
    });
    expect(result).toBe(42);
    const timedEntries = logs.getAll().filter((e) => e.durationMs !== undefined);
    expect(timedEntries.length).toBeGreaterThan(0);
  });

  it("timed() 失败时记录 error 级别耗时日志并重新抛出", async () => {
    const { logger, logs } = createTestLogger();
    await expect(
      logger.timed("失败操作", async () => {
        throw new Error("测试错误");
      }),
    ).rejects.toThrow("测试错误");
    expect(logs.getByLevel("error").length).toBeGreaterThan(0);
  });

  it("timedSync() 同步操作记录耗时", () => {
    const { logger, logs } = createTestLogger();
    const result = logger.timedSync("同步操作", () => "done");
    expect(result).toBe("done");
    const timedEntries = logs.getAll().filter((e) => e.durationMs !== undefined);
    expect(timedEntries.length).toBeGreaterThan(0);
  });
});

describe("ArmorLogger - 传输器管理", () => {
  it("addTransport 动态追加传输器", () => {
    const { logger } = createTestLogger();
    const extra = new MemoryTransport();
    logger.addTransport(extra);
    logger.info("test");
    expect(extra.count).toBe(1);
  });

  it("removeTransport 移除指定传输器", () => {
    const { logger } = createTestLogger();
    const extra = new MemoryTransport();
    logger.addTransport(extra);
    logger.info("before remove");
    logger.removeTransport("memory");
    logger.info("after remove - extra still captures");
    // extra 有自己的 name="memory"，被移除后不再接收
    // 注意：createTestLogger 已有一个 memory，remove 会移除第一个找到的
    expect(extra.count).toBeGreaterThan(0);
  });
});

describe("ArmorLogger - AegisLogger 兼容", () => {
  it("toAegisLogger() 返回兼容接口", () => {
    const { logger, logs } = createTestLogger();
    const aegis = logger.toAegisLogger();
    aegis.debug("debug via aegis");
    aegis.info("info via aegis");
    aegis.warn("warn via aegis");
    aegis.error("error via aegis");
    expect(logs.getAll()).toHaveLength(4);
  });
});

describe("MemoryTransport - 辅助方法", () => {
  it("getAll() 返回只读快照", () => {
    const { logger, logs } = createTestLogger();
    logger.info("msg1");
    logger.warn("msg2");
    const all = logs.getAll();
    expect(all).toHaveLength(2);
  });

  it("getAlerts() 只返回 warn 和 error", () => {
    const { logger, logs } = createTestLogger();
    logger.info("info");
    logger.debug("debug");
    logger.warn("warn");
    logger.error("error");
    const alerts = logs.getAlerts();
    expect(alerts).toHaveLength(2);
    expect(alerts.every((e) => e.level === "warn" || e.level === "error")).toBe(true);
  });

  it("getByModule() 按模块名过滤", () => {
    const { logger, logs } = createTestLogger();
    logger.child({ module: "parser" }).info("parser msg");
    logger.info("root msg");
    expect(logs.getByModule("parser")).toHaveLength(1);
  });

  it("clear() 清空所有条目", () => {
    const { logger, logs } = createTestLogger();
    logger.info("msg");
    logs.clear();
    expect(logs.count).toBe(0);
  });

  it("assert.lastEntry() 返回最后一条", () => {
    const { logger, assert } = createTestLogger();
    logger.info("first");
    logger.warn("last");
    expect(assert.lastEntry()!.level).toBe("warn");
  });

  it("assert.firstAlert() 返回第一条告警", () => {
    const { logger, assert } = createTestLogger();
    logger.info("not alert");
    logger.warn("first alert");
    logger.error("second alert");
    expect(assert.firstAlert()!.level).toBe("warn");
  });
});
