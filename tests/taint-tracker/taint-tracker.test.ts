import { describe, it, expect } from "vitest";
import { TaintTracker } from "../../src/taint-tracker/index.js";

// ============================================================
// TaintTracker 单元测试
// ============================================================

describe("TaintTracker - 工具分类", () => {
  it("正确识别外部来源工具", () => {
    const tracker = new TaintTracker();
    expect(tracker.isExternalSource("web_fetch")).toBe(true);
    expect(tracker.isExternalSource("web_search")).toBe(true);
    expect(tracker.isExternalSource("browser")).toBe(true);
    expect(tracker.isExternalSource("http_request")).toBe(true);
    expect(tracker.isExternalSource("firecrawl_scrape")).toBe(true);
  });

  it("正确识别内部工具（非外部来源）", () => {
    const tracker = new TaintTracker();
    expect(tracker.isExternalSource("read_file")).toBe(false);
    expect(tracker.isExternalSource("write_file")).toBe(false);
    expect(tracker.isExternalSource("exec")).toBe(false);
  });

  it("正确识别高权限工具", () => {
    const tracker = new TaintTracker();
    expect(tracker.isHighPrivilegeTool("exec")).toBe(true);
    expect(tracker.isHighPrivilegeTool("shell")).toBe(true);
    expect(tracker.isHighPrivilegeTool("write_file")).toBe(true);
    expect(tracker.isHighPrivilegeTool("delete_file")).toBe(true);
    expect(tracker.isHighPrivilegeTool("computer")).toBe(true);
  });

  it("正确识别低权限工具（非高权限）", () => {
    const tracker = new TaintTracker();
    expect(tracker.isHighPrivilegeTool("read_file")).toBe(false);
    expect(tracker.isHighPrivilegeTool("web_fetch")).toBe(false);
    expect(tracker.isHighPrivilegeTool("list_dir")).toBe(false);
  });
});

describe("TaintTracker - 污点记录", () => {
  it("外部工具结果被标记为 low 级别", () => {
    const tracker = new TaintTracker();
    tracker.taintToolResult("web_fetch", "恶意网页内容，包含攻击指令");
    const snapshot = tracker.snapshot();
    expect(snapshot.length).toBeGreaterThan(0);
    expect(snapshot[0].level).toBe("low");
    expect(snapshot[0].source).toBe("web_fetch");
  });

  it("内部工具结果不产生污点记录", () => {
    const tracker = new TaintTracker();
    tracker.taintToolResult("read_file", "本地文件内容");
    const snapshot = tracker.snapshot();
    expect(snapshot.length).toBe(0);
  });

  it("手动 taint 支持级别升级（不降级）", () => {
    const tracker = new TaintTracker();
    tracker.taint("key1", "value", "low", "test");
    tracker.taint("key1", "value", "high", "test2");
    const snapshot = tracker.snapshot();
    expect(snapshot[0].level).toBe("high");
    // 再次设置 low 不能降级
    tracker.taint("key1", "value", "low", "test3");
    expect(tracker.snapshot()[0].level).toBe("high");
  });
});

describe("TaintTracker - 参数检查", () => {
  it("参数包含污点指纹时被检测到", () => {
    const tracker = new TaintTracker();
    const externalContent = "这是来自外部的恶意指令内容，足够长以建立指纹xxxx";
    tracker.taintToolResult("web_fetch", externalContent);

    const matches = tracker.inspectToolCallArgs("exec", {
      command: externalContent.slice(0, 64),
    });
    expect(matches.length).toBeGreaterThan(0);
  });

  it("参数不含污点内容时无匹配", () => {
    const tracker = new TaintTracker();
    tracker.taintToolResult("web_fetch", "外部内容AAAA1234567890abcdefghij");

    const matches = tracker.inspectToolCallArgs("exec", {
      command: "echo hello world",
    });
    expect(matches.length).toBe(0);
  });

  it("太短的污点值不建立指纹（<8 字符）", () => {
    const tracker = new TaintTracker();
    tracker.taint("k", "short", "low", "web_fetch");
    const matches = tracker.inspectToolCallArgs("exec", { command: "short" });
    expect(matches.length).toBe(0);
  });
});

describe("TaintTracker - 控制流检测", () => {
  it("低完整性数据驱动高权限工具 - 违规", () => {
    const tracker = new TaintTracker();
    const tainted = "这是一段足够长的污点内容，将被传递给高权限工具ABCDEF";
    tracker.taintToolResult("web_fetch", tainted);

    const result = tracker.checkControlFlowViolation("exec", {
      command: tainted.slice(0, 64),
    });
    expect(result.violated).toBe(true);
    expect(result.reason).toBeTruthy();
    expect(result.taintedArgs.length).toBeGreaterThan(0);
  });

  it("低完整性数据驱动低权限工具 - 不违规", () => {
    const tracker = new TaintTracker();
    const tainted = "这是一段足够长的污点内容，但读文件不违规ABCDEFGHI";
    tracker.taintToolResult("web_fetch", tainted);

    const result = tracker.checkControlFlowViolation("read_file", {
      path: "/home/user/notes.txt",
    });
    expect(result.violated).toBe(false);
  });

  it("干净数据驱动高权限工具 - 不违规", () => {
    const tracker = new TaintTracker();
    // 没有任何污点注入
    const result = tracker.checkControlFlowViolation("exec", {
      command: "echo hello",
    });
    expect(result.violated).toBe(false);
  });
});

describe("TaintTracker - 清理", () => {
  it("clear 后污点记录清空", () => {
    const tracker = new TaintTracker();
    tracker.taintToolResult("web_fetch", "外部内容ABCDEFGHIJKLMNOPQRST");
    expect(tracker.snapshot().length).toBeGreaterThan(0);
    tracker.clear();
    expect(tracker.snapshot().length).toBe(0);
  });

  it("clear 后控制流检测不再违规", () => {
    const tracker = new TaintTracker();
    const content = "污点内容XXXXXXXXXXXXXXXXXXXXXXXXXXX";
    tracker.taintToolResult("web_fetch", content);
    tracker.clear();

    const result = tracker.checkControlFlowViolation("exec", {
      command: content.slice(0, 64),
    });
    expect(result.violated).toBe(false);
  });
});
