// ============================================================
// ClawArmor Shell 命令威胁分析器
// 职责：检测 Shell 命令混淆技术，独立原创实现
// ============================================================

// ---- 不可见/零宽 Unicode 码点集合 ----
// 这些字符可用于视觉欺骗，让恶意命令看起来无害
const ZERO_WIDTH_CODEPOINTS = new Set([
  0x00AD, // 软连字符
  0x034F, // 组合图形连接
  0x061C, // 阿拉伯字母标记
  0x180B, 0x180C, 0x180D, 0x180E, 0x180F, // 蒙古变体选择器
  0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // 零宽空格系列
  0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // 双向覆盖控制
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // 不可见数学运算符
  0x2066, 0x2067, 0x2068, 0x2069,           // 双向隔离控制
  0xFEFF, // 字节序标记（BOM）
]);

// ---- 混淆攻击分类 ----

type ObfuscationCategory =
  | "unicode-steganography"   // Unicode 零宽字符插入
  | "encoded-pipe-exec"       // 编码数据管道执行
  | "remote-fetch-exec"       // 远程获取并执行
  | "interpreter-encoded"     // 解释器编码命令
  | "char-escape-exec"        // 字符转义执行
  | "variable-expansion"      // 变量展开混淆
  | "command-too-long";       // 命令超长（防止扫描绕过）

export type ShellAnalysisResult = {
  isThreat: boolean;
  categories: ObfuscationCategory[];
  matchedSignatures: string[];
};

// ---- 编码管道执行签名 ----
// 特征：将编码数据解码后直接传入 Shell 执行

const ENCODED_PIPE_EXEC_SIGS = [
  { id: "b64d-to-shell",     regex: /base64\s+(?:-d|--decode)\b[^|]*\|\s*(?:su?do\s+)?(?:sh|bash|zsh|dash|ksh|fish)\b/i },
  { id: "xxd-r-to-shell",   regex: /xxd\s+-r\b[^|]*\|\s*(?:sh|bash|zsh|dash|ksh|fish)\b/i },
  { id: "printf-hex-shell",  regex: /printf\s+['"\\x0-9a-f\s]+\|\s*(?:sh|bash|zsh|dash|ksh|fish)\b/i },
  { id: "eval-b64",          regex: /eval\s+.*\$\(\s*(?:echo|printf)\s+[A-Za-z0-9+/=]{8,}\s*\|\s*base64/i },
] as const;

// ---- 远程获取执行签名 ----

const REMOTE_FETCH_EXEC_SIGS = [
  { id: "curl-pipe-sh",      regex: /(?:curl|wget)\s+(?:-[A-Za-z0-9]+\s+)*https?:\/\/[^\s|]+\s*\|\s*(?:su?do\s+)?(?:sh|bash|zsh|dash|ksh|fish)\b/i },
  { id: "process-sub-fetch", regex: /(?:sh|bash|zsh)\s+<\s*\(\s*(?:curl|wget)\s+/i },
  { id: "source-remote",     regex: /(?:source|\.)\s+<\s*\(\s*(?:curl|wget)\s+/i },
] as const;

// ---- 解释器编码命令签名 ----

const INTERPRETER_ENCODED_SIGS = [
  { id: "python-b64exec",    regex: /python[23]?\s+-[cCeE]\s+['"].*(?:base64|b64decode|exec|eval|decode)/i },
  { id: "node-buf-exec",     regex: /node\s+-[eE]\s+['"].*(?:Buffer\.from|atob|require\('child_process'\)|eval)/i },
  { id: "pwsh-encoded",      regex: /(?:powershell|pwsh)\b.*-[Ee]ncodedCommand\s+[A-Za-z0-9+/=_-]{8,}/i },
  { id: "heredoc-shell",     regex: /(?:sh|bash|zsh)\s+<<-?\s*['"]?[A-Z_][A-Z0-9_]*['"]?\s*\n/i },
] as const;

// ---- 字符转义执行签名 ----

const CHAR_ESCAPE_SIGS = [
  { id: "ansi-c-octal",      regex: /\$'(?:[^'\\]|\\[0-7]{3}){3,}'/ },
  { id: "ansi-c-hex",        regex: /\$'(?:[^'\\]|\\x[0-9a-fA-F]{2}){3,}'/ },
  { id: "cmd-sub-decode",    regex: /\$\(\s*(?:echo|printf)\s+[A-Za-z0-9+/=\\x,\s]+\s*\|\s*(?:base64|xxd)/i },
] as const;

// ---- 变量展开混淆签名 ----

const VARIABLE_EXPANSION_SIGS = [
  { id: "var-concat-exec",   regex: /(?:[a-zA-Z_]\w{0,3}=['"][^'"]{1,30}['"]\s*;?\s*){3,}\$[{(]?[a-zA-Z_]/ },
] as const;

const MAX_COMMAND_LENGTH = 10_000;

// ---- 核心分析函数 ----

/**
 * 从命令字符串中移除零宽/不可见 Unicode 字符后正规化
 */
function normalizeCommand(raw: string): string {
  const stripped = [...raw]
    .filter((ch) => !ZERO_WIDTH_CODEPOINTS.has(ch.codePointAt(0) ?? -1))
    .join("");
  return stripped.normalize("NFKC");
}

/**
 * 检测字符串中是否存在零宽 Unicode 字符
 */
function detectUnicodeSteganography(raw: string): boolean {
  return [...raw].some((ch) => ZERO_WIDTH_CODEPOINTS.has(ch.codePointAt(0) ?? -1));
}

/**
 * 主入口：分析 Shell 命令字符串的威胁级别
 */
export function analyzeShellCommand(command: string | undefined | null): ShellAnalysisResult {
  if (!command || !command.trim()) {
    return { isThreat: false, categories: [], matchedSignatures: [] };
  }

  const categories: ObfuscationCategory[] = [];
  const matchedSignatures: string[] = [];

  // 超长命令检查（防止扫描器被绕过）
  if (command.length > MAX_COMMAND_LENGTH) {
    return {
      isThreat: true,
      categories: ["command-too-long"],
      matchedSignatures: ["command-too-long"],
    };
  }

  // Unicode 隐写检查（在正规化前做）
  if (detectUnicodeSteganography(command)) {
    categories.push("unicode-steganography");
    matchedSignatures.push("zero-width-unicode");
  }

  // 正规化后再做模式匹配
  const normalized = normalizeCommand(command);

  // 逐类别检测
  for (const sig of ENCODED_PIPE_EXEC_SIGS) {
    if (sig.regex.test(normalized)) {
      if (!categories.includes("encoded-pipe-exec")) categories.push("encoded-pipe-exec");
      matchedSignatures.push(sig.id);
    }
  }

  for (const sig of REMOTE_FETCH_EXEC_SIGS) {
    if (sig.regex.test(normalized)) {
      if (!categories.includes("remote-fetch-exec")) categories.push("remote-fetch-exec");
      matchedSignatures.push(sig.id);
    }
  }

  for (const sig of INTERPRETER_ENCODED_SIGS) {
    if (sig.regex.test(normalized)) {
      if (!categories.includes("interpreter-encoded")) categories.push("interpreter-encoded");
      matchedSignatures.push(sig.id);
    }
  }

  for (const sig of CHAR_ESCAPE_SIGS) {
    if (sig.regex.test(normalized)) {
      if (!categories.includes("char-escape-exec")) categories.push("char-escape-exec");
      matchedSignatures.push(sig.id);
    }
  }

  for (const sig of VARIABLE_EXPANSION_SIGS) {
    if (sig.regex.test(normalized)) {
      if (!categories.includes("variable-expansion")) categories.push("variable-expansion");
      matchedSignatures.push(sig.id);
    }
  }

  return {
    isThreat: categories.length > 0,
    categories,
    matchedSignatures,
  };
}
