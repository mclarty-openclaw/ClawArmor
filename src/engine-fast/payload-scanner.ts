// ============================================================
// ClawArmor 编码载荷扫描器
// 职责：检测文本中隐藏于编码（base64/hex/base32/url）内的恶意载荷
// 独立原创实现，采用"解码管道 + 风险分析"模式
// ============================================================

import { createHash } from "node:crypto";

// ---- 配置常量 ----

const MAX_INPUT_CHARS = 10_000;
const MAX_TOKEN_CHARS = 2_048;
const MAX_TOKENS_PER_SCAN = 32;
const MAX_DECODE_DEPTH = 2;
const MAX_DECODED_BYTES = 4_096;

// ---- 编码类型 ----

export type EncodingKind = "base64" | "base64url" | "hex" | "base32" | "urlencode";

export type PayloadFinding = {
  encodingKind: EncodingKind;
  /** 原始 token 的摘要（sha256 前16字节）*/
  tokenDigest: string;
  /** 解码后文本的摘要 */
  decodedDigest: string;
  /** 解码后文本前 120 字符（供调试）*/
  decodedPreview: string;
  decodedLength: number;
  riskFlags: string[];
  /** 置信度：medium=1个risk flag，high=2+个 */
  confidence: "medium" | "high";
};

export type ScanResult = {
  findings: PayloadFinding[];
  /** 扫描是否因限制而降级（不完整）*/
  degraded: boolean;
  scannedChars: number;
};

// ---- 字符集谓词 ----

function isHex(ch: string): boolean {
  return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F");
}

function isBase64Std(ch: string): boolean {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") ||
         (ch >= "0" && ch <= "9") || ch === "+" || ch === "/" || ch === "=";
}

function isBase64Url(ch: string): boolean {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") ||
         (ch >= "0" && ch <= "9") || ch === "-" || ch === "_" || ch === "=";
}

const BASE32_CHARS = new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=");
function isBase32(ch: string): boolean {
  return BASE32_CHARS.has(ch.toUpperCase());
}

// ---- Token 提取 ----
// 从文本中分割出连续的编码候选串

const TOKEN_DELIMITERS = new Set(' \t\n\r"\'`()[]{},;:=<>');

function extractTokens(text: string): string[] {
  const tokens: string[] = [];
  const seen = new Set<string>();
  let current = "";

  const flush = () => {
    const t = current;
    current = "";
    if (t.length < 8 || t.length > MAX_TOKEN_CHARS) return;
    if (!seen.has(t)) {
      seen.add(t);
      tokens.push(t);
    }
  };

  for (const ch of text) {
    if (TOKEN_DELIMITERS.has(ch)) {
      flush();
    } else if (ch.charCodeAt(0) >= 0x21 && ch.charCodeAt(0) <= 0x7e) {
      current += ch;
      if (current.length > MAX_TOKEN_CHARS) flush();
    } else {
      flush();
    }
    if (tokens.length >= MAX_TOKENS_PER_SCAN) break;
  }
  flush();
  return tokens;
}

// ---- 编码类型推断 ----

function detectEncoding(token: string): EncodingKind | null {
  // URL 编码（%xx 模式）
  if (token.includes("%") && /(?:%[0-9A-Fa-f]{2}){2,}/.test(token)) return "urlencode";

  // Hex：长度偶数，全为16进制字符
  if (token.length >= 16 && token.length % 2 === 0 && [...token].every(isHex)) return "hex";

  // Base32：仅包含 A-Z2-7=，有数字
  if (token.length >= 16 && [...token].every(isBase32) && /[2-7]/.test(token)) return "base32";

  // Base64url：包含 - 或 _
  if (token.length >= 8 && [...token].every(isBase64Url) && /[-_]/.test(token)) return "base64url";

  // Base64：包含 + 或 / 或小写字母
  if (token.length >= 8 && [...token].every(isBase64Std) && (/[+/]/.test(token) || /[a-z]/.test(token))) return "base64";

  return null;
}

// ---- 各编码解码实现 ----

function decodeHex(token: string): string | null {
  if (token.length % 2 !== 0) return null;
  const bytes = Buffer.alloc(token.length / 2);
  for (let i = 0; i < token.length; i += 2) {
    const n = parseInt(token.slice(i, i + 2), 16);
    if (!Number.isFinite(n)) return null;
    bytes[i / 2] = n;
  }
  return bufferToText(bytes);
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function decodeBase32(token: string): string | null {
  const clean = token.toUpperCase().replace(/=/g, "");
  let bits = 0;
  let val = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) return null;
    val = (val << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((val >>> bits) & 0xff);
      if (bytes.length > MAX_DECODED_BYTES) return null;
    }
  }
  return bufferToText(Buffer.from(bytes));
}

function decodeBase64(token: string): string | null {
  const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (normalized.length % 4 || 4)) % 4;
  const padded = normalized + "=".repeat(pad);
  try {
    return bufferToText(Buffer.from(padded, "base64"));
  } catch {
    return null;
  }
}

function decodeUrl(token: string): string | null {
  try {
    return decodeURIComponent(token.replace(/\+/g, "%20")).replace(/\s+/g, " ").trim() || null;
  } catch {
    return null;
  }
}

function decode(token: string, kind: EncodingKind): string | null {
  switch (kind) {
    case "hex":       return decodeHex(token);
    case "base32":    return decodeBase32(token);
    case "base64":
    case "base64url": return decodeBase64(token);
    case "urlencode": return decodeUrl(token);
  }
}

/** 检查 Buffer 是否为有效的可打印 UTF-8 文本 */
function bufferToText(buf: Buffer): string | null {
  if (buf.length === 0 || buf.length > MAX_DECODED_BYTES) return null;
  const text = buf.toString("utf8");
  if (text.includes("\uFFFD")) return null;
  const printable = [...text].filter((ch) => {
    const c = ch.charCodeAt(0);
    return c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126);
  }).length;
  return printable / text.length >= 0.7 ? text.trim() : null;
}

// ---- 解码内容风险分析 ----
// 对解码后的文本做快速威胁扫描

const DECODED_RISK_SIGS = [
  { flag: "injection",     regex: /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?/i },
  { flag: "injection",     regex: /忽略(?:之前|前面|所有)的?(?:指令|规则)/ },
  { flag: "shell-danger",  regex: /\brm\s+-rf?\s+[/~]/ },
  { flag: "shell-danger",  regex: /(?:curl|wget)\s+https?:\/\/[^\s]+\s*\|\s*(?:sh|bash)/ },
  { flag: "secret-access", regex: /(?:api[_-]?key|password|token|secret)[=:]['"]?[^\s'"]{8,}/i },
  { flag: "exec-code",     regex: /\beval\s*\(|\bexec\s*\(|child_process\.exec/ },
  { flag: "remote-url",    regex: /https?:\/\/(?!(?:example\.com|localhost))[^\s]{8,}/ },
] as const;

function analyzeDecoded(text: string): string[] {
  return [...new Set(
    DECODED_RISK_SIGS.filter((s) => s.regex.test(text)).map((s) => s.flag)
  )];
}

function shortDigest(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

// ---- 递归解码分析 ----

type DecodeState = {
  depth: number;
  totalBytes: number;
  visitedTokens: Set<string>;
};

function analyzeTokenRecursive(
  token: string,
  kind: EncodingKind,
  rootToken: string,
  state: DecodeState,
): PayloadFinding | null {
  if (state.depth > MAX_DECODE_DEPTH || state.totalBytes >= MAX_DECODED_BYTES) return null;

  const visitKey = `${kind}:${token}`;
  if (state.visitedTokens.has(visitKey)) return null;
  state.visitedTokens.add(visitKey);

  const decoded = decode(token, kind);
  if (!decoded) return null;

  state.totalBytes += Buffer.byteLength(decoded, "utf8");
  const riskFlags = analyzeDecoded(decoded);

  if (riskFlags.length > 0) {
    return {
      encodingKind: kind,
      tokenDigest: shortDigest(rootToken),
      decodedDigest: shortDigest(decoded),
      decodedPreview: decoded.slice(0, 120),
      decodedLength: decoded.length,
      riskFlags,
      confidence: riskFlags.length >= 2 ? "high" : "medium",
    };
  }

  // 尝试递归解码（编码套编码场景）
  if (decoded.length < MAX_TOKEN_CHARS && decoded !== token) {
    const nestedKind = detectEncoding(decoded);
    if (nestedKind) {
      return analyzeTokenRecursive(decoded, nestedKind, rootToken, {
        ...state,
        depth: state.depth + 1,
      });
    }
  }

  return null;
}

// ---- 主扫描接口 ----

/**
 * 扫描文本，检测其中隐藏于编码载荷内的威胁
 */
export function scanForEncodedPayloads(text: string): ScanResult {
  if (!text) return { findings: [], degraded: false, scannedChars: 0 };

  let degraded = false;
  let scannedText = text;

  // 超长文本：取头尾各半
  if (text.length > MAX_INPUT_CHARS) {
    const half = Math.floor(MAX_INPUT_CHARS / 2);
    scannedText = text.slice(0, half) + text.slice(-half);
    degraded = true;
  }

  const tokens = extractTokens(scannedText);
  if (tokens.length >= MAX_TOKENS_PER_SCAN) degraded = true;

  const findings: PayloadFinding[] = [];

  for (const token of tokens) {
    const kind = detectEncoding(token);
    if (!kind) continue;

    const finding = analyzeTokenRecursive(token, kind, token, {
      depth: 1,
      totalBytes: 0,
      visitedTokens: new Set(),
    });

    if (finding) findings.push(finding);
  }

  return { findings, degraded, scannedChars: scannedText.length };
}

// ---- 密钥变体生成（用于输出脱敏）----

const B32_ENCODE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function encodeBase32(buf: Buffer): string {
  let bits = 0;
  let val = 0;
  let out = "";
  for (const byte of buf) {
    val = (val << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ENCODE[(val >>> bits) & 0x1f];
    }
  }
  if (bits > 0) out += B32_ENCODE[(val << (5 - bits)) & 0x1f];
  return out;
}

/**
 * 为已知密钥生成各种编码变体（用于后续输出中的批量脱敏）
 */
export function buildSecretVariants(secret: string): string[] {
  const s = secret.trim();
  if (s.length < 8 || s.length > 256) return [];
  const buf = Buffer.from(s, "utf8");
  const variants = new Set<string>([
    s,
    buf.toString("base64"),
    buf.toString("base64url"),
    buf.toString("hex"),
    encodeBase32(buf),
    encodeURIComponent(s),
  ]);
  return [...variants].sort((a, b) => b.length - a.length);
}

/**
 * 将文本中所有已知密钥变体替换为脱敏占位符
 */
export function redactSecretVariants(
  text: string,
  secrets: string[],
  placeholder: string,
): { text: string; count: number } {
  if (!text || secrets.length === 0) return { text, count: 0 };

  let result = text;
  let count = 0;

  for (const secret of secrets.slice(0, 16)) {
    for (const variant of buildSecretVariants(secret)) {
      if (variant.length < 8 || !result.includes(variant)) continue;
      const occurrences = result.split(variant).length - 1;
      if (occurrences > 0) {
        result = result.split(variant).join(placeholder);
        count += occurrences;
      }
    }
  }

  return { text: result, count };
}
