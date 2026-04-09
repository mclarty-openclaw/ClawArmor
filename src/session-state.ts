// ============================================================
// ClawArmor 会话安全状态管理器
// 独立原创实现，采用"分域存储 + TTL 自动淘汰"模式
// ============================================================

import { promises as fs } from "node:fs";
import path from "node:path";
import type { ArmorLogger } from "./logger/index.js";

// ============================================================
// 状态记录类型
// ============================================================

/** 单个回合的安全信号汇总 */
export type TurnSignals = {
  injectionFlags: string[];
  secretLeakFlags: string[];
  toolResultFlags: string[];
  skillRiskFlags: string[];
  runtimeFlags: string[];
  hasExternalToolResult: boolean;
  isToolResultSuspicious: boolean;
  isToolResultOversize: boolean;
  needsPromptPrepend: boolean;
  updatedAt: number;
};

/** 单次 run 的安全信号累积 */
export type RunSignals = {
  sessionKey?: string;
  sourceSignals: string[];
  transformSignals: string[];
  sinkSignals: string[];
  riskFlags: string[];
  updatedAt: number;
};

/** 已观测到的密钥记录（用于输出脱敏） */
type ObservedSecret = {
  values: string[];
  updatedAt: number;
};

/** 受信任 Skill 持久化格式 */
type TrustedSkillEntry = {
  filePath: string;
  contentHash: string;
  fileSize: number;
  scannedAt: number;
};

type PersistFile = {
  schemaVersion: 1;
  entries: TrustedSkillEntry[];
};

// ============================================================
// TTL 常量
// ============================================================

const TURN_TTL_MS = 5 * 60_000;
const RUN_TTL_MS = 5 * 60_000;
const SECRET_TTL_MS = 5 * 60_000;

// ============================================================
// SessionStateManager
// ============================================================

export class SessionStateManager {
  /** key = sessionKey */
  private readonly turnMap = new Map<string, TurnSignals>();
  /** key = runId */
  private readonly runMap = new Map<string, RunSignals>();
  /** key = sessionKey → observed secrets */
  private readonly secretMap = new Map<string, ObservedSecret>();
  /** key = filePath → hash（用于 loop 计数和脚本溯源） */
  private readonly loopCounters = new Map<string, number>();
  /** key = contentHash → TrustedSkillEntry（持久化） */
  private readonly trustedSkills = new Map<string, TrustedSkillEntry>();

  private readonly trustedSkillsPath: string;

  private readonly log: ArmorLogger;

  constructor(
    stateDir: string,
    logger: ArmorLogger,
    private readonly clock: () => number = Date.now,
  ) {
    this.log = logger.child({ module: "session-state" });
    this.trustedSkillsPath = path.join(stateDir, "trusted-skills.json");
  }

  // ============================================================
  // 初始化（持久化数据加载）
  // ============================================================

  async initialize(): Promise<void> {
    try {
      const raw = await fs.readFile(this.trustedSkillsPath, "utf8");
      const data = JSON.parse(raw) as PersistFile;
      if (data.schemaVersion === 1 && Array.isArray(data.entries)) {
        for (const entry of data.entries) {
          if (this.isValidEntry(entry)) {
            this.trustedSkills.set(entry.contentHash, entry);
          }
        }
      }
    } catch {
      // 文件不存在或格式错误，从空状态开始
    }
  }

  async persistTrustedSkills(): Promise<void> {
    const data: PersistFile = {
      schemaVersion: 1,
      entries: [...this.trustedSkills.values()].sort((a, b) => a.filePath.localeCompare(b.filePath)),
    };
    await atomicWrite(this.trustedSkillsPath, JSON.stringify(data, null, 2));
  }

  // ============================================================
  // 回合信号管理
  // ============================================================

  /** 追加注入/安全扫描标记到当前回合 */
  appendTurnFlags(sessionKey: string, updates: Partial<Omit<TurnSignals, "updatedAt">>): TurnSignals {
    const now = this.clock();
    this.evictExpiredTurnStates(now);
    const current = this.turnMap.get(sessionKey) ?? createEmptyTurnSignals(now);

    if (updates.injectionFlags) current.injectionFlags = dedup([...current.injectionFlags, ...updates.injectionFlags]);
    if (updates.secretLeakFlags) current.secretLeakFlags = dedup([...current.secretLeakFlags, ...updates.secretLeakFlags]);
    if (updates.toolResultFlags) current.toolResultFlags = dedup([...current.toolResultFlags, ...updates.toolResultFlags]);
    if (updates.skillRiskFlags) current.skillRiskFlags = dedup([...current.skillRiskFlags, ...updates.skillRiskFlags]);
    if (updates.runtimeFlags) current.runtimeFlags = dedup([...current.runtimeFlags, ...updates.runtimeFlags]);
    if (updates.hasExternalToolResult) current.hasExternalToolResult = true;
    if (updates.isToolResultSuspicious) current.isToolResultSuspicious = true;
    if (updates.isToolResultOversize) current.isToolResultOversize = true;

    current.needsPromptPrepend =
      current.injectionFlags.length > 0 ||
      current.hasExternalToolResult ||
      current.skillRiskFlags.length > 0 ||
      current.runtimeFlags.length > 0;

    current.updatedAt = now;
    this.turnMap.set(sessionKey, current);
    return { ...current };
  }

  /** 读取当前回合信号（不消耗） */
  peekTurnSignals(sessionKey: string): TurnSignals | undefined {
    this.evictExpiredTurnStates(this.clock());
    return this.turnMap.get(sessionKey);
  }

  /** 消耗当前回合信号（用于 before_prompt_build）*/
  consumeTurnSignals(sessionKey: string): TurnSignals | undefined {
    const signals = this.turnMap.get(sessionKey);
    this.turnMap.delete(sessionKey);
    return signals;
  }

  // ============================================================
  // Run 信号管理（外泄链追踪）
  // ============================================================

  appendRunSignals(runId: string, updates: {
    sessionKey?: string;
    sourceSignals?: string[];
    transformSignals?: string[];
    sinkSignals?: string[];
    riskFlags?: string[];
  }): RunSignals {
    const now = this.clock();
    this.evictExpiredRunStates(now);
    const current = this.runMap.get(runId) ?? createEmptyRunSignals(updates.sessionKey, now);

    if (updates.sessionKey && !current.sessionKey) current.sessionKey = updates.sessionKey;
    if (updates.sourceSignals) current.sourceSignals = dedup([...current.sourceSignals, ...updates.sourceSignals]);
    if (updates.transformSignals) current.transformSignals = dedup([...current.transformSignals, ...updates.transformSignals]);
    if (updates.sinkSignals) current.sinkSignals = dedup([...current.sinkSignals, ...updates.sinkSignals]);
    if (updates.riskFlags) current.riskFlags = dedup([...current.riskFlags, ...updates.riskFlags]);
    current.updatedAt = now;

    this.runMap.set(runId, current);
    return { ...current };
  }

  peekRunSignals(runId: string): RunSignals | undefined {
    this.evictExpiredRunStates(this.clock());
    return this.runMap.get(runId);
  }

  // ============================================================
  // 密钥观测记录（用于输出脱敏）
  // ============================================================

  recordObservedSecrets(sessionKey: string, values: string[]): string[] {
    const now = this.clock();
    const normalized = dedup(values.map((v) => v.trim()).filter((v) => v.length >= 8))
      .sort((a, b) => b.length - a.length);

    if (normalized.length === 0) return this.getObservedSecrets(sessionKey);

    const existing = this.secretMap.get(sessionKey);
    const merged = dedup([...(existing?.values ?? []), ...normalized])
      .sort((a, b) => b.length - a.length);

    this.secretMap.set(sessionKey, { values: merged, updatedAt: now });
    return [...merged];
  }

  getObservedSecrets(sessionKey: string): string[] {
    return [...(this.secretMap.get(sessionKey)?.values ?? [])];
  }

  // ============================================================
  // 循环计数器（loop guard）
  // ============================================================

  incrementLoopCounter(runId: string, toolName: string): number {
    const key = `${runId}:${toolName}`;
    const next = (this.loopCounters.get(key) ?? 0) + 1;
    this.loopCounters.set(key, next);
    return next;
  }

  getLoopCount(runId: string, toolName: string): number {
    return this.loopCounters.get(`${runId}:${toolName}`) ?? 0;
  }

  // ============================================================
  // Skill 信任管理
  // ============================================================

  isTrustedSkill(contentHash: string): boolean {
    return this.trustedSkills.has(contentHash);
  }

  recordTrustedSkill(entry: TrustedSkillEntry): void {
    this.trustedSkills.set(entry.contentHash, entry);
  }

  // ============================================================
  // 会话/Run 清理
  // ============================================================

  clearSession(sessionKey: string): void {
    this.turnMap.delete(sessionKey);
    this.secretMap.delete(sessionKey);
    // 清除该 session 关联的 run 数据
    for (const [runId, signals] of this.runMap) {
      if (signals.sessionKey === sessionKey) this.runMap.delete(runId);
    }
    // 清除 loop 计数
    for (const key of this.loopCounters.keys()) {
      if (key.startsWith(`${sessionKey}:`)) this.loopCounters.delete(key);
    }
  }

  clearRun(runId: string): void {
    this.runMap.delete(runId);
    for (const key of this.loopCounters.keys()) {
      if (key.startsWith(`${runId}:`)) this.loopCounters.delete(key);
    }
  }

  // ============================================================
  // 私有工具
  // ============================================================

  private evictExpiredTurnStates(now: number): void {
    for (const [key, state] of this.turnMap) {
      if (now - state.updatedAt > TURN_TTL_MS) this.turnMap.delete(key);
    }
  }

  private evictExpiredRunStates(now: number): void {
    for (const [key, state] of this.runMap) {
      if (now - state.updatedAt > RUN_TTL_MS) this.runMap.delete(key);
    }
  }

  private isValidEntry(entry: unknown): entry is TrustedSkillEntry {
    return (
      typeof entry === "object" &&
      entry !== null &&
      typeof (entry as TrustedSkillEntry).filePath === "string" &&
      typeof (entry as TrustedSkillEntry).contentHash === "string" &&
      typeof (entry as TrustedSkillEntry).fileSize === "number" &&
      typeof (entry as TrustedSkillEntry).scannedAt === "number"
    );
  }
}

// ============================================================
// 工具函数
// ============================================================

function dedup(arr: string[]): string[] {
  return [...new Set(arr.filter((v) => v.trim().length > 0))];
}

function createEmptyTurnSignals(now: number): TurnSignals {
  return {
    injectionFlags: [],
    secretLeakFlags: [],
    toolResultFlags: [],
    skillRiskFlags: [],
    runtimeFlags: [],
    hasExternalToolResult: false,
    isToolResultSuspicious: false,
    isToolResultOversize: false,
    needsPromptPrepend: false,
    updatedAt: now,
  };
}

function createEmptyRunSignals(sessionKey: string | undefined, now: number): RunSignals {
  return {
    sessionKey,
    sourceSignals: [],
    transformSignals: [],
    sinkSignals: [],
    riskFlags: [],
    updatedAt: now,
  };
}

async function atomicWrite(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tmp, content, "utf8");
    await fs.rename(tmp, filePath);
  } finally {
    await fs.rm(tmp, { force: true }).catch(() => undefined);
  }
}
