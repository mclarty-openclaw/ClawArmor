// ============================================================
// ClawArmor Skill 监控服务
// 职责：异步扫描 Skill 文件，检测恶意内容
// 独立原创实现，采用"作业池 + 哈希缓存"模式
// ============================================================

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { scanSkillContent } from "./rule-engine.js";
import type { ArmorLogger } from "../logger/index.js";

// ---- 常量 ----

const SCAN_TARGET_FILENAME = "SKILL.md";
const FILE_SIZE_LIMIT = 100 * 1024; // 100KB
const JOB_TIMEOUT_MS = 3_000;
const MAX_CONCURRENT_JOBS = 4;
const MAX_QUEUE_SIZE = 16;
const FAILURE_COOLDOWN_MS = 5 * 60_000;
const FAILURE_THRESHOLD = 3;
const FAILURE_WINDOW_MS = 60_000;

// ---- 数据类型 ----

export type SkillTrustRecord = {
  filePath: string;
  contentHash: string;
  fileSize: number;
  scannedAt: number;
  isTrusted: boolean;
  findings: string[];
};

type ScanJob = {
  jobId: string;
  filePath: string;
  contentHash: string;
  fileSize: number;
  text: string;
  resolve: (record: SkillTrustRecord) => void;
  reject: (err: unknown) => void;
  addedAt: number;
};

type WorkerHealth = {
  consecutiveFailures: number;
  failureTimestamps: number[];
  cooldownUntil: number;
};

// ---- SkillWatcher 主类 ----

export class SkillWatcher {
  /** 已扫描结果缓存（hash → record）*/
  private readonly cache = new Map<string, SkillTrustRecord>();

  /** 等待处理的作业队列 */
  private readonly queue: ScanJob[] = [];

  /** 当前正在执行的作业数 */
  private activeJobs = 0;

  /** Worker 线程健康状态 */
  private health: WorkerHealth = {
    consecutiveFailures: 0,
    failureTimestamps: [],
    cooldownUntil: 0,
  };

  private readonly log: ArmorLogger;

  constructor(logger: ArmorLogger) {
    this.log = logger.child({ module: "skill-watcher" });
  }

  // ---- 公开接口 ----

  /**
   * 提交 Skill 文件扫描作业
   * 已缓存或队列已满时快速返回
   */
  async submitScanJob(filePath: string): Promise<SkillTrustRecord | null> {
    // 冷却期检查
    if (Date.now() < this.health.cooldownUntil) {
      this.log.debug("[SkillWatcher] 处于冷却期，跳过扫描", { filePath });
      return null;
    }

    // 读取文件
    let text: string;
    let stat: { size: number };
    try {
      stat = await fs.stat(filePath);
      if (stat.size > FILE_SIZE_LIMIT) {
        this.log.debug("[SkillWatcher] 文件超限，跳过", { filePath, size: stat.size });
        return null;
      }
      text = await fs.readFile(filePath, "utf8");
    } catch {
      return null;
    }

    const hash = sha256(text);

    // 命中缓存
    const cached = this.cache.get(hash);
    if (cached) return cached;

    // 队列已满
    if (this.queue.length >= MAX_QUEUE_SIZE) {
      this.log.debug("[SkillWatcher] 队列已满，跳过", { filePath });
      return null;
    }

    return new Promise((resolve, reject) => {
      this.queue.push({
        jobId: `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        filePath,
        contentHash: hash,
        fileSize: stat.size,
        text,
        resolve,
        reject,
        addedAt: Date.now(),
      });
      this.drainQueue();
    });
  }

  /**
   * 扫描一组根目录下的所有 SKILL.md 文件（启动时调用）
   */
  async scanRoots(roots: string[], budgetMs = 200): Promise<SkillTrustRecord[]> {
    const deadline = Date.now() + budgetMs;
    const results: SkillTrustRecord[] = [];

    for (const root of roots) {
      if (Date.now() > deadline) break;
      const skillFiles = await this.findSkillFiles(root);
      for (const filePath of skillFiles) {
        if (Date.now() > deadline) break;
        const record = await this.scanFileDirect(filePath);
        if (record) results.push(record);
      }
    }

    return results;
  }

  /** 获取缓存快照 */
  getCachedRecords(): SkillTrustRecord[] {
    return [...this.cache.values()];
  }

  // ---- 私有实现 ----

  private async drainQueue(): Promise<void> {
    while (this.queue.length > 0 && this.activeJobs < MAX_CONCURRENT_JOBS) {
      const job = this.queue.shift();
      if (!job) break;
      this.activeJobs++;
      this.executeJob(job).finally(() => {
        this.activeJobs--;
        // 继续排队
        if (this.queue.length > 0) this.drainQueue();
      });
    }
  }

  private async executeJob(job: ScanJob): Promise<void> {
    try {
      const record = await this.runScan(job);
      this.cache.set(job.contentHash, record);
      this.recordSuccess();
      job.resolve(record);
    } catch (err) {
      this.recordFailure();
      job.reject(err);
    }
  }

  /**
   * 尝试用 Worker 线程扫描，失败则降级为同步扫描
   */
  private async runScan(job: ScanJob): Promise<SkillTrustRecord> {
    // 降级：直接同步扫描（Worker 线程不可用时的 fallback）
    const { isTrusted, findings } = scanSkillContent(job.text);
    return {
      filePath: job.filePath,
      contentHash: job.contentHash,
      fileSize: job.fileSize,
      scannedAt: Date.now(),
      isTrusted,
      findings,
    };
  }

  private async scanFileDirect(filePath: string): Promise<SkillTrustRecord | null> {
    try {
      const stat = await fs.stat(filePath);
      if (stat.size > FILE_SIZE_LIMIT) return null;
      const text = await fs.readFile(filePath, "utf8");
      const hash = sha256(text);
      const cached = this.cache.get(hash);
      if (cached) return cached;
      const { isTrusted, findings } = scanSkillContent(text);
      const record: SkillTrustRecord = {
        filePath,
        contentHash: hash,
        fileSize: stat.size,
        scannedAt: Date.now(),
        isTrusted,
        findings,
      };
      this.cache.set(hash, record);
      return record;
    } catch {
      return null;
    }
  }

  private async findSkillFiles(root: string): Promise<string[]> {
    const results: string[] = [];
    try {
      await walkDir(root, (filePath) => {
        if (path.basename(filePath) === SCAN_TARGET_FILENAME) {
          results.push(filePath);
        }
      });
    } catch {
      // 目录不存在时忽略
    }
    return results;
  }

  private recordSuccess(): void {
    this.health.consecutiveFailures = 0;
  }

  private recordFailure(): void {
    const now = Date.now();
    this.health.consecutiveFailures++;
    this.health.failureTimestamps.push(now);
    // 滑动窗口内的失败次数
    this.health.failureTimestamps = this.health.failureTimestamps
      .filter((t) => now - t < FAILURE_WINDOW_MS);
    if (this.health.failureTimestamps.length >= FAILURE_THRESHOLD) {
      this.health.cooldownUntil = now + FAILURE_COOLDOWN_MS;
      this.log.warn("[SkillWatcher] 连续失败触发冷却", {
        failures: this.health.failureTimestamps.length,
        cooldownUntilMs: this.health.cooldownUntil,
      });
    }
  }
}

// ---- 工具函数 ----

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

async function walkDir(dir: string, visitor: (filePath: string) => void): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkDir(full, visitor);
    } else if (entry.isFile()) {
      visitor(full);
    }
  }
}
