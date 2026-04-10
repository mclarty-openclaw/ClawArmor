// ============================================================
// 模型路由网关
// 根据配置动态选择 Ollama（本地）或 OpenAI 兼容（云端）适配器
// ============================================================

import type { ClawArmorSlowEngineConfig } from "../../types/index.js";
import type { IVerifierModel } from "../../types/index.js";
import { OllamaAdapter } from "./ollama.js";
import { OpenAICompatAdapter } from "./openai-compat.js";

/** 最小日志接口，兼容 ArmorLogger，不引入循环依赖 */
type SlowPathLogger = {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
};

/** 截断长字符串并附加长度信息，用于日志可读性 */
function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen)}…[共 ${text.length} 字符]`;
}

export class ModelGateway {
  private adapter: IVerifierModel | null = null;
  private config: ClawArmorSlowEngineConfig;
  private logger: SlowPathLogger | null;

  constructor(config: ClawArmorSlowEngineConfig, logger?: SlowPathLogger) {
    this.config = config;
    this.logger = logger ?? null;
    this.adapter = this.buildAdapter(config);
  }

  private buildAdapter(config: ClawArmorSlowEngineConfig): IVerifierModel | null {
    if (!config.enabled || config.mode === "disabled") return null;
    if (config.mode === "ollama") {
      return new OllamaAdapter(config.ollamaBaseUrl, config.ollamaModel, config.timeoutMs);
    }
    if (config.mode === "openai-compat") {
      return new OpenAICompatAdapter(
        config.openaiCompatBaseUrl,
        config.openaiCompatModel,
        config.openaiCompatApiKey,
        config.timeoutMs,
      );
    }
    return null;
  }

  isEnabled(): boolean {
    return this.adapter !== null;
  }

  async isAvailable(): Promise<boolean> {
    if (!this.adapter) return false;
    return this.adapter.isAvailable();
  }

  getAdapter(): IVerifierModel | null {
    return this.adapter;
  }

  /**
   * 执行旁路验证请求，失败时 fail-open（不阻断）
   * @param label 调用方标识（如 "intent-alignment"），用于日志区分
   */
  async safeVerify(
    systemPrompt: string,
    userContent: string,
    maxTokens = 256,
    label = "unknown",
  ): Promise<{ content: string; latencyMs: number } | null> {
    if (!this.adapter) return null;

    const provider = this.config.mode;
    const modelName = this.config.mode === "ollama"
      ? this.config.ollamaModel
      : this.config.openaiCompatModel;

    // ---- 调用前日志：记录提交给模型的完整上下文 ----
    this.logger?.info("[ClawArmor][SlowPath] 模型调用开始", {
      checker: label,
      provider,
      model: modelName,
      maxTokens,
      systemPromptLength: systemPrompt.length,
      systemPrompt: truncate(systemPrompt, 300),
      userContentLength: userContent.length,
      userContent: truncate(userContent, 800),
    });

    try {
      const result = await this.adapter.verify({ systemPrompt, userContent, maxTokens });

      // ---- 调用后日志：记录模型返回的完整内容 ----
      this.logger?.info("[ClawArmor][SlowPath] 模型响应完成", {
        checker: label,
        provider,
        model: result.model || modelName,
        latencyMs: result.latencyMs,
        responseLength: result.content.length,
        response: truncate(result.content, 1000),
      });

      return { content: result.content, latencyMs: result.latencyMs };
    } catch (err: unknown) {
      // ---- 错误日志：记录失败原因，fail-open 不阻断主流程 ----
      this.logger?.warn("[ClawArmor][SlowPath] 模型调用失败，fail-open", {
        checker: label,
        provider,
        model: modelName,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }
}

export { OllamaAdapter } from "./ollama.js";
export { OpenAICompatAdapter } from "./openai-compat.js";
