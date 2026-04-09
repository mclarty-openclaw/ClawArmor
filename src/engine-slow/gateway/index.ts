// ============================================================
// 模型路由网关
// 根据配置动态选择 Ollama（本地）或 OpenAI 兼容（云端）适配器
// ============================================================

import type { ClawArmorSlowEngineConfig } from "../../types/index.js";
import type { IVerifierModel } from "../../types/index.js";
import { OllamaAdapter } from "./ollama.js";
import { OpenAICompatAdapter } from "./openai-compat.js";

export class ModelGateway {
  private adapter: IVerifierModel | null = null;
  private config: ClawArmorSlowEngineConfig;

  constructor(config: ClawArmorSlowEngineConfig) {
    this.config = config;
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
   */
  async safeVerify(
    systemPrompt: string,
    userContent: string,
    maxTokens = 256,
  ): Promise<{ content: string; latencyMs: number } | null> {
    if (!this.adapter) return null;
    try {
      const result = await this.adapter.verify({ systemPrompt, userContent, maxTokens });
      return { content: result.content, latencyMs: result.latencyMs };
    } catch {
      // Slow Path 失败时 fail-open，不影响主流程
      return null;
    }
  }
}

export { OllamaAdapter } from "./ollama.js";
export { OpenAICompatAdapter } from "./openai-compat.js";
