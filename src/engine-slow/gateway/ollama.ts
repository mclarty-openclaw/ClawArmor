// ============================================================
// Ollama 本地模型适配器
// 适用于高机密业务场景，数据完全本地化，不出域
// ============================================================

import type { IVerifierModel, ModelGatewayRequest, ModelGatewayResponse } from "../../types/index.js";

type OllamaChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

type OllamaChatResponse = {
  message: {
    content: string;
  };
  model: string;
  done: boolean;
};

export class OllamaAdapter implements IVerifierModel {
  private readonly apiBase: string;
  private readonly modelName: string;

  constructor(
    baseUrl: string,
    model: string,
    private readonly timeoutMs: number = 10_000,
  ) {
    // 规范化 baseUrl：移除 /v1 后缀，确保指向 Ollama 原生 API 根路径
    this.apiBase = baseUrl.replace(/\/v1\/?$/, "").replace(/\/$/, "");
    // 规范化 model name：移除 ollama/ 前缀（Ollama 原生 API 只需 model 短名）
    this.modelName = model.replace(/^ollama\//, "");
  }

  async isAvailable(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3_000);
      const response = await fetch(`${this.apiBase}/api/tags`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      return response.ok;
    } catch {
      return false;
    }
  }

  async verify(request: ModelGatewayRequest): Promise<ModelGatewayResponse> {
    const messages: OllamaChatMessage[] = [
      { role: "system", content: request.systemPrompt },
      { role: "user", content: request.userContent },
    ];

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    const startedAt = Date.now();

    try {
      const response = await fetch(`${this.apiBase}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: this.modelName,
          messages,
          stream: false,
          options: {
            num_predict: request.maxTokens ?? 256,
            temperature: 0,
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`Ollama API 返回错误状态：${response.status}`);
      }

      const data = (await response.json()) as OllamaChatResponse;
      return {
        content: data.message.content.trim(),
        model: data.model,
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      clearTimeout(timer);
      throw error;
    }
  }
}
