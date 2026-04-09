// ============================================================
// OpenAI 兼容协议适配器
// 支持 DeepSeek、Kimi、OpenAI 等任意 OpenAI 兼容接口
// ============================================================

import type { IVerifierModel, ModelGatewayRequest, ModelGatewayResponse } from "../../types/index.js";

type ChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

type OpenAICompatResponse = {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
  model: string;
};

export class OpenAICompatAdapter implements IVerifierModel {
  constructor(
    private readonly baseUrl: string,
    private readonly model: string,
    private readonly apiKey: string,
    private readonly timeoutMs: number = 10_000,
  ) {}

  async isAvailable(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3_000);
      const response = await fetch(`${this.baseUrl}/models`, {
        headers: { Authorization: `Bearer ${this.apiKey}` },
        signal: controller.signal,
      });
      clearTimeout(timer);
      return response.ok;
    } catch {
      return false;
    }
  }

  async verify(request: ModelGatewayRequest): Promise<ModelGatewayResponse> {
    const messages: ChatMessage[] = [
      { role: "system", content: request.systemPrompt },
      { role: "user", content: request.userContent },
    ];

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    const startedAt = Date.now();

    try {
      const response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.model,
          messages,
          max_tokens: request.maxTokens ?? 256,
          temperature: 0,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`OpenAI 兼容 API 返回错误状态：${response.status}`);
      }

      const data = (await response.json()) as OpenAICompatResponse;
      const content = data.choices[0]?.message.content.trim() ?? "";
      return {
        content,
        model: data.model,
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      clearTimeout(timer);
      throw error;
    }
  }
}
