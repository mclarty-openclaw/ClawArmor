// ============================================================
// OpenClaw Plugin Runtime API 类型声明
// 这是插件与 OpenClaw 框架之间的接口契约
// 实际运行时由 OpenClaw 框架注入，此文件仅用于 TypeScript 类型推导
// ============================================================

export type OpenClawPluginConfigSchema = {
  jsonSchema: Record<string, unknown>;
  uiHints?: Record<string, unknown>;
};

export type AegisLogger = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
};

export type OpenClawPluginApi = {
  /** 插件配置（来自 clawarmor.json 或 openclaw.json 中的 pluginConfig 字段）*/
  pluginConfig?: unknown;
  /** 路径解析工具（将相对路径解析为绝对路径）*/
  resolvePath: (input: string) => string;
  /** 日志记录器 */
  logger: AegisLogger;
  /** 运行时状态接口 */
  runtime: {
    state: {
      resolveStateDir: () => string;
    };
  };
  /** 注册生命周期钩子 */
  on: (event: string, handler: (event: unknown) => unknown) => void;
};

// ---- 生命周期事件类型 ----

export type PluginHookAgentStartEvent = {
  sessionKey: string;
  runId: string;
  messages?: Array<{ role: string; content: unknown }>;
};

export type PluginHookBeforeToolCallEvent = {
  sessionKey: string;
  runId: string;
  toolName: string;
  params?: unknown;
};

export type PluginHookBeforeToolCallResult = {
  block: boolean;
  reason?: string;
};

export type PluginHookAfterToolCallEvent = {
  sessionKey: string;
  runId: string;
  toolName: string;
  result: unknown;
};

export type PluginHookBeforePromptBuildEvent = {
  sessionKey: string;
  runId: string;
  [key: string]: unknown;
};

export type PluginHookBeforePromptBuildResult = {
  block: boolean;
  reason?: string;
  prependSystem?: string;
};

export type PluginHookBeforeMessageWriteEvent = {
  sessionKey: string;
  role: string;
  content: string;
};

export type PluginHookMessageSendingEvent = {
  sessionKey: string;
  runId: string;
};

export type PluginHookMessageSendingResult = {
  block: boolean;
  reason?: string;
};

export type PluginHookSessionEndEvent = {
  sessionKey: string;
};

export type PluginHookAgentEndEvent = {
  sessionKey: string;
  runId: string;
};
