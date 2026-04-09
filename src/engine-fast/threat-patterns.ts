// ============================================================
// ClawArmor 威胁模式库
// 按攻击面分类组织，独立原创实现
// ============================================================

// ---- 通用模式单元 ----

export type ThreatPattern = {
  id: string;
  regex: RegExp;
  // 是否只在"非安全示例"上下文中触发
  requiresUnsafeContext?: boolean;
};

export type ThreatCategory = {
  id: string;
  patterns: readonly ThreatPattern[];
};

// ============================================================
// 1. 提示词注入模式
// 覆盖直接注入（用户输入）与间接注入（工具返回结果）
// ============================================================

export const INJECTION_PATTERNS: readonly ThreatPattern[] = [
  // 英文越狱指令
  { id: "ignore-prev-en",   regex: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?/i },
  { id: "disregard-en",     regex: /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|guidelines?)/i },
  { id: "new-identity",     regex: /you\s+are\s+now\s+(?:a|an)\s+(?!helpful|an?\s+AI)[a-z\s]{3,40}(?:with\s+no\s+restrictions?|without\s+(?:any\s+)?restrictions?|that\s+(?:can|will)\s+do\s+anything)/i },
  { id: "jailbreak-dan",    regex: /\bDAN\b.*(?:do\s+anything\s+now|without\s+restrictions?)/i },
  { id: "override-rules",   regex: /override\s+(?:your\s+)?(?:rules?|guidelines?|safety|restrictions?|programming)/i },
  { id: "pretend-no-rules", regex: /pretend\s+(?:you\s+have\s+)?no\s+(?:rules?|restrictions?|guidelines?|limitations?)/i },
  { id: "act-as-unfilter",  regex: /act\s+as\s+(?:if\s+you\s+(?:were\s+|are\s+))?(?:an?\s+)?(?:uncensored|unfiltered|unrestricted)\b/i },
  { id: "forget-instruct",  regex: /forget\s+(?:all\s+)?(?:previous\s+)?instructions?\s+(?:and|,)\s+(?:instead|now)/i },
  // 中文越狱指令
  { id: "ignore-cn",        regex: /忽略.{0,5}(?:之前|前面|上面|所有).{0,10}(?:指令|规则|限制|要求|约束)/ },
  { id: "override-cn",      regex: /覆盖(?:system\s*)?(?:prompt|提示词|系统|规则)/ },
  { id: "new-role-cn",      regex: /你(?:现在|从现在起)?(?:是|扮演|变成|成为)(?!一个有帮助).{1,30}(?:没有(?:任何)?限制|不受限制|可以做任何)/ },
  { id: "bypass-cn",        regex: /绕过(?:安全|限制|审查|过滤|规则)/ },
  // 角色注入
  { id: "role-inject",      regex: /\[(?:system|developer|assistant|user)\].*(?:you\s+are|your\s+new\s+role)/i },
  // 特殊 token 伪造
  { id: "special-token",    regex: /<\|(?:im_start|im_end|endoftext|eot_id|start_header_id|end_header_id)\|>/i },
  { id: "tool-boundary",    regex: /<\/?\s*tool_response\s*>/i },
  // 外部数据中的越权指令
  { id: "external-override",regex: /(?:as\s+(?:an?\s+)?(?:ai|assistant|system)|your\s+(?:new\s+)?instructions?\s+are)[:\s]+/i },
];

// ============================================================
// 2. 凭证与密钥外泄检测模式
// ============================================================

export const SECRET_LEAK_PATTERNS: readonly ThreatPattern[] = [
  // API Key 提取请求
  { id: "extract-apikey",   regex: /(?:print|show|output|send|share|reveal|display|return|get|fetch|read|tell\s+me)\s+(?:the\s+|your\s+|all\s+)?(?:api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|credentials?|auth(?:orization)?\s*token)/i },
  { id: "extract-apikey-cn",regex: /(?:输出|打印|显示|发送|分享|读取|获取|提供)\s*(?:api\s*key|密钥|秘钥|token|凭证|认证|授权)/ },
  // 环境变量提取
  { id: "env-extract",      regex: /(?:print|cat|echo|read)\s+(?:all\s+)?(?:env(?:ironment)?\s+(?:variable)?|process\.env|\$\{?[A-Z_]{4,}\}?)/ },
  { id: "env-list-cmd",     regex: /\benv\b|\bprintenv\b|\bset\b.*\bexport\b/ },
  // 已知密钥格式（存在于输出中，可能是外泄尝试）
  { id: "openai-key",       regex: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { id: "github-pat",       regex: /\bghp_[A-Za-z0-9]{36}\b/ },
  { id: "aws-access-key",   regex: /\bAKIA[A-Z0-9]{16}\b/ },
  { id: "generic-bearer",   regex: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}/ },
  { id: "generic-secret",   regex: /(?:secret|password|passwd|private[_-]?key)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?/i },
];

// ============================================================
// 3. 危险 Shell 命令模式
// ============================================================

export const DANGEROUS_COMMAND_PATTERNS: readonly ThreatPattern[] = [
  // 递归删除类
  // 递归删除（必须含 r 标志；仅 -f 不含 r 的不拦截）
  { id: "rm-rf-general",       regex: /\brm\s+-[^\s]*r[^\s]*\s/ },
  { id: "rm-recursive-root",   regex: /\brm\s+(?:-\S*[rRfF]\S*\s+){0,3}[/~](?:\s|$)/ },
  { id: "rm-recursive-star",   regex: /\brm\s+(?:-\S*[rRfF]\S*\s+){1,3}\*/ },
  { id: "rm-rf-home",          regex: /\brm\s+-rf?\s+~\b/ },
  // 危险重定向
  { id: "overwrite-sys",       regex: />\s*(?:\/dev\/(?:s?da|nvme\d)|\/etc\/(?:passwd|shadow|sudoers))/ },
  // 无限循环炸弹
  { id: "fork-bomb",           regex: /:\s*\(\s*\)\s*\{\s*:[^}]*\|\s*:\s*&\s*\}/ },
  // 强制关机/重启
  { id: "poweroff",            regex: /\b(?:poweroff|shutdown\s+-[hH]|halt\s+-f|reboot\s+-f)\b/ },
  // curl/wget 管道执行（Fast Path 侧，Slow Path 做语义深度分析）
  { id: "remote-pipe-exec",    regex: /(?:curl|wget)\s+[^\|]+\|\s*(?:su?do\s+)?(?:sh|bash|zsh|ash|dash)\b/ },
  // OpenClaw 自身控制命令（防止插件被卸载）
  { id: "openclaw-ctrl",       regex: /\bopenclaw\s+plugins?\s+(?:uninstall|remove|disable)\b/i },
  { id: "openclaw-ctrl-cn",    regex: /openclaw.*(?:卸载|删除|禁用).*插件/ },
];

// ============================================================
// 4. 受保护路径模式
// 匹配试图访问高敏感路径的参数
// ============================================================

export const PROTECTED_PATH_PATTERNS: readonly ThreatPattern[] = [
  // SSH 配置
  { id: "ssh-dir",         regex: /(?:^|\/)\.ssh(?:\/|$)/ },
  // Shell 初始化文件
  { id: "shell-rc",        regex: /(?:^|\/)\.(?:bash(?:rc|_profile|_history)|zshrc|zprofile|profile|zsh_history)(?:$|\/)/ },
  // OpenClaw 自身目录（精确保护敏感子目录，排除 media/ workspace/ canvas/ 等正常运行目录）
  { id: "openclaw-dir",    regex: /(?:^|\/)\.openclaw\/(?:plugins|extensions|agents|skills|tasks)(?:\/|$)/ },
  // 系统敏感文件
  { id: "etc-sensitive",   regex: /(?:^|\/)etc\/(?:passwd|shadow|sudoers|hosts|crontab)(?:$|\/)/ },
  // AWS/云凭证
  { id: "aws-cred",        regex: /(?:^|\/)\.aws\/(?:credentials|config)(?:$|\/)/ },
  // Git 凭证
  { id: "git-cred",        regex: /(?:^|\/)\.git(?:credentials|config)(?:$|\/)/ },
  // 通用 .config
  { id: "dot-config",      regex: /(?:^|\/)\.config\/(?!Code\/)[^\s/]{2,}(?:\/|$)/ },
  // npm/yarn 配置（含注册表 token）
  { id: "npm-config",      regex: /(?:^|\/)\.npmrc(?:$|\/)/ },
];

// ============================================================
// 5. 记忆写入风险模式
// 检测 memory_store 写入中的恶意内容
// ============================================================

export const MEMORY_WRITE_RISK_PATTERNS: readonly ThreatPattern[] = [
  { id: "mem-inject-en",   regex: /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?/i },
  { id: "mem-inject-cn",   regex: /忽略(?:之前|前面|所有)的?(?:指令|规则)/ },
  { id: "mem-role-change", regex: /you\s+are\s+now\s+(?!a\s+helpful)/i },
  { id: "mem-role-cn",     regex: /你现在(?:是|变成|扮演)/ },
  { id: "mem-special-tok", regex: /<\|(?:im_start|im_end|endoftext)\|>/ },
];

// ============================================================
// 6. 数据外泄链模式
// 检测 source→transform→sink 的数据外泄调用链信号
// ============================================================

export const EXFIL_SOURCE_SIGNALS: readonly ThreatPattern[] = [
  { id: "read-sensitive",  regex: /(?:read|cat|get|fetch)\s+(?:.*\/)?(?:\.env|secrets?|credentials?|\.ssh\/|config\.ya?ml)/i },
  { id: "env-access",      regex: /process\.env\b|os\.environ\b|\$\{?[A-Z_]{5,}\}?/ },
];

export const EXFIL_TRANSFORM_SIGNALS: readonly ThreatPattern[] = [
  { id: "base64-encode",   regex: /base64\s*(?:-w\s*0\b|\s*-e\b)?(?!\s*-d)/ },
  { id: "hex-encode",      regex: /xxd\b(?!\s*-r)/ },
  { id: "compress-pipe",   regex: /(?:gzip|bzip2|tar)\s+(?:-[czo]\s*){1,3}/ },
];

export const EXFIL_SINK_SIGNALS: readonly ThreatPattern[] = [
  { id: "curl-post",       regex: /curl\s+(?:-[A-Z]\s+)*-[dD]\s+['"]?@?/ },
  { id: "wget-post",       regex: /wget\s+--post-(?:data|file)\s+/ },
  { id: "nc-send",         regex: /\bnc\s+(?:-[a-z]+\s+)*[0-9]{1,3}\.[0-9]{1,3}/ },
  { id: "dns-exfil",       regex: /\bnslookup\s+\$|dig\s+\$\{/ },
];

// ============================================================
// 7. Skill 文件扫描模式
// 用于扫描 Skill 定义文件中的恶意内容
// ============================================================

export const SKILL_RISK_PATTERNS: readonly ThreatPattern[] = [
  // 要求读取凭证
  { id: "skill-cred-read",     regex: /(?:read|access|fetch|get)\s+(?:api[_-]?key|password|secret|token|credentials?)/i, requiresUnsafeContext: true },
  // 要求执行远程代码
  { id: "skill-remote-exec",   regex: /(?:curl|wget)\s+https?:\/\/[^\s]+\s*\|\s*(?:sh|bash|python|node)/i, requiresUnsafeContext: true },
  // 要求绕过安全限制
  { id: "skill-bypass",        regex: /(?:bypass|disable|ignore|override)\s+(?:security|safety|restrictions?|filters?)/i, requiresUnsafeContext: true },
  // 要求自我修改
  { id: "skill-self-mod",      regex: /(?:modify|edit|replace|update)\s+(?:this\s+)?(?:skill|plugin|extension)\s+(?:file|definition)/i, requiresUnsafeContext: true },
  // 要求写入系统路径
  { id: "skill-write-sys",     regex: /(?:write|create|append)\s+(?:to\s+)?(?:\/etc\/|\/usr\/|~\/\.ssh\/)/i, requiresUnsafeContext: true },
];

// 远程自举规则（download + execute 组合）
export type BootstrapRule = {
  id: string;
  downloadPatterns: readonly RegExp[];
  executePatterns: readonly RegExp[];
  directPatterns: readonly RegExp[];
};

export const SKILL_BOOTSTRAP_RULES: readonly BootstrapRule[] = [
  {
    id: "remote-script-bootstrap",
    directPatterns: [
      /(?:curl|wget)\s+[^\n]+\|\s*(?:su?do\s+)?(?:sh|bash|zsh|python|node)\b/i,
    ],
    downloadPatterns: [
      /(?:curl|wget)\s+https?:\/\/[^\s]+/i,
      /git\s+clone\s+https?:\/\/[^\s]+/i,
    ],
    executePatterns: [
      /(?:sh|bash|zsh|python|node|ruby|perl)\s+[^\n]*\.(?:sh|py|js|rb|pl)\b/i,
      /chmod\s+\+?x\s+[^\n]+&&[^\n]+(?:sh|bash|\.\/)/i,
    ],
  },
];

// 安全示例上下文标记（包含这些词时不触发 requiresUnsafeContext 规则）
export const SAFE_EXAMPLE_MARKERS: readonly RegExp[] = [
  /\b(?:example|demo|test|sample|placeholder|todo|fixme|note|warning|caution)\b/i,
  /^#+\s/m,            // Markdown 标题
  /`{1,3}[^`]*`{1,3}/, // 代码块内容
  /<!--[^>]*-->/,       // HTML 注释
];

// ============================================================
// 8. 工具返回内容中的嵌入式执行指令检测
// 防御攻击者在文件/文档/API响应中植入"exec:"类伪指令欺骗 Agent 执行
// ============================================================

export const EMBEDDED_EXEC_PATTERNS: readonly ThreatPattern[] = [
  // "exec:" / "run:" 伪指令前缀（文档注入最常见手法）
  { id: "exec-prefix-inject",   regex: /^\s*exec\s*:/mi },
  { id: "run-prefix-inject",    regex: /^\s*(?:run|execute|cmd|command)\s*:/mi },
  // 文档中隐藏的 bash -c 执行块
  { id: "inline-bash-c",        regex: /^\s*(?:sh|bash|zsh|ash)\s+-c\s+/mi },
  // "请执行以下命令" / "please execute" 类社会工程学诱导
  { id: "social-exec-cn",       regex: /请(?:立即|马上|)?(?:执行|运行|输入|操作)(?:以下|如下|下列)?(?:命令|指令|步骤|操作)/u },
  { id: "social-exec-en",       regex: /please\s+(?:execute|run|perform)\s+(?:the\s+)?(?:following|below)\s+(?:command|instruction)/i },
  // 维护模块/自动模块标记（伪装成系统内容的注入框）
  { id: "fake-maintenance-cn",  regex: /[-—]{2,}\s*(?:系统|自动|维护|巡检|诊断)\s*(?:模块|步骤|操作|维护)\s*[-—]{2,}/ },
];

// ============================================================
// 辅助：内联执行检测（非 Shell 语境，如 Python eval / Node exec）
// ============================================================

export const INLINE_EXEC_PATTERNS: readonly ThreatPattern[] = [
  { id: "python-eval",     regex: /\beval\s*\(/i },
  { id: "python-exec",     regex: /\bexec\s*\(/i },
  { id: "node-eval",       regex: /\beval\s*\(|new\s+Function\s*\(/i },
  { id: "node-child",      regex: /child_process\.(?:exec|spawn|execSync|spawnSync)\s*\(/i },
  { id: "deno-run",        regex: /Deno\.(?:run|command)\s*\(/i },
];
