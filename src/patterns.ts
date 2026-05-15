// Regex patterns for detecting hardcoded credentials commonly used by AI agents.
//
// Precision over recall: each pattern matches the provider's published key prefix
// + length, so the false-positive rate stays manageable without AST analysis.
// We do not try to compete with TruffleHog on generic secrets. We focus on the
// keys AI agents actually carry: LLM provider tokens, vector DB tokens, agent
// framework credentials, and cloud LLM gateway keys.

export interface KeyPattern {
  provider: string;
  label: string;
  regex: RegExp;
  description: string;
  remediation: string;
}

export const KEY_PATTERNS: KeyPattern[] = [
  {
    provider: 'openai',
    label: 'OpenAI API key',
    // Modern OpenAI keys: sk-proj-..., sk-..., legacy sk-... (>=20 chars after sk-)
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    description:
      'OpenAI API keys grant full access to your account, including model invocation and billing. A leaked key can cost thousands of dollars in unauthorised usage within hours.',
    remediation:
      'Move this key to a secret manager (AWS Secrets Manager, Doppler, 1Password). Issue a short-lived, per-agent identity instead of sharing the master key.',
  },
  {
    provider: 'anthropic',
    label: 'Anthropic API key',
    // sk-ant-api03-... and sk-ant-... patterns
    regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,}\b/g,
    description:
      'Anthropic API keys grant access to Claude models and your billing account. Common leak path: committed .env files in agent frameworks.',
    remediation:
      'Rotate the key in the Anthropic console immediately. Use a per-agent identity with scoped permissions instead of embedding the workspace key.',
  },
  {
    provider: 'google-ai',
    label: 'Google AI / Gemini API key',
    // AIza... is the universal Google API key prefix (39 chars total)
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    description:
      'Google AI Studio / Gemini API keys grant access to Gemini models and incur usage charges on the project they belong to.',
    remediation:
      'Rotate via Google Cloud Console. For agents, prefer Vertex AI with workload identity federation over raw AIza keys.',
  },
  {
    provider: 'aws-bedrock',
    label: 'AWS access key ID',
    // AKIA = long-term IAM user, ASIA = short-term STS — both can call Bedrock
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    description:
      'AWS access key IDs paired with a secret in your code grant access to Bedrock, S3, and any service IAM permits. Leaks of these are the most common cloud breach vector.',
    remediation:
      'Rotate via IAM immediately. Use IAM roles + STS short-lived credentials for agent runtimes. Never embed long-term AKIA keys in code.',
  },
  {
    provider: 'aws-bedrock',
    label: 'AWS secret access key (likely)',
    // 40-char base64-like strings preceded by typical AWS variable names
    regex:
      /\b(?:aws[_-]?secret[_-]?access[_-]?key|AWS_SECRET_ACCESS_KEY)\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/g,
    description:
      'AWS secret access keys, when paired with the access key ID, grant full access to AWS resources the IAM user can reach.',
    remediation:
      'Rotate immediately and prefer short-lived STS credentials or IAM roles for any agent runtime.',
  },
  {
    provider: 'azure-openai',
    label: 'Azure OpenAI key (likely)',
    // 32-char hex string assigned to env vars matching Azure naming
    regex:
      /\b(?:AZURE[_-]?OPENAI[_-]?(?:API[_-]?)?KEY|AZURE[_-]?AI[_-]?KEY)\b\s*[:=]\s*["']?([a-f0-9]{32})\b/gi,
    description:
      'Azure OpenAI keys grant access to a specific deployment. Common leak path: hardcoded in agent config when teams migrate from raw OpenAI to Azure for compliance.',
    remediation:
      'Rotate via Azure portal. Use Entra ID / managed identity for production agents instead of static keys.',
  },
  {
    provider: 'replicate',
    label: 'Replicate API token',
    regex: /\br8_[A-Za-z0-9]{37,40}\b/g,
    description:
      'Replicate tokens grant access to model invocation and account billing.',
    remediation: 'Rotate via Replicate dashboard. Avoid embedding tokens in agent code.',
  },
  {
    provider: 'huggingface',
    label: 'Hugging Face token',
    regex: /\bhf_[A-Za-z0-9]{34,40}\b/g,
    description:
      'Hugging Face tokens grant access to private models, datasets, and inference endpoints.',
    remediation: 'Rotate via huggingface.co/settings/tokens. Use scoped read-only tokens where possible.',
  },
  {
    provider: 'cohere',
    label: 'Cohere API key (likely)',
    // 40-char alphanumeric assigned to COHERE_API_KEY
    regex: /\b(?:COHERE[_-]?API[_-]?KEY)\b\s*[:=]\s*["']?([A-Za-z0-9]{40})\b/gi,
    description: 'Cohere API keys grant access to model invocation and incur usage charges.',
    remediation: 'Rotate via Cohere dashboard.',
  },
  {
    provider: 'mistral',
    label: 'Mistral API key (likely)',
    regex: /\b(?:MISTRAL[_-]?API[_-]?KEY)\b\s*[:=]\s*["']?([A-Za-z0-9]{32,40})\b/gi,
    description: 'Mistral API keys grant access to model invocation.',
    remediation: 'Rotate via console.mistral.ai.',
  },
  {
    provider: 'perplexity',
    label: 'Perplexity API key',
    regex: /\bpplx-[A-Za-z0-9]{48,56}\b/g,
    description: 'Perplexity API keys grant access to the sonar models and search APIs.',
    remediation: 'Rotate via perplexity.ai/settings/api.',
  },
  {
    provider: 'groq',
    label: 'Groq API key',
    regex: /\bgsk_[A-Za-z0-9]{48,56}\b/g,
    description: 'Groq API keys grant access to inference and incur usage charges.',
    remediation: 'Rotate via console.groq.com.',
  },
  {
    provider: 'pinecone',
    label: 'Pinecone API key (UUID format)',
    // Pinecone keys are UUID4 strings; flag when assigned to PINECONE_API_KEY
    regex:
      /\b(?:PINECONE[_-]?API[_-]?KEY)\b\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi,
    description:
      'Pinecone API keys grant full read/write to your vector indexes. Agents with RAG pipelines commonly leak these.',
    remediation: 'Rotate via Pinecone dashboard and audit which agents had access.',
  },
  {
    provider: 'langsmith',
    label: 'LangSmith / LangChain API key',
    regex: /\blsv2_(?:sk|pt)_[A-Za-z0-9]{32,48}\b/g,
    description:
      'LangSmith API keys grant access to traces, datasets, and project data. Leaked LangSmith keys expose your entire prompt and tool-use history.',
    remediation: 'Rotate via smith.langchain.com/settings.',
  },
  {
    provider: 'stripe',
    label: 'Stripe secret key',
    regex: /\bsk_(?:test|live)_[A-Za-z0-9]{24,99}\b/g,
    description:
      'Stripe secret keys grant payment and customer access. Critical for agents using Stripe ACP or autonomous transaction flows.',
    remediation:
      'Rotate via Stripe dashboard immediately. Use restricted keys with scoped permissions for agent contexts.',
  },
  {
    provider: 'github',
    label: 'GitHub personal access token',
    regex: /\bghp_[A-Za-z0-9]{36,40}\b/g,
    description: 'GitHub PATs grant repository access. Agents that read or write code commonly carry these.',
    remediation:
      'Rotate via github.com/settings/tokens. Prefer fine-grained tokens with explicit repo scoping for agent use.',
  },
  {
    provider: 'github',
    label: 'GitHub fine-grained token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    description: 'GitHub fine-grained PATs grant scoped repository access.',
    remediation: 'Rotate via github.com/settings/tokens.',
  },
  {
    provider: 'slack',
    label: 'Slack bot/user token',
    regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    description:
      'Slack tokens grant workspace access. Agents that send notifications or read channels frequently carry these.',
    remediation: 'Rotate via Slack app management. Use granular scopes for agent bots.',
  },
];

// Detect lines that look like agent configurations with broad / unbounded
// permissions. Used by the long-lived-credentials rule.
export const BROAD_PERMISSION_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /\bscope\s*[:=]\s*["']\*["']/gi, label: 'wildcard scope ("*")' },
  { regex: /\brole\s*[:=]\s*["']?(?:admin|superuser|root)["']?/gi, label: 'admin/root role assignment' },
  { regex: /\bpermissions?\s*[:=]\s*["']?(?:all|full|\*)["']?/gi, label: 'all/full permissions' },
  { regex: /\bexpires?(?:_at|At|_in|In)?\s*[:=]\s*(?:null|none|None|undefined|0)\b/g, label: 'permission with no expiry' },
  { regex: /\bttl\s*[:=]\s*(?:0|null|none|None|undefined|-1)\b/gi, label: 'TTL set to zero or null' },
];

// Common variable / env names that suggest a credential is being passed to an
// agent. Used by the shared-credentials rule to detect "one key, many agents".
export const AGENT_CREDENTIAL_HINTS: RegExp[] = [
  /\b(?:OPENAI|ANTHROPIC|GOOGLE|AZURE|MISTRAL|COHERE|GROQ|PERPLEXITY|REPLICATE)_API_KEY\b/g,
  /\b(?:apiKey|api_key|llmKey|llm_key)\s*[:=]/g,
];
