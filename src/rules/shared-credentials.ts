// Rule: detect when one credential is being passed to multiple agent
// definitions in the same file. This is the most common anti-pattern in
// LangChain / CrewAI codebases — a single OPENAI_API_KEY threaded through
// 5 agents, which means "the agents" are one identity, not many.
//
// Detection heuristic (intentionally narrow to avoid false positives):
//   - Find lines that declare an LLM client with an explicit `api_key=` /
//     `apiKey:` argument.
//   - If the same variable is referenced as the api_key for 2+ distinct
//     agent / chain / tool instantiations in the same file, flag it.
//
// This is a regex-only heuristic. Cleaner with an AST, but we deferred that
// to v0.2 to ship a working v0.1.

import { offsetToLineCol, type ScannableFile } from '../scanner.js';
import type { Finding } from '../types.js';

// Match lines like: `llm = ChatOpenAI(api_key=OPENAI_API_KEY, ...)`
// or: `const llm = new ChatOpenAI({ apiKey: OPENAI_API_KEY })`
// Captures the variable name used as the credential.
const CREDENTIAL_PASS_PATTERN =
  /\b(?:api_key|apiKey|api-key|openai_api_key|anthropic_api_key)\s*[:=]\s*([A-Za-z_][A-Za-z0-9_]*)/g;

// Detect "this looks like an agent / chain / LLM client instantiation".
const AGENT_INSTANTIATION_PATTERN =
  /\b(?:Agent|ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|OpenAI|Anthropic|LLM|Chain|Tool|Crew|Task)\s*\(/g;

export function findSharedCredentials(file: ScannableFile): Finding[] {
  const findings: Finding[] = [];

  // Step 1: collect every (variable, offset) pair where a credential variable
  // is passed in.
  const credentialUsages: Array<{ varName: string; offset: number }> = [];
  let match: RegExpExecArray | null;

  CREDENTIAL_PASS_PATTERN.lastIndex = 0;
  while ((match = CREDENTIAL_PASS_PATTERN.exec(file.content)) !== null) {
    const varName = match[1];
    // Skip obvious string-literal cases — that's the hardcoded-keys rule's job.
    if (!varName || varName.length < 2) continue;
    credentialUsages.push({ varName, offset: match.index });
  }

  if (credentialUsages.length < 2) return findings;

  // Step 2: group by variable name. Two or more usages of the same variable in
  // the same file = shared credential.
  const byVar = new Map<string, number[]>();
  for (const { varName, offset } of credentialUsages) {
    if (!byVar.has(varName)) byVar.set(varName, []);
    byVar.get(varName)!.push(offset);
  }

  // Step 3: confirm at least one usage is inside an agent-instantiation context.
  // Without this check, we'd flag generic API client setup.
  AGENT_INSTANTIATION_PATTERN.lastIndex = 0;
  const agentOffsets: number[] = [];
  let agentMatch: RegExpExecArray | null;
  while ((agentMatch = AGENT_INSTANTIATION_PATTERN.exec(file.content)) !== null) {
    agentOffsets.push(agentMatch.index);
  }

  // A credential usage is "near" an agent instantiation if it appears within
  // 200 characters of one. This handles typical multi-line constructor calls
  // without requiring AST parsing.
  function isNearAgentInstantiation(credOffset: number): boolean {
    for (const agentOffset of agentOffsets) {
      if (Math.abs(credOffset - agentOffset) < 200) return true;
    }
    return false;
  }

  for (const [varName, offsets] of byVar.entries()) {
    const nearAgents = offsets.filter(isNearAgentInstantiation);
    if (nearAgents.length < 2) continue;

    // Report at the first occurrence.
    const firstOffset = nearAgents[0];
    const { line, column } = offsetToLineCol(file.content, firstOffset);

    findings.push({
      severity: 'high',
      category: 'shared-credential',
      ruleId: 'shared-credential:multi-agent',
      file: file.relativePath,
      line,
      column,
      snippet: `${varName} used as credential in ${nearAgents.length} agent definitions`,
      message: `One credential (\`${varName}\`) is passed to ${nearAgents.length} agent definitions in this file. When all agents share an identity, you cannot tell which agent did what during an incident.`,
      remediation:
        'Issue a per-agent identity. Each agent should authenticate with its own short-lived credential so audit trails attribute actions correctly.',
    });
  }

  return findings;
}
