// Rule: detect hardcoded LLM provider / cloud / framework keys in source.
// Severity: critical for high-value provider keys, high for everything else.

import { KEY_PATTERNS } from '../patterns.js';
import { getLine, offsetToLineCol, redact, type ScannableFile } from '../scanner.js';
import type { Finding, Severity } from '../types.js';

const CRITICAL_PROVIDERS = new Set([
  'openai',
  'anthropic',
  'aws-bedrock',
  'azure-openai',
  'google-ai',
  'stripe',
]);

// Indicators that a match is a placeholder / example, not a real key.
// We treat these as suppressors to keep false-positive noise low. Anything
// inside a fixture file under test/, examples/, samples/, or docs/ is also
// allowed to remain a finding (so our own fixtures still trigger).
// Substrings we scan for in either the surrounding line OR the matched value
// itself. Underscores break JS word-boundary anchors, so we match without `\b`
// and rely on plain substring search.
const PLACEHOLDER_INDICATORS = [
  /your[_-]?api[_-]?key/i,
  /your[_-]?key[_-]?here/i,
  /example/i,
  /placeholder/i,
  /redacted/i,
  /sanitized/i,
  /dummy/i,
  /<your-?[^>]*>/i,
  /do[_-]?not[_-]?use/i,
  /fake/i,
  /test[_-]?key/i,
  /sample/i,
];

function looksLikePlaceholder(line: string, matched: string): boolean {
  for (const indicator of PLACEHOLDER_INDICATORS) {
    if (indicator.test(line) || indicator.test(matched)) return true;
  }
  // Repeated runs (AAAAA, XXXXX, 00000) — almost always docs / examples.
  if (/(.)\1{6,}/.test(matched)) return true;
  // Very few unique characters overall.
  const uniqueChars = new Set(matched.split('')).size;
  if (uniqueChars <= 5) return true;
  return false;
}

export function findHardcodedKeys(file: ScannableFile): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of KEY_PATTERNS) {
    // Reset lastIndex for global regexes that are reused across files.
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(file.content)) !== null) {
      const matched = match[1] ?? match[0];
      const line = getLine(file.content, match.index);

      if (looksLikePlaceholder(line, matched)) continue;

      const { line: lineNum, column } = offsetToLineCol(file.content, match.index);

      const severity: Severity = CRITICAL_PROVIDERS.has(pattern.provider) ? 'critical' : 'high';

      findings.push({
        severity,
        category: 'hardcoded-key',
        ruleId: `hardcoded-key:${pattern.provider}`,
        file: file.relativePath,
        line: lineNum,
        column,
        snippet: line.trim().slice(0, 200),
        matchedText: redact(matched),
        message: `${pattern.label} found in source. ${pattern.description}`,
        remediation: pattern.remediation,
      });
    }
  }

  return findings;
}
