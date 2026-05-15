// Rule: detect agent permissions / scopes that are unbounded or never expire.
// Severity: medium. These aren't immediately exploitable like a leaked key,
// but they're the structural anti-pattern that makes incidents larger.

import { BROAD_PERMISSION_PATTERNS } from '../patterns.js';
import { getLine, offsetToLineCol, type ScannableFile } from '../scanner.js';
import type { Finding } from '../types.js';

export function findLongLived(file: ScannableFile): Finding[] {
  const findings: Finding[] = [];

  for (const { regex, label } of BROAD_PERMISSION_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(file.content)) !== null) {
      const line = getLine(file.content, match.index);
      const { line: lineNum, column } = offsetToLineCol(file.content, match.index);

      findings.push({
        severity: 'medium',
        category: 'long-lived',
        ruleId: `long-lived:${label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
        file: file.relativePath,
        line: lineNum,
        column,
        snippet: line.trim().slice(0, 200),
        message: `Agent configuration uses ${label}. Permissions without scope or expiry are the #1 blast-radius multiplier in agent incidents.`,
        remediation:
          'Set an explicit TTL (typically 2-24 hours). Use least-privilege scopes per agent action — never wildcard or admin.',
      });
    }
  }

  return findings;
}
