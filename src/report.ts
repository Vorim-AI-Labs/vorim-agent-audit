// Report formatter. Two outputs: a colourised CLI report (default), and a
// machine-readable JSON output. The CLI report is the main artifact users see,
// so its design matters more than the code that produces it.

import pc from 'picocolors';
import type { Finding, ScanResult, Severity } from './types.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
};

function colorForSeverity(severity: Severity, text: string): string {
  switch (severity) {
    case 'critical':
      return pc.red(pc.bold(text));
    case 'high':
      return pc.yellow(pc.bold(text));
    case 'medium':
      return pc.blue(pc.bold(text));
  }
}

function severityIcon(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '✖';
    case 'high':
      return '⚠';
    case 'medium':
      return 'ⓘ';
  }
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function formatCli(result: ScanResult): string {
  const lines: string[] = [];
  const findings = sortFindings(result.findings);
  const counts = countBySeverity(findings);

  // ─── Header ────────────────────────────────────────────────────────────────
  lines.push('');
  lines.push(pc.bold('  Vorim agent-audit') + pc.dim('  v0.1.0'));
  lines.push(
    pc.dim(
      `  Scanned ${result.filesScanned} files in ${result.rootDir} (${result.durationMs}ms)`
    )
  );
  lines.push('');

  if (findings.length === 0) {
    lines.push(pc.green('  ✓ No agent hygiene issues found.'));
    lines.push('');
    lines.push(
      pc.dim('  This scan covers hardcoded keys, shared credentials, and long-lived')
    );
    lines.push(
      pc.dim('  permissions. It does not replace a full security audit, but it does')
    );
    lines.push(
      pc.dim('  catch the most common AI agent code anti-patterns.')
    );
    lines.push('');
    lines.push(pc.dim('  Free Agent Identity Scorecard → ') + pc.cyan('https://vorim.ai/agent-identity-scorecard'));
    lines.push('');
    return lines.join('\n');
  }

  // ─── Findings ──────────────────────────────────────────────────────────────
  let currentFile = '';
  for (const f of findings) {
    if (f.file !== currentFile) {
      currentFile = f.file;
      lines.push('');
      lines.push(pc.underline(pc.bold(f.file)));
    }

    const loc = f.column ? `${f.line}:${f.column}` : `${f.line}`;
    const header =
      `  ${severityIcon(f.severity)} ` +
      colorForSeverity(f.severity, f.severity.toUpperCase()) +
      pc.dim(`  ${loc}  ${f.ruleId}`);
    lines.push(header);

    lines.push('    ' + pc.bold(f.message));

    if (f.matchedText) {
      lines.push('    ' + pc.dim('matched: ') + pc.dim(f.matchedText));
    }
    if (f.snippet) {
      lines.push('    ' + pc.dim('└─ ' + f.snippet));
    }
    lines.push('    ' + pc.dim('fix: ') + pc.dim(f.remediation));
    lines.push('');
  }

  // ─── Summary ───────────────────────────────────────────────────────────────
  lines.push(pc.bold('Summary'));

  const summaryParts: string[] = [];
  if (counts.critical > 0)
    summaryParts.push(colorForSeverity('critical', `${counts.critical} critical`));
  if (counts.high > 0) summaryParts.push(colorForSeverity('high', `${counts.high} high`));
  if (counts.medium > 0)
    summaryParts.push(colorForSeverity('medium', `${counts.medium} medium`));

  lines.push('  ' + summaryParts.join(pc.dim(' · ')));
  lines.push('');

  // ─── CTA (single, soft) ────────────────────────────────────────────────────
  lines.push(pc.dim('─'.repeat(60)));
  lines.push('');
  lines.push(
    pc.dim('  Vorim Agent Identity Scorecard tests 10 broader best practices'));
  lines.push(
    pc.dim('  in 4 minutes — ') + pc.cyan('https://vorim.ai/agent-identity-scorecard')
  );
  lines.push('');

  return lines.join('\n');
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function exitCodeFromFindings(findings: Finding[]): number {
  const counts = countBySeverity(findings);
  if (counts.critical > 0) return 2;
  if (counts.high > 0) return 1;
  return 0;
}
