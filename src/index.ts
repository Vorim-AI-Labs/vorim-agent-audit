#!/usr/bin/env node
// CLI entry. Library exports are also re-exported here so programmatic users
// can do `import { runScan } from "@vorim/agent-audit"`.

import { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { runScan } from './audit.js';
import { exitCodeFromFindings, formatCli, formatJson } from './report.js';

export { runScan } from './audit.js';
export type { Finding, ScanResult, ScanOptions } from './types.js';

interface CliOptions {
  json?: boolean;
  output?: string;
  silent?: boolean;
  failOn?: 'critical' | 'high' | 'medium' | 'none';
}

async function main(): Promise<void> {
  const program = new Command();

  program
    .name('vorim-audit')
    .description(
      'Free AI agent code hygiene checker. Scans for hardcoded LLM keys, shared credentials, and long-lived permissions.'
    )
    .version('0.1.0')
    .argument('[path]', 'Directory to scan', '.')
    .option('--json', 'Output machine-readable JSON instead of a CLI report')
    .option('-o, --output <file>', 'Write JSON output to a file (implies --json)')
    .option('--silent', 'Suppress all output except errors. Useful in CI with --output.')
    .option(
      '--fail-on <level>',
      'Exit non-zero when findings of this severity or worse exist (critical|high|medium|none)',
      'critical'
    )
    .action(async (path: string, options: CliOptions) => {
      const result = await runScan({ rootDir: path });

      const wantsJsonOutput = !!options.json || !!options.output;

      if (options.output) {
        await writeFile(options.output, formatJson(result), 'utf8');
        if (!options.silent) {
          process.stdout.write(`Wrote ${result.findings.length} findings to ${options.output}\n`);
        }
      } else if (wantsJsonOutput) {
        process.stdout.write(formatJson(result) + '\n');
      } else if (!options.silent) {
        process.stdout.write(formatCli(result));
      }

      const exitCode = computeExitCode(result.findings, options.failOn ?? 'critical');
      process.exit(exitCode);
    });

  await program.parseAsync(process.argv);
}

function computeExitCode(
  findings: import('./types.js').Finding[],
  failOn: NonNullable<CliOptions['failOn']>
): number {
  if (failOn === 'none') return 0;

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
  };
  for (const f of findings) counts[f.severity]++;

  if (failOn === 'medium' && (counts.critical > 0 || counts.high > 0 || counts.medium > 0)) {
    return exitCodeFromFindings(findings) || 1;
  }
  if (failOn === 'high' && (counts.critical > 0 || counts.high > 0)) {
    return exitCodeFromFindings(findings) || 1;
  }
  if (failOn === 'critical' && counts.critical > 0) {
    return 2;
  }
  return 0;
}

main().catch((err) => {
  process.stderr.write(`agent-audit: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(99);
});
