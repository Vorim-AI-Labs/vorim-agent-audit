// Programmatic API. Importable as a library, used by the CLI as the entry.

import { resolve } from 'node:path';
import { walk } from './scanner.js';
import { findHardcodedKeys } from './rules/hardcoded-keys.js';
import { findSharedCredentials } from './rules/shared-credentials.js';
import { findLongLived } from './rules/long-lived.js';
import type { Finding, ScanOptions, ScanResult } from './types.js';

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const rootDir = resolve(options.rootDir);
  const start = Date.now();
  const findings: Finding[] = [];
  let filesScanned = 0;

  for await (const file of walk(rootDir, { maxFileSizeBytes: options.maxFileSizeBytes })) {
    filesScanned++;
    findings.push(...findHardcodedKeys(file));
    findings.push(...findSharedCredentials(file));
    findings.push(...findLongLived(file));
  }

  return {
    rootDir,
    filesScanned,
    findings,
    durationMs: Date.now() - start,
    scannedAt: new Date().toISOString(),
  };
}

export type { Finding, ScanResult, ScanOptions } from './types.js';
