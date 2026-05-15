// Shared types for the agent-audit tool.

export type Severity = 'critical' | 'high' | 'medium';

export type Category = 'hardcoded-key' | 'shared-credential' | 'long-lived';

export interface Finding {
  severity: Severity;
  category: Category;
  ruleId: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  message: string;
  remediation: string;
  matchedText?: string;
}

export interface ScanResult {
  rootDir: string;
  filesScanned: number;
  findings: Finding[];
  durationMs: number;
  scannedAt: string;
}

export interface ScanOptions {
  rootDir: string;
  ignore?: string[];
  maxFileSizeBytes?: number;
  followSymlinks?: boolean;
}
