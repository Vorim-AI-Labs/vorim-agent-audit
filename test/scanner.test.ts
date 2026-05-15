import { describe, expect, it } from 'vitest';
import { runScan } from '../src/audit.js';
import { findHardcodedKeys } from '../src/rules/hardcoded-keys.js';
import { findSharedCredentials } from '../src/rules/shared-credentials.js';
import { findLongLived } from '../src/rules/long-lived.js';
import { redact } from '../src/scanner.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, 'fixtures');

async function loadFixture(name: string) {
  const absolutePath = join(FIXTURES, name);
  const content = await readFile(absolutePath, 'utf8');
  return { absolutePath, relativePath: name, content };
}

describe('hardcoded-keys rule', () => {
  it('detects critical OpenAI, Anthropic, Google AI, and AWS keys', async () => {
    const file = await loadFixture('bad-openai.ts');
    const findings = findHardcodedKeys(file);

    const providers = new Set(findings.map((f) => f.ruleId));
    expect(providers).toContain('hardcoded-key:openai');
    expect(providers).toContain('hardcoded-key:anthropic');
    expect(providers).toContain('hardcoded-key:google-ai');
    expect(providers).toContain('hardcoded-key:aws-bedrock');

    for (const f of findings) {
      expect(f.severity).toBe('critical');
      expect(f.category).toBe('hardcoded-key');
      expect(f.matchedText).toMatch(/…/); // should be redacted
    }
  });

  it('does NOT flag placeholder values in documentation', async () => {
    const file = await loadFixture('placeholder.md');
    const findings = findHardcodedKeys(file);

    // The fixture contains AKIAXXXXXXXXXXXXXXXX and sk-EXAMPLE_KEY...
    // — both should be suppressed by the placeholder heuristic.
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag clean code that uses env vars', async () => {
    const file = await loadFixture('good-agent.ts');
    const findings = findHardcodedKeys(file);
    expect(findings).toHaveLength(0);
  });
});

describe('shared-credentials rule', () => {
  it('detects one credential passed to multiple agent definitions', async () => {
    const file = await loadFixture('bad-langchain.py');
    const findings = findSharedCredentials(file);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('shared-credential');
    expect(findings[0].message).toMatch(/OPENAI_API_KEY/);
  });

  it('does NOT flag a single agent with its own credential', async () => {
    const file = await loadFixture('good-agent.ts');
    const findings = findSharedCredentials(file);
    expect(findings).toHaveLength(0);
  });
});

describe('long-lived rule', () => {
  it('detects wildcard scopes, admin roles, and zero TTL', async () => {
    const file = await loadFixture('bad-permissions.yaml');
    const findings = findLongLived(file);

    expect(findings.length).toBeGreaterThanOrEqual(3);
    for (const f of findings) {
      expect(f.severity).toBe('medium');
      expect(f.category).toBe('long-lived');
    }
  });

  it('does NOT flag scoped, time-bound permissions', async () => {
    const file = await loadFixture('good-agent.ts');
    const findings = findLongLived(file);
    expect(findings).toHaveLength(0);
  });
});

describe('end-to-end runScan', () => {
  it('scans the fixtures directory and returns expected severity counts', async () => {
    const result = await runScan({ rootDir: FIXTURES });

    expect(result.filesScanned).toBeGreaterThan(0);

    const counts = { critical: 0, high: 0, medium: 0 };
    for (const f of result.findings) counts[f.severity]++;

    expect(counts.critical).toBeGreaterThanOrEqual(4); // bad-openai.ts
    expect(counts.high).toBeGreaterThanOrEqual(1); // bad-langchain.py
    expect(counts.medium).toBeGreaterThanOrEqual(3); // bad-permissions.yaml
  });

  it('reports findings with valid file/line references', async () => {
    const result = await runScan({ rootDir: FIXTURES });
    for (const f of result.findings) {
      expect(f.file).toBeTruthy();
      expect(f.line).toBeGreaterThan(0);
      expect(f.message).toBeTruthy();
      expect(f.remediation).toBeTruthy();
    }
  });
});

describe('redact', () => {
  it('preserves first and last 4 chars of long strings', () => {
    expect(redact('sk-proj-1234567890ABCDEF')).toMatch(/^sk-p…/);
    expect(redact('sk-proj-1234567890ABCDEF')).toMatch(/CDEF$/);
  });

  it('fully masks short strings', () => {
    expect(redact('short')).toBe('*****');
  });
});
