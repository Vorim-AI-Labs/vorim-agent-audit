// File-system walker. Yields scannable text files under a root directory,
// respecting a sensible default exclude list. Designed to be small, dependency-
// free, and predictable — no fancy globbing, just directory traversal with
// hard-coded skip rules that match what teams actually want excluded.

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.cache',
  '.turbo',
  '.parcel-cache',
  'coverage',
  '.coverage',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  'target',
  '.gradle',
  '.idea',
  '.vscode',
  '.DS_Store',
]);

// Files we never scan because they are noisy by definition (lockfiles), binary,
// or generated. Listed by basename or extension.
const IGNORE_BASENAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'Cargo.lock',
  'Gemfile.lock',
  'poetry.lock',
  'composer.lock',
  '.DS_Store',
]);

const IGNORE_EXTENSIONS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.svg',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.7z',
  '.mp3',
  '.mp4',
  '.mov',
  '.avi',
  '.webm',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.wasm',
  '.class',
  '.pyc',
  '.pyo',
]);

// Extensions we care about. Empty extension is allowed because .env, .envrc,
// Dockerfile, etc. need scanning. We do final size + binary heuristic checks.
const SCANNABLE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.go',
  '.rb',
  '.rs',
  '.java',
  '.kt',
  '.swift',
  '.cs',
  '.php',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.conf',
  '.env',
  '.envrc',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.md',
  '.mdx',
  '.txt',
  '.xml',
  '.html',
  '.htm',
]);

const DOTENV_BASENAMES = new Set(['.env', '.env.local', '.env.production', '.env.development', '.env.test', '.envrc']);

const DEFAULT_MAX_FILE_BYTES = 1_000_000; // 1MB; key leaks live in small files

function getExtension(filename: string): string {
  const idx = filename.lastIndexOf('.');
  if (idx === -1) return '';
  return filename.slice(idx).toLowerCase();
}

function isLikelyBinary(content: string): boolean {
  // Cheap heuristic: if the first 1KB has more than 1% NUL bytes, treat as binary.
  const slice = content.slice(0, 1024);
  let nulls = 0;
  for (let i = 0; i < slice.length; i++) {
    if (slice.charCodeAt(i) === 0) nulls++;
  }
  return nulls / Math.max(slice.length, 1) > 0.01;
}

export interface ScannableFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

export async function* walk(
  rootDir: string,
  options: { maxFileSizeBytes?: number; ignoreDirs?: Set<string> } = {}
): AsyncGenerator<ScannableFile> {
  const maxSize = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_BYTES;
  const ignoreDirs = options.ignoreDirs ?? DEFAULT_IGNORE_DIRS;

  async function* walkDir(dir: string): AsyncGenerator<ScannableFile> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      // Permission errors etc. — skip silently. Audit tools should never crash
      // because of one unreadable directory.
      return;
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (ignoreDirs.has(entry.name)) continue;
        yield* walkDir(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      if (IGNORE_BASENAMES.has(entry.name)) continue;

      const ext = getExtension(entry.name);
      if (IGNORE_EXTENSIONS.has(ext)) continue;

      // Always scan dotenv-style files even if their extension would otherwise
      // be empty / unrecognised. Otherwise restrict to known scannable types.
      const isDotenv = DOTENV_BASENAMES.has(entry.name) || entry.name.startsWith('.env.');
      if (!isDotenv && ext && !SCANNABLE_EXTENSIONS.has(ext)) continue;
      if (!isDotenv && !ext) continue;

      let info;
      try {
        info = await stat(fullPath);
      } catch {
        continue;
      }
      if (info.size > maxSize) continue;
      if (info.size === 0) continue;

      let content: string;
      try {
        content = await readFile(fullPath, 'utf8');
      } catch {
        continue;
      }

      if (isLikelyBinary(content)) continue;

      yield {
        absolutePath: fullPath,
        relativePath: relative(rootDir, fullPath) || entry.name,
        content,
      };
    }
  }

  yield* walkDir(rootDir);
}

// Helper used by rules: convert an offset within a file into a (line, column).
export function offsetToLineCol(content: string, offset: number): { line: number; column: number } {
  let line = 1;
  let col = 1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) {
      line++;
      col = 1;
    } else {
      col++;
    }
  }
  return { line, column: col };
}

// Helper used by rules: extract the line containing a given offset.
export function getLine(content: string, offset: number): string {
  let start = offset;
  while (start > 0 && content.charCodeAt(start - 1) !== 10) start--;
  let end = offset;
  while (end < content.length && content.charCodeAt(end) !== 10) end++;
  return content.slice(start, end);
}

// Redact a matched secret so it can be safely printed in the CLI report.
// Keeps the first 4 and last 4 chars so users can recognise which key it is.
export function redact(value: string): string {
  if (value.length <= 12) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}…${'*'.repeat(8)}…${value.slice(-4)}`;
}
