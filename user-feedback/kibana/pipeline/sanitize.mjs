#!/usr/bin/env node
// Offline only: inspect existing JSONL or export sanitized copies into a NEW
// directory. Never rewrite tracked corpus/history to prepare a public patch.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CorpusError, pipelinePaths, readRecords, safeFailure, writeText } from './corpus-io.mjs';

const defaults = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let stage;
try {
  const { input, output } = pipelinePaths(defaults);
  const check = process.argv.includes('--check');
  if (!check && (!process.argv.includes('--output-root') || output === input || fs.existsSync(output))) {
    throw new CorpusError('new-output-root-required');
  }
  const sourceRoot = path.join(input, 'sources');
  const files = [];
  const reports = [];
  let count = 0, changed = 0;
  // Complete admission for every file before creating a staging directory.
  for (const source of fs.readdirSync(sourceRoot).sort()) {
    if (!/^[a-z0-9-]+$/.test(source) || !fs.statSync(path.join(sourceRoot, source)).isDirectory()) throw new CorpusError('invalid-source-directory');
    for (const kind of ['raw', 'enriched']) {
      const relative = path.join('sources', source, kind + '.jsonl');
      const file = path.join(input, relative);
      if (!fs.existsSync(file)) continue;
      const rows = readRecords(file, { onRecord: ({ line, categories }) => {
        count++;
        if (Object.keys(categories).length) {
          changed++;
          reports.push({ file: relative, line, categories });
        }
      } });
      files.push({ relative, rows });
    }
  }
  if (!check) {
    // The caller chooses a private parent. An existing destination is never
    // reused, and only fully sanitized bytes enter the sibling staging tree.
    const parent = path.dirname(output);
    if (!fs.statSync(parent).isDirectory()) throw new CorpusError('output-parent-required');
    stage = fs.mkdtempSync(path.join(parent, '.corpus-export-'));
    for (const { relative, rows } of files) {
      writeText(path.join(stage, relative), rows.map(row => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''));
    }
    if (fs.existsSync(output)) throw new CorpusError('new-output-root-required');
    fs.renameSync(stage, output);
    stage = undefined;
  }
  for (const report of reports) console.log(JSON.stringify(report));
  console.log(JSON.stringify({ mode: check ? 'check' : 'export', files: files.length, records: count, redacted_records: changed }));
  if (check && changed) process.exitCode = 2;
} catch (error) {
  console.error(safeFailure(error));
  process.exitCode = 1;
} finally {
  if (stage) fs.rmSync(stage, { recursive: true, force: true });
}
