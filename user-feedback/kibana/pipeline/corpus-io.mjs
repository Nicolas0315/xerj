// Shared admission boundary for public research records. This is a bounded,
// context-based redactor, not a universal secret detector. No original matches
// are returned in diagnostics or persisted in a sidecar.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const REDACTED = 'REDACTED';
export class CorpusError extends Error {
  constructor(category, line = 0) {
    super(`corpus: ${category}${line ? ` at line ${line}` : ''}`);
    this.category = category;
    this.line = line;
  }
}
export function safeFailure(error) {
  return error instanceof CorpusError ? error.message : 'corpus: operation-failed';
}
export function pipelinePaths(defaultRoot) {
  // Also protects errors from legacy projection code: never print an exception
  // carrying a record, a parser excerpt, or an untrusted filesystem path.
  process.on('uncaughtException', error => {
    console.error(safeFailure(error));
    process.exitCode = 1;
  });
  const args = process.argv.slice(2);
  const option = name => {
    const i = args.indexOf(name);
    if (i < 0) return defaultRoot;
    if (!args[i + 1] || args[i + 1].startsWith('--')) throw new CorpusError('missing-path-option');
    return path.resolve(args[i + 1]);
  };
  return { input: option('--input-root'), output: option('--output-root') };
}

// Decode only representation syntax for inspection, retaining a source map so
// replacements preserve the original quoting, entities and other research text.
function viewOf(text) {
  let view = text;
  // Use UTF-16 offsets, as RegExp and String.slice do.
  let ranges = Array.from({ length: text.length }, (_, i) => [i, i + 1]);
  for (let pass = 0; pass < 3; pass++) {
    const rx = /&(?:amp|quot|apos|lt|gt|nbsp|#(?:x[\da-f]+|\d+));|\\(?:["'nrt\\/]|u[\da-f]{4})/gi;
    let out = '', mapped = [], start = 0, changed = false;
    for (const match of view.matchAll(rx)) {
      out += view.slice(start, match.index);
      mapped.push(...ranges.slice(start, match.index));
      const raw = match[0];
      let decoded;
      if (raw[0] === '&') {
        const entity = raw.slice(1, -1).toLowerCase();
        const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' };
        const code = entity.startsWith('#x') ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
        decoded = named[entity] ?? (Number.isInteger(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : raw);
      } else {
        decoded = raw[1] === 'u' ? String.fromCharCode(parseInt(raw.slice(2), 16)) : ({ n: '\n', r: '\r', t: '\t' }[raw[1]] ?? raw[1]);
      }
      out += decoded;
      const span = [ranges[match.index][0], ranges[match.index + raw.length - 1][1]];
      for (let i = 0; i < decoded.length; i++) mapped.push(span);
      start = match.index + raw.length;
      changed ||= decoded !== raw;
    }
    out += view.slice(start);
    mapped.push(...ranges.slice(start));
    view = out; ranges = mapped;
    if (!changed) break;
  }
  return { view, ranges };
}

const KEY = '(?:[\\w.-]*[._-])?(?:password|passwd|pwd|client[_-]?secret|encryptionKey|serviceAccountToken|api[_-]?key|access[_-]?token|secret[_-]?access[_-]?key|secret|token)';
const credentialField = key => new RegExp(`^(?:${KEY}|(?:proxy[_-]?)?authorization)$`, 'i').test(key);
const alreadyRedacted = value => /^(?:REDACTED(?:\s+REDACTED)*|\*+|<redacted>|\[redacted\])$/i.test(value);

function credentialSpans(text, ranges, original) {
  const spans = [];
  const add = (start, end, category) => {
    if (end <= start || alreadyRedacted(text.slice(start, end))) return;
    spans.push({ start, end, category });
  };
  // A value is a quoted string or one unquoted config/shell token. Never let
  // whitespace in the serialized JSONL join unrelated records.
  const valueAt = (position, category, { restOfLine = false } = {}) => {
    let start = position;
    while (/[ \t]/.test(text[start] || '') && start < text.length) start++;
    if (start >= text.length) return;
    const quote = text[start];
    if (quote === '"' || quote === "'") {
      const close = text.indexOf(quote, start + 1);
      // Normalization is for recognition only. An escaped quote inside valid
      // JSON cannot become a closing delimiter just because the next character
      // happens to be whitespace or a comma. Mixed encodings/escape depths are
      // deliberately refused rather than publishing a partially scrubbed value.
      if (close >= 0 && original.slice(...ranges[start]) !== original.slice(...ranges[close])) throw new CorpusError('unsupported-credential-value');
      if (close >= 0 && close + 1 < text.length && !/[\s,;:)}\]<>]/.test(text[close + 1])) throw new CorpusError('unsupported-credential-value');
      add(start + 1, close < 0 ? text.length : close, category);
      return;
    }
    // YAML blocks/structured values and continuation-only values require an
    // explicit operator decision. Do not emit a partly scrubbed representation.
    if (/[\r\n|>{\[]/.test(quote) || quote === '\\') throw new CorpusError('unsupported-credential-value');
    const stop = restOfLine ? /[\r\n"'<>]/ : /[\s,;"'<>}\]]/;
    let end = start;
    while (end < text.length && !stop.test(text[end])) end++;
    const delimiter = text[end] || '';
    if (end === start || /[,;<>}\]]/.test(delimiter) ||
        (category !== 'authorization' && /["']/.test(delimiter)) ||
        text.slice(start, end).includes('\\')) throw new CorpusError('unsupported-credential-value');
    if (category === 'authorization' && /["']/.test(delimiter) && original.slice(...ranges[end]).includes('\\')) throw new CorpusError('unsupported-credential-value');
    // YAML plain scalars can contain spaces and punctuation. The token grammar
    // is safe only for a complete scalar; don't silently keep its remaining tail.
    if (category === 'assignment' && text.slice(end).split(/[\r\n]/, 1)[0].trim()) throw new CorpusError('unsupported-credential-value');
    add(start, end, category);
  };
  for (const m of text.matchAll(new RegExp(`(?:^|[\\s{,])(?:["']?${KEY}["']?|(?:PASSWORD|SERVICE_TOKEN)\\s+[^\\s=]+)[ \\t]*[:=][ \\t]*`, 'gim'))) {
    valueAt(m.index + m[0].length, 'assignment');
  }
  for (const m of text.matchAll(/\bAuthorization["']?[ \t]*[:=][ \t]*/gi)) {
    const pos = m.index + m[0].length;
    if (text[pos] === '"' || text[pos] === "'") valueAt(pos, 'authorization');
    else {
      const scheme = /^(?:Basic|Bearer|ApiKey|Token)[ \t]+/i.exec(text.slice(pos));
      if (scheme) valueAt(pos + scheme[0].length, 'authorization');
      else valueAt(pos, 'authorization', { restOfLine: true });
    }
  }
  for (const m of text.matchAll(/(?:^|\s)(?:-[a-tv-z]*u|--(?:user|proxy-user|oauth2-bearer)(?:=|[ \t]+))/gim)) {
    valueAt(m.index + m[0].length, 'auth-argument');
  }
  for (const m of text.matchAll(/https?:\/\/[^\s<>"']+/gi)) {
    const url = m[0], base = m.index;
    const authorityStart = url.indexOf('//') + 2;
    const authorityEnd = url.slice(authorityStart).search(/[/?#]/);
    const authority = url.slice(authorityStart, authorityEnd < 0 ? url.length : authorityStart + authorityEnd);
    const at = authority.lastIndexOf('@');
    if (at >= 0) add(base + authorityStart, base + authorityStart + at, 'url-userinfo');
    // Inspect individual query/fragment pairs without normalizing/re-serializing
    // the URL; malformed/example hosts still get their credential fields removed.
    for (const pair of url.matchAll(/[?&#]([^=&#]+)=([^&#]*)/g)) {
      let key;
      try { key = decodeURIComponent(pair[1]); } catch { throw new CorpusError('unsupported-url-encoding'); }
      if (/^(?:x-amz-(?:credential|signature|security-token)|awsaccesskeyid|signature|(?:access_|id_)?token|api[_-]?key|password|client_secret)$/i.test(key)) {
        const start = base + pair.index + 1 + pair[1].length + 1;
        add(start, start + pair[2].length, 'url-credential');
      }
    }
  }
  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g)) add(m.index, m.index + m[0].length, 'jwt');
  for (const m of text.matchAll(/-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g)) add(m.index, m.index + m[0].length, 'private-key');
  return spans;
}

export function redactRecord(record) {
  if (!record || Array.isArray(record) || typeof record !== 'object' ||
      typeof record.id !== 'string' || typeof record.source !== 'string') {
    throw new CorpusError('invalid-record');
  }
  const categories = {}, found = new Set();
  const inspect = text => {
    const { view, ranges } = viewOf(text);
    const spans = credentialSpans(view, ranges, text);
    for (const { start, end, category } of spans) {
      const value = view.slice(start, end);
      // Replace repetitions in the same record as well. Short/common values
      // are removed at credential contexts only, avoiding damage to metadata.
      if (value.length >= 8) found.add(value);
      const credential = category === 'auth-argument' || category === 'url-userinfo'
        ? value.slice(value.indexOf(':') + 1)
        : category === 'authorization' ? value.replace(/^(?:Basic|Bearer|ApiKey|Token)\s+/i, '') : '';
      if (credential.length >= 8 && !alreadyRedacted(credential)) found.add(credential);
    }
    return { text, view, ranges, spans };
  };
  const visit = (value, fn, key = '') => {
    if (typeof value === 'string') return fn(value, key);
    if (credentialField(key) && value != null) throw new CorpusError('unsupported-credential-value');
    if (Array.isArray(value)) return value.map(v => visit(v, fn, key));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, visit(v, fn, k)]));
    return value;
  };
  visit(record, (text, key) => {
    inspect(text);
    if (credentialField(key) && text.length >= 8 && !alreadyRedacted(text)) {
      found.add(text);
      const token = text.replace(/^(?:Basic|Bearer|ApiKey|Token)\s+/i, '');
      if (token.length >= 8 && !alreadyRedacted(token)) found.add(token);
    }
  });
  const safe = visit(record, (text, key) => {
    const { view, ranges, spans } = inspect(text);
    if (credentialField(key) && !alreadyRedacted(text)) spans.push({ start: 0, end: view.length, category: 'credential-field' });
    for (const value of found) {
      let pos = 0;
      while ((pos = view.indexOf(value, pos)) >= 0) {
        spans.push({ start: pos, end: pos + value.length, category: 'repeated-value' });
        pos += value.length;
      }
    }
    const merged = [];
    for (const span of spans.filter(s => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end)) {
      categories[span.category] = (categories[span.category] || 0) + 1;
      const last = merged.at(-1);
      if (last && span.start <= last.end) last.end = Math.max(last.end, span.end);
      else merged.push({ ...span });
    }
    for (const { start, end } of merged.reverse()) {
      const a = ranges[start][0], b = ranges[end - 1][1];
      // Keep real line boundaries, including multi-line quoted logs.
      text = text.slice(0, a) + text.slice(a, b).replace(/[^\r\n]+/g, REDACTED) + text.slice(b);
    }
    return text;
  });
  return { record: safe, categories };
}

export function readRecords(file, { onRecord } = {}) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { throw new CorpusError('read-failed'); }
  const records = [];
  for (const [index, line] of text.split('\n').entries()) {
    if (!line.trim()) continue;
    let item;
    try { item = JSON.parse(line); } catch { throw new CorpusError('invalid-json', index + 1); }
    let result;
    try { result = redactRecord(item); } catch (error) {
      throw new CorpusError(error instanceof CorpusError ? error.category : 'invalid-record', index + 1);
    }
    records.push(result.record);
    onRecord?.({ line: index + 1, categories: result.categories });
  }
  return records;
}

export function writeText(file, text) {
  const temporary = path.join(path.dirname(file), `.corpus-${randomUUID()}.tmp`);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(temporary, text, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, file);
  } catch {
    throw new CorpusError('write-failed');
  } finally {
    try { fs.unlinkSync(temporary); } catch { /* renamed or never created */ }
  }
}

export function writeBatch(file, incoming) {
  const seen = new Set();
  const kept = [];
  for (const item of fs.existsSync(file) ? readRecords(file) : []) {
    if (!seen.has(item.id)) { seen.add(item.id); kept.push(item); }
  }
  // Validate the entire incoming batch before any write, including duplicates.
  const safe = incoming.filter(item => item && item.id).map(item => redactRecord(item).record);
  let added = 0, replaced = 0;
  for (const item of safe) {
    if (seen.has(item.id)) { replaced++; continue; }
    seen.add(item.id);
    kept.push(item);
    added++;
  }
  writeText(file, kept.map(item => JSON.stringify(item)).join('\n') + (kept.length ? '\n' : ''));
  return { added, replaced };
}
