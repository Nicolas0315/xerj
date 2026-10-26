import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const here = path.dirname(fileURLToPath(import.meta.url));
const secret = () => 'synthetic_' + randomBytes(12).toString('hex');
const artifact = (body, extra = {}) => ({
  id: 'so-synthetic', source: 'stackoverflow',
  source_url: 'https://stackoverflow.com/questions/1',
  posted_at: '2026-01-01T00:00:00Z', captured_at: '2026-01-02T00:00:00Z',
  author: 'synthetic-author', kind: 'question', product: ['kibana'],
  title: 'Kibana dashboard is slow', body, score: 20,
  category: '04-performance-and-load', sentiment: 'negative', tags: [], ...extra,
});
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(process.env.CORPUS_TEST_TMP || os.tmpdir(), 'feedback-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const root = path.join(dir, 'user-feedback/kibana');
  fs.mkdirSync(path.join(root, 'pipeline'), { recursive: true });
  for (const name of fs.readdirSync(here).filter(n => n.endsWith('.mjs') && !n.endsWith('.test.mjs'))) {
    fs.copyFileSync(path.join(here, name), path.join(root, 'pipeline', name));
  }
  return { dir, root };
}
function records(root, kind, rows) {
  const p = path.join(root, 'sources/stackoverflow', kind + '.jsonl');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, rows.map(r => JSON.stringify(r)).join('\n') + '\n');
  return p;
}
function run(root, script, args = []) {
  return spawnSync(process.execPath, [path.join(root, 'pipeline', script + '.mjs'), ...args], {
    encoding: 'utf8', env: { ...process.env, GH_TOKEN: '', GITHUB_TOKEN: '' },
  });
}
function outputFiles(root) {
  return fs.readdirSync(root, { recursive: true }).filter(p => {
    const f = path.join(root, p);
    return fs.statSync(f).isFile() && !p.startsWith('pipeline/') && !p.startsWith('sources/');
  }).map(p => fs.readFileSync(path.join(root, p), 'utf8')).join('\n');
}

// Removing admission at classifier input must make this fail: original raw text
// must never be copied into enriched records or category projections.
test('classifier protects raw imports and preserves provenance and record boundaries', t => {
  const { root } = fixture(t);
  const value = secret();
  const original = [artifact(`PASSWORD service = ${value}\nnext line`), artifact('ordinary body', { id: 'so-control' })];
  const input = records(root, 'raw', original);
  const before = fs.readFileSync(input, 'utf8');
  const result = run(root, 'classify');
  assert.equal(result.status, 0);
  const out = fs.readFileSync(path.join(root, 'sources/stackoverflow/enriched.jsonl'), 'utf8');
  assert.equal(out.includes(value), false, 'generated password reached enriched output');
  const parsed = out.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].source_url, original[0].source_url);
  assert.equal(parsed[0].author, original[0].author);
  assert.equal(parsed[1].body, 'ordinary body');
  assert.equal(fs.readFileSync(input, 'utf8'), before, 'raw input was rewritten');
});

for (const script of ['stats', 'themes', 'design-inputs']) {
  // Removing any individual reader's guard must expose the synthetic title.
  test(`${script} protects directly imported enriched records`, t => {
    const { root } = fixture(t);
    const value = secret();
    const input = records(root, 'enriched', [artifact('Kibana dashboard is slow and broken. '.repeat(5), {
      title: `password: ${value}`, labels: ['enhancement'], source: 'stackoverflow',
    })]);
    const before = fs.readFileSync(input, 'utf8');
    const result = run(root, script);
    assert.equal(result.status, 0);
    assert.equal(outputFiles(root).includes(value), false, 'credential reached projection');
    assert.equal(fs.readFileSync(input, 'utf8'), before);
  });
}

test('redacts credential syntax without discarding surrounding research text', async () => {
  const { redactRecord } = await import('./corpus-io.mjs');
  const value = secret();
  const jwt = [Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'test' })).toString('base64url'),
    Buffer.from(JSON.stringify({ sub: value })).toString('base64url'), randomBytes(16).toString('base64url')].join('.');
  const encoded = [...value].map(c => `&#x${c.charCodeAt(0).toString(16)};`).join('');
  const cases = [
    [`password: "${value}"\nkeep this line`, 'keep this line', value],
    [`{"client_secret":"${value}","other":1}`, '"other":1', value],
    [`{\\"password\\":\\"${value}\\",\\"other\\":1}`, '\\"other\\":1', value],
    [`&#112;assword&#58; &quot;${encoded}&quot;\nkeep`, 'keep', encoded],
    [`PASSWORD service = ${value}\nkeep`, 'keep', value],
    [`SERVICE_TOKEN service/name = ${value}\nkeep`, 'keep', value],
    [`xpack.security.encryptionKey: ${value}\nkeep`, 'keep', value],
    [`elasticsearch.serviceAccountToken: ${value}\nkeep`, 'keep', value],
    [`curl -u 'name:${value}' https://example.invalid/path -X GET`, ' -X GET', value],
    [`curl -uname:${value} https://example.invalid/path`, 'https://example.invalid/path', value],
    [`curl -ku name:${value} https://example.invalid/path`, 'https://example.invalid/path', value],
    [`curl -u=name:${value} https://example.invalid/path`, 'https://example.invalid/path', value],
    [`curl --user=name:${value} https://example.invalid/path`, 'https://example.invalid/path', value],
    [`curl --proxy-user "name:${value}" --oauth2-bearer ${value} https://example.invalid/path`, 'https://example.invalid/path', value],
    [`curl -H 'Authorization: Bearer ${value}' https://example.invalid/path`, 'https://example.invalid/path', value],
    [`{"Authorization":"Basic ${value}","other":1}`, '"other":1', value],
    [`https://name:${value}@example.invalid/path?ordinary=1#section`, '/path?ordinary=1#section', value],
    [`https://example.invalid/path?X-Amz-Credential=${value}%2Fscope&X-Amz-Signature=${value}&ordinary=1#access_token=${value}`, 'ordinary=1', value],
    [`https://example.invalid/path?api%5Fkey=${value}&ordinary=1`, 'ordinary=1', value],
    [`https://example.invalid/path?token=${value}&ordinary=1`, 'ordinary=1', value],
    [`token from log ${jwt}\nkeep`, 'keep', jwt],
    [`-----BEGIN PRIVATE KEY-----\n${value}\n-----END PRIVATE KEY-----\nkeep`, 'keep', value],
  ];
  for (const [body, retained, sensitive] of cases) {
    const result = redactRecord(artifact(body));
    assert.equal(result.record.body.includes(sensitive), false, 'sensitive syntax survived');
    assert.equal(result.record.body.includes(retained), true, 'surrounding content disappeared');
    const second = redactRecord(result.record);
    assert.equal(JSON.stringify(second.record), JSON.stringify(result.record), 'not idempotent');
  }
});

test('refuses ambiguous escaped quote concatenation rather than leaking a suffix', async () => {
  const { redactRecord } = await import('./corpus-io.mjs');
  const a = secret(), b = secret();
  for (const body of [`password: "${a}\\"${b}"`, `curl -u 'name:${a}'"${b}"`,
    `curl -u name:'${a}'`, `curl -u name:${a}\\ ${b}`]) {
    assert.throws(() => redactRecord(artifact(body)), error => error.category === 'unsupported-credential-value');
  }
});

test('nested authentication fields and long repeated password/header values cannot bypass record admission', async () => {
  const { redactRecord } = await import('./corpus-io.mjs');
  const value = secret();
  for (const record of [
    artifact(`curl -u name:${value}\nrepeated ${value}`),
    artifact(`{"Authorization":"Bearer ${value}"}\nrepeated ${value}`),
    artifact('ordinary body', { imported: { headers: { Authorization: `Bearer ${value}` } } }),
  ]) {
    assert.equal(JSON.stringify(redactRecord(record).record).includes(value), false);
  }
  assert.throws(() => redactRecord(artifact('ordinary body', { imported: { password: 123 } })),
    error => error.category === 'unsupported-credential-value');
});

test('ambiguous quoted and unquoted credential suffixes refuse every publication path', t => {
  const failures = [];
  for (const form of ['quote-space', 'quote-comma', 'plain-comma', 'plain-semicolon']) {
    const value = secret(), tail = secret();
    // This is valid embedded JSON. Its escaped quote is part of the password,
    // not the end of the value, even when followed by a permitted delimiter.
    const body = form.startsWith('quote-')
      ? JSON.stringify({ password: `${value}"${form === 'quote-space' ? ' ' : ','}${tail}` })
      : `elasticsearch.password: ${value}${form === 'plain-comma' ? ',' : ';'}${tail}`;
    for (const script of ['classify', 'stats', 'themes', 'design-inputs', 'sanitize']) {
      const { root, dir } = fixture(t);
      const kind = script === 'classify' || script === 'sanitize' ? 'raw' : 'enriched';
      const input = records(root, kind, [artifact(body)]);
      const before = fs.readFileSync(input, 'utf8');
      const output = path.join(dir, 'refused');
      const result = run(root, script, ['--output-root', output]);
      if (result.status === 0 || fs.existsSync(output)) failures.push({ form, script, accepted: result.status === 0 });
      assert.equal((result.stdout + result.stderr).includes(value) || (result.stdout + result.stderr).includes(tail), false);
      assert.equal(fs.readFileSync(input, 'utf8'), before);
      if (script === 'sanitize' && run(root, 'sanitize', ['--check']).status !== 1) failures.push({ form, script: 'sanitize-check' });
    }
  }
  assert.equal(failures.length, 0, JSON.stringify(failures));
});

test('handles multiline and truncated quoted values without crossing JSONL records', async () => {
  const { redactRecord } = await import('./corpus-io.mjs');
  const a = secret(), b = secret();
  for (const body of [`password: "${a}\n${b}"\nkeep`, `password: "${a}`, `curl --user 'name:${a}`]) {
    const out = redactRecord(artifact(body)).record.body;
    assert.equal(out.includes(a) || out.includes(b), false);
  }
  const ordinary = artifact('content_key: item-1\n--dns example.invalid\nversion: 8.13\nUUID identifiers are useful.');
  assert.deepEqual(redactRecord(ordinary).record, ordinary);
});

test('collector writer sanitizes existing and incoming data while keeping first-id dedupe', async t => {
  const { root } = fixture(t);
  const old = secret(), next = secret();
  const file = records(root, 'raw', [artifact(`password: ${old}`)]);
  const argv = process.argv;
  process.argv = [process.execPath, 'collect', '--source', 'none'];
  let collect;
  try { collect = await import(pathToFileURL(path.join(root, 'pipeline/collect.mjs'))); }
  finally { process.argv = argv; }
  assert.equal(typeof collect.writeBatch, 'function', 'collector does not expose its guarded persistence boundary');
  const result = collect.writeBatch(file, [artifact('replacement must be skipped'), artifact(`password: ${next}`, { id: 'so-next' })]);
  assert.deepEqual(result, { added: 1, replaced: 1 });
  const text = fs.readFileSync(file, 'utf8');
  assert.equal(text.includes(old) || text.includes(next), false);
  assert.equal(text.includes('replacement must be skipped'), false);
  collect.writeBatch(file, []);
  assert.equal(fs.readFileSync(file, 'utf8'), text);
});

test('all readers refuse unsupported or malformed imports before replacing outputs and hide parser excerpts', t => {
  for (const script of ['classify', 'stats', 'themes', 'design-inputs']) {
    const { root } = fixture(t);
    const value = secret();
    const kind = script === 'classify' ? 'raw' : 'enriched';
    const file = records(root, kind, [artifact(`password: |\n  ${value}`)]);
    const sentinel = path.join(root, script === 'classify' ? 'sources/stackoverflow/enriched.jsonl' : 'INDEX.md');
    fs.writeFileSync(sentinel, 'previous publication\n');
    for (const bad of [fs.readFileSync(file, 'utf8'), `{"body":"${value}"\n`]) {
      fs.writeFileSync(file, bad);
      const result = run(root, script);
      assert.notEqual(result.status, 0, 'unsafe import was accepted');
      assert.equal((result.stdout + result.stderr).includes(value), false);
      assert.equal(fs.readFileSync(sentinel, 'utf8'), 'previous publication\n');
    }
  }
});

test('offline export/check stages a new root and never rewrites source or existing destination', t => {
  const { root, dir } = fixture(t);
  const value = secret();
  const file = records(root, 'raw', [artifact(`password: ${value}`)]);
  records(root, 'enriched', [artifact(`password: ${value}`)]);
  const before = fs.readFileSync(file, 'utf8');
  const checked = run(root, 'sanitize', ['--check']);
  assert.equal(checked.status, 2, 'check must signal redaction needed');
  assert.equal((checked.stdout + checked.stderr).includes(value), false);
  const output = path.join(dir, 'safe-export');
  const exported = run(root, 'sanitize', ['--output-root', output]);
  assert.equal(exported.status, 0);
  const safe = fs.readFileSync(path.join(output, 'sources/stackoverflow/raw.jsonl'), 'utf8');
  assert.equal(safe.includes(value), false);
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(run(root, 'sanitize', ['--input-root', output, '--check']).status, 0);
  assert.notEqual(run(root, 'sanitize', ['--output-root', root]).status, 0);
  assert.notEqual(run(root, 'sanitize', ['--output-root', output]).status, 0);
  assert.equal(fs.readFileSync(path.join(output, 'sources/stackoverflow/raw.jsonl'), 'utf8'), safe);
  fs.appendFileSync(file, `{"body":"${value}"\n`);
  const rejectedRoot = path.join(dir, 'rejected');
  const rejected = run(root, 'sanitize', ['--output-root', rejectedRoot]);
  assert.notEqual(rejected.status, 0);
  assert.equal(fs.existsSync(rejectedRoot), false);
  assert.equal((rejected.stdout + rejected.stderr).includes(value), false);
});

test('explicit projection roots contain every generated file including legacy frontend module', t => {
  const { root, dir } = fixture(t);
  records(root, 'enriched', [artifact('Kibana dashboard slow and broken. '.repeat(5))]);
  const output = path.join(dir, 'derived');
  const result = run(root, 'design-inputs', ['--output-root', output]);
  assert.equal(result.status, 0);
  assert.equal(fs.existsSync(path.join(output, 'web/src/data/feedback-citations.js')), true);
  assert.equal(fs.existsSync(path.join(dir, 'web')), false, 'projection escaped requested root');
});

test('writer preflight and failed atomic rename leave authoritative state intact', async t => {
  const { root } = fixture(t);
  const { writeBatch, writeText } = await import('./corpus-io.mjs');
  const file = records(root, 'raw', [artifact('ordinary body')]);
  const before = fs.readFileSync(file, 'utf8');
  assert.throws(() => writeBatch(file, [artifact('password: |\n  blocked', { id: 'so-blocked' })]));
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  const directory = path.join(root, 'existing-directory');
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, 'authority'), 'unchanged');
  assert.throws(() => writeText(directory, 'replacement'));
  assert.equal(fs.readFileSync(path.join(directory, 'authority'), 'utf8'), 'unchanged');
  assert.equal(fs.readdirSync(root).some(n => n.startsWith('.corpus-')), false, 'staging file survived failure');
});
