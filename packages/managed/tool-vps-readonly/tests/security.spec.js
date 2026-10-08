import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { REMOTE_HELPER_SOURCE_FOR_TESTS, TOOL_NAMES, TOOL_SCHEMAS, validateArguments, validatePath } from '../src/index.js'

test('registers exactly the eight bounded VPS read tools and schemas', () => {
  assert.deepEqual(TOOL_NAMES, ['vps_list', 'vps_find', 'vps_read', 'vps_git_status', 'vps_git_log', 'vps_search_read', 'vps_search_content', 'vps_repo_summary'])
  assert.deepEqual(Object.keys(TOOL_SCHEMAS), TOOL_NAMES)
  assert.equal(TOOL_SCHEMAS.vps_read.max_lines.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_find.max_results.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_git_log.max_entries.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_search_read.match.type, 'string')
  assert.deepEqual(TOOL_SCHEMAS.vps_search_read.match.enum, ['exact', 'contains'])
  assert.equal(TOOL_SCHEMAS.vps_search_read.result_index.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_repo_summary.repo.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_repo_summary.max_entries.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_repo_summary.max_commits.type, 'string')
  assert.equal(TOOL_SCHEMAS.vps_search_content.pattern.required, true)
  assert.equal(Object.hasOwn(TOOL_SCHEMAS.vps_search_content.path, 'required'), false)
  assert.equal(TOOL_NAMES.some(name => /shell|write|delete|commit|reset|deploy/i.test(name)), false)
})

test('accepts only canonical absolute paths within /srv/ai-hub', () => {
  assert.equal(validatePath('/srv/ai-hub'), '/srv/ai-hub')
  assert.equal(validatePath('/srv/ai-hub/projects/example/state.json'), '/srv/ai-hub/projects/example/state.json')
  for (const path of ['/etc/passwd', '/srv/ai-hub/../etc/passwd', '/srv/ai-hub/a/../../etc', '/srv/ai-hub/x;id', '/srv/ai-hub/*.json', '/srv/ai-hub//projects', '/srv/ai-hub/./bin', '/srv/ai-hub/bin/']) {
    assert.throws(() => validatePath(path), path)
  }
})

test('rejects traversal and shell syntax from filename search', () => {
  assert.throws(() => validateArguments('vps_find', { root: '/srv/ai-hub', name: '../../etc/passwd' }))
  assert.throws(() => validateArguments('vps_find', { root: '/srv/ai-hub', name: 'x;id' }))
  assert.deepEqual(validateArguments('vps_find', { root: '/srv/ai-hub', name: 'state.json' }), {
    root: '/srv/ai-hub', name: 'state.json', max_results: 50,
  })
})

test('bounds read and Git arguments and rejects unknown tools', () => {
  assert.throws(() => validateArguments('vps_read', { path: '/srv/ai-hub/x', max_lines: 301 }))
  assert.throws(() => validateArguments('vps_git_log', { repo: '/srv/ai-hub', max_entries: 51 }))
  assert.deepEqual(validateArguments('vps_read', { path: '/srv/ai-hub/x', start_line: '1', max_lines: '20' }), {
    path: '/srv/ai-hub/x', start_line: 1, max_lines: 20,
  })
  assert.throws(() => validateArguments('vps_read', { path: '/srv/ai-hub/x', start_line: '1;id', max_lines: '20' }))
  assert.throws(() => validateArguments('shell', { command: 'id' }))
})

test('validates composed search/read arguments and rejects unsafe inputs', () => {
  const valid = { root: '/srv/ai-hub/projects', name: 'state.json', match: 'exact', result_index: '0', start_line: '1', max_lines: '20' }
  assert.deepEqual(validateArguments('vps_search_read', valid), {
    ...valid, start_line: 1, max_lines: 20,
  })
  for (const value of [
    { ...valid, root: '/etc' },
    { ...valid, root: '/srv/ai-hub/../etc' },
    { ...valid, name: 'state*.json' },
    { ...valid, name: 'x;id' },
    { ...valid, match: 'regex' },
    { ...valid, result_index: '-1' },
    { ...valid, result_index: '100' },
    { ...valid, start_line: '10001' },
    { ...valid, max_lines: '301' },
  ]) assert.throws(() => validateArguments('vps_search_read', value))
  assert.equal(validateArguments('vps_search_read', { ...valid, result_index: 'auto' }).result_index, 'auto')
})

test('validates repo summary scope and result bounds', () => {
  const valid = { repo: '/srv/ai-hub/projects/example', max_entries: '40', max_commits: '10' }
  assert.deepEqual(validateArguments('vps_repo_summary', valid), {
    repo: valid.repo, max_entries: 40, max_commits: 10,
  })
  for (const value of [
    { ...valid, repo: '/etc' },
    { ...valid, repo: '/srv/ai-hub/../etc' },
    { ...valid, repo: '/srv/ai-hub/repo;id' },
    { ...valid, repo: '/srv/ai-hub/*.git' },
    { ...valid, max_entries: '51' },
    { ...valid, max_commits: '21' },
    { ...valid, max_entries: '-1' },
  ]) assert.throws(() => validateArguments('vps_repo_summary', value))
})

test('validates bounded literal content-search inputs and rejects injection or mutation-shaped requests', () => {
  assert.deepEqual(validateArguments('vps_search_content', { pattern: 'AC-OBS-001' }), {
    pattern: 'AC-OBS-001', path: '/srv/ai-hub', max_matches: 50, max_files: 10000, max_file_bytes: 8 * 1024 * 1024,
  })
  for (const args of [
    { pattern: '' },
    { pattern: 'x\ny' },
    { pattern: 'x;id' },
    { pattern: '$(id)' },
    { pattern: 'x`id`' },
    { pattern: 'x|cat /etc/passwd' },
    { pattern: 'x'.repeat(257) },
    { pattern: 'valid', path: '/etc' },
    { pattern: 'valid', path: '/srv/ai-hub/../../etc' },
    { pattern: 'valid', max_matches: 201 },
    { pattern: 'valid', max_files: 10001 },
    { pattern: 'valid', max_file_bytes: 8 * 1024 * 1024 + 1 },
    { pattern: 'valid', max_files: '10000;touch /tmp/pwned' },
    { pattern: 'valid', command: 'rm -rf /' },
  ]) assert.throws(() => validateArguments('vps_search_content', args))
  assert.throws(() => validateArguments('python', { executable: 'python3', args: ['-c', 'id'] }))
  assert.throws(() => validateArguments('vps_write', { path: '/srv/ai-hub/x', content: 'mutate' }))
})

test('remote content search returns bounded literal matches and skips binary, oversized, and symlink files', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-content-search-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const outside = path.join(path.dirname(temp), `${path.basename(temp)}-outside.txt`)
  writeFileSync(outside, 'needle outside\n')
  t.after(() => rmSync(outside, { force: true }))
  mkdirSync(path.join(temp, 'nested'))
  writeFileSync(path.join(temp, 'nested', 'match.txt'), 'first needle\nsecond needle\n')
  writeFileSync(path.join(temp, 'nested', 'z-long-line.txt'), `${'x'.repeat(1500)}needle${'y'.repeat(600)}\n`)
  writeFileSync(path.join(temp, 'binary.bin'), Buffer.from([0, 1, 2, 3]))
  writeFileSync(path.join(temp, 'oversized.txt'), 'needle'.repeat(1000))
  symlinkSync(outside, path.join(temp, 'linked.txt'))
  symlinkSync(outside, path.join(temp, 'escape-dir'))

  const valid = runRemote(temp, 'vps_search_content', {
    path: temp, pattern: 'needle', max_matches: 1, max_files: 20, max_file_bytes: 4096,
  })
  assert.equal(valid.status, 0)
  assert.equal(valid.result.matches.length, 1)
  assert.equal(valid.result.matches[0].path, path.join(temp, 'nested', 'match.txt'))
  assert.equal(valid.result.matches[0].line_number, 1)
  assert.match(valid.result.matches[0].line, /needle/)
  assert.equal(valid.result.truncated.matches, true)
  assert.equal(valid.result.skipped_binary, 1)
  assert.equal(valid.result.skipped_oversized, 1)
  assert.equal(valid.result.matches.every(match => match.path === temp || match.path.startsWith(temp + path.sep)), true)

  const oneFile = runRemote(temp, 'vps_search_content', {
    path: temp, pattern: 'needle', max_matches: 20, max_files: 1, max_file_bytes: 4096,
  })
  assert.equal(oneFile.status, 0)
  assert.equal(oneFile.result.files_examined, 1)
  assert.equal(oneFile.result.truncated.files, true)

  const boundedLine = runRemote(temp, 'vps_search_content', {
    path: temp, pattern: 'needle', max_matches: 20, max_files: 20, max_file_bytes: 4096,
  })
  const longMatch = boundedLine.result.matches.find(match => match.path === path.join(temp, 'nested', 'z-long-line.txt'))
  assert.equal(longMatch.line_truncated, true)
  assert.ok(Buffer.byteLength(longMatch.line, 'utf8') <= 1028)

  const invalidPath = runRemote(temp, 'vps_search_content', { path: path.join(temp, '..'), pattern: 'needle' })
  assert.equal(invalidPath.status, 2)
  assert.match(invalidPath.result.error, /must remain under|resolves outside/)
})

test('remote content search enforces remote argument bounds and rejects control or shell syntax', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-content-search-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  for (const arguments_ of [
    { path: temp, pattern: 'x\ncommand' },
    { path: temp, pattern: 'x;id' },
    { path: temp, pattern: '$(id)' },
    { path: temp, pattern: 'x', max_matches: 201 },
    { path: temp, pattern: 'x', max_files: 10001 },
    { path: temp, pattern: 'x', max_file_bytes: 8 * 1024 * 1024 + 1 },
  ]) {
    const result = runRemote(temp, 'vps_search_content', arguments_)
    assert.equal(result.status, 2)
  }
  assert.equal(TOOL_NAMES.some(name => /shell|write|delete|commit|reset|deploy/i.test(name)), false)
})

function runRemote(approved, tool, arguments_) {
  const source = REMOTE_HELPER_SOURCE_FOR_TESTS.replace("APPROVED_ROOT = '/srv/ai-hub'", `APPROVED_ROOT = '${approved}'`)
  const child = spawnSync('python3', ['-I', '-B', '-c', source], {
    input: JSON.stringify({ tool, arguments: arguments_ }), encoding: 'utf8',
  })
  return { status: child.status, result: JSON.parse(child.stdout) }
}

test('remote composed search/read supports exact selection, sorted ambiguity, and bounded text', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-search-read-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  mkdirSync(path.join(temp, 'b'))
  mkdirSync(path.join(temp, 'a'))
  writeFileSync(path.join(temp, 'unique.txt'), 'one\ntwo\nthree\n')
  writeFileSync(path.join(temp, 'a', 'state.json'), '{"source":"a"}\n')
  writeFileSync(path.join(temp, 'b', 'state.json'), '{"source":"b"}\n')
  const base = { root: temp, match: 'exact', result_index: 'auto', start_line: 1, max_lines: 2 }

  const exact = runRemote(temp, 'vps_search_read', { ...base, name: 'unique.txt' })
  assert.equal(exact.status, 0)
  assert.equal(exact.result.status, 'ok')
  assert.equal(exact.result.selected_path, path.join(temp, 'unique.txt'))
  assert.equal(exact.result.content, 'one\ntwo')
  assert.equal(exact.result.lines, 2)

  const ambiguous = runRemote(temp, 'vps_search_read', { ...base, name: 'state.json' })
  assert.equal(ambiguous.status, 0)
  assert.equal(ambiguous.result.status, 'ambiguous')
  assert.deepEqual(ambiguous.result.candidates, [path.join(temp, 'a', 'state.json'), path.join(temp, 'b', 'state.json')])
  assert.equal(Object.hasOwn(ambiguous.result, 'content'), false)

  const selected = runRemote(temp, 'vps_search_read', { ...base, name: 'state', match: 'contains', result_index: '1' })
  assert.equal(selected.status, 0)
  assert.equal(selected.result.selected_path, path.join(temp, 'b', 'state.json'))
  assert.equal(selected.result.content, '{"source":"b"}')

  const invalidIndex = runRemote(temp, 'vps_search_read', { ...base, name: 'state.json', result_index: '2' })
  assert.equal(invalidIndex.status, 2)
  assert.match(invalidIndex.result.error, /does not identify/)
})

test('remote composed search/read rejects binary files and symlink results', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-search-read-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const outside = path.join(path.dirname(temp), `${path.basename(temp)}-outside.bin`)
  writeFileSync(outside, 'outside')
  t.after(() => rmSync(outside, { force: true }))
  writeFileSync(path.join(temp, 'image.bin'), Buffer.from([0, 1, 2, 3]))
  symlinkSync(outside, path.join(temp, 'linked.txt'))
  const base = { root: temp, match: 'exact', result_index: 'auto', start_line: 1, max_lines: 10 }
  const binary = runRemote(temp, 'vps_search_read', { ...base, name: 'image.bin' })
  assert.equal(binary.status, 0)
  assert.equal(binary.result.error, 'not_text_file')
  const linked = runRemote(temp, 'vps_search_read', { ...base, name: 'linked.txt' })
  assert.equal(linked.result.status, 'not_found')
  const escapedRoot = runRemote(temp, 'vps_search_read', { ...base, root: outside, name: 'outside.bin' })
  assert.equal(escapedRoot.status, 2)
  assert.match(escapedRoot.result.error, /must remain under|resolves outside/)
})

test('remote helper rejects symlink escape before listing a target', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-readonly-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const approved = path.join(temp, 'approved')
  const outside = path.join(temp, 'outside')
  mkdirSync(approved)
  mkdirSync(outside)
  symlinkSync(outside, path.join(approved, 'escape'))
  const source = REMOTE_HELPER_SOURCE_FOR_TESTS.replace("APPROVED_ROOT = '/srv/ai-hub'", `APPROVED_ROOT = '${approved}'`)
  const child = spawnSync('python3', ['-I', '-B', '-c', source], {
    input: JSON.stringify({ tool: 'vps_list', arguments: { path: path.join(approved, 'escape') } }),
    encoding: 'utf8',
  })
  assert.equal(child.status, 2, child.stderr)
  assert.match(JSON.parse(child.stdout).error, /resolves outside/)
})

test('remote repo summary handles non-Git directories and rejects files and symlink escapes', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-repo-summary-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const repo = path.join(temp, 'plain')
  mkdirSync(repo)
  mkdirSync(path.join(repo, 'src'))
  writeFileSync(path.join(repo, 'README.md'), 'metadata contents are not returned')
  writeFileSync(path.join(temp, 'not-a-directory'), 'plain file')
  const args = { repo, max_entries: 50, max_commits: 10 }
  const plain = runRemote(temp, 'vps_repo_summary', args)
  assert.equal(plain.status, 0)
  assert.equal(plain.result.exists, true)
  assert.equal(plain.result.is_git_repo, false)
  assert.equal(plain.result.branch, null)
  assert.equal(plain.result.head, null)
  assert.equal(plain.result.dirty, null)
  assert.deepEqual(plain.result.entries.map(entry => entry.name), ['README.md', 'src'])
  assert.deepEqual(plain.result.metadata_files, ['README.md'])
  assert.equal(Object.hasOwn(plain.result, 'content'), false)
  assert.throws(() => validateArguments('vps_repo_summary', { ...args, repo: '/srv/ai-hub/../etc' }))

  const nonDirectory = runRemote(temp, 'vps_repo_summary', { ...args, repo: path.join(temp, 'not-a-directory') })
  assert.equal(nonDirectory.status, 2)
  assert.match(nonDirectory.result.error, /must be a directory/)

  const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-repo-outside-')))
  t.after(() => rmSync(outside, { recursive: true, force: true }))
  symlinkSync(outside, path.join(temp, 'escape'))
  const escaped = runRemote(temp, 'vps_repo_summary', { ...args, repo: path.join(temp, 'escape') })
  assert.equal(escaped.status, 2)
  assert.match(escaped.result.error, /resolves outside/)
})

test('remote repo summary rejects unsafe Git metadata before invoking Git', t => {
  const temp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dsh-vps-repo-summary-')))
  t.after(() => rmSync(temp, { recursive: true, force: true }))
  const repo = path.join(temp, 'repo')
  mkdirSync(path.join(repo, '.git'), { recursive: true })
  writeFileSync(path.join(repo, '.git', 'config'), '[core]\n repositoryformatversion = 0\n[include]\n path = /tmp/untrusted-git-config\n')
  const result = runRemote(temp, 'vps_repo_summary', { repo, max_entries: 50, max_commits: 10 })
  assert.equal(result.status, 2)
  assert.match(result.result.error, /includes are not allowed/)
})
