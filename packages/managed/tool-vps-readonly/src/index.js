/** Bounded read-only AI Hub VPS tools for the local-managed SDK profile. */
import { spawn } from 'node:child_process'
import { defineTool } from '../../../core/tools/lib/index.js'

const SSH_TARGET = 'private@167.233.253.110'
const APPROVED_ROOT = '/srv/ai-hub'
const MAX_OUTPUT_BYTES = 64 * 1024

/** @type {readonly ['vps_list', 'vps_find', 'vps_read', 'vps_git_status', 'vps_git_log', 'vps_search_read', 'vps_repo_summary']} */
export const TOOL_NAMES = Object.freeze([
  'vps_list',
  'vps_find',
  'vps_read',
  'vps_git_status',
  'vps_git_log',
  'vps_search_read',
  'vps_repo_summary',
])

/** @type {Readonly<Record<string, Record<string, { type: string; required: boolean; description: string; enum?: readonly string[] }>>>} */
export const TOOL_SCHEMAS = Object.freeze({
  vps_list: {
    path: { type: 'string', required: true, description: 'Absolute directory path under /srv/ai-hub.' },
  },
  vps_find: {
    root: { type: 'string', required: true, description: 'Absolute search root under /srv/ai-hub.' },
    name: { type: 'string', required: true, description: 'Literal, case-sensitive filename substring; glob syntax is not accepted.' },
    max_results: { type: 'string', required: true, description: 'Decimal integer from 1 to 100.' },
  },
  vps_read: {
    path: { type: 'string', required: true, description: 'Absolute text-file path under /srv/ai-hub.' },
    start_line: { type: 'string', required: true, description: 'One-based decimal integer from 1 to 10,000.' },
    max_lines: { type: 'string', required: true, description: 'Decimal integer from 1 to 300.' },
  },
  vps_git_status: {
    repo: { type: 'string', required: true, description: 'Absolute Git repository path under /srv/ai-hub.' },
  },
  vps_git_log: {
    repo: { type: 'string', required: true, description: 'Absolute Git repository path under /srv/ai-hub.' },
    max_entries: { type: 'string', required: true, description: 'Decimal integer from 1 to 50.' },
  },
  vps_search_read: {
    root: { type: 'string', required: true, description: 'Absolute search root under /srv/ai-hub.' },
    name: { type: 'string', required: true, description: 'Literal filename to match; glob and regex syntax are not accepted.' },
    match: { type: 'string', required: true, enum: ['exact', 'contains'], description: 'Match the full filename or a literal filename substring.' },
    result_index: { type: 'string', required: true, description: 'Use auto only when exactly one match exists, or a zero-based decimal result index from 0 to 99.' },
    start_line: { type: 'string', required: true, description: 'One-based decimal integer from 1 to 10,000.' },
    max_lines: { type: 'string', required: true, description: 'Decimal integer from 1 to 300.' },
  },
  vps_repo_summary: {
    repo: { type: 'string', required: true, description: 'Absolute repository directory under /srv/ai-hub.' },
    max_entries: { type: 'string', required: true, description: 'Decimal integer from 1 to 50.' },
    max_commits: { type: 'string', required: true, description: 'Decimal integer from 1 to 20.' },
  },
})

const PATH_SAFE = /^[A-Za-z0-9._/-]+$/
const NAME_SAFE = /^[A-Za-z0-9._ -]{1,128}$/

function assertBoundedInteger(value, name, fallback, max) {
  let selected = value === undefined ? fallback : value
  if (typeof selected === 'string') {
    if (!/^(0|[1-9][0-9]*)$/.test(selected)) throw new Error(`${name} must be a decimal integer`)
    selected = Number(selected)
  }
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > max) {
    throw new Error(`${name} must be an integer between 1 and ${max}`)
  }
  return selected
}

/**
 * @param {string} value
 * @param {string} [name]
 * @returns {string}
 */
export function validatePath(value, name = 'path') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    throw new Error(`${name} must be a non-empty absolute path under ${APPROVED_ROOT}`)
  }
  if (!PATH_SAFE.test(value) || value.includes('..') || value.includes('//')) {
    throw new Error(`${name} contains unsupported path characters`)
  }
  if (value !== APPROVED_ROOT && !value.startsWith(`${APPROVED_ROOT}/`)) {
    throw new Error(`${name} must remain under ${APPROVED_ROOT}`)
  }
  if (value !== APPROVED_ROOT && (value.endsWith('/') || value.split('/').includes('.'))) {
    throw new Error(`${name} must be a canonical path`)
  }
  return value
}

/**
 * @param {string} name
 * @param {Record<string, unknown>} args
 * @returns {Record<string, unknown>}
 */
export function validateArguments(name, args) {
  if (!TOOL_NAMES.includes(name) || args === null || typeof args !== 'object' || Array.isArray(args)) {
    throw new Error('unknown VPS read tool or invalid arguments')
  }
  switch (name) {
    case 'vps_list':
      return { path: validatePath(args.path) }
    case 'vps_find':
      if (typeof args.name !== 'string' || !NAME_SAFE.test(args.name) || args.name.includes('..')) {
        throw new Error('name must be a literal filename substring without glob or shell syntax')
      }
      return {
        root: validatePath(args.root, 'root'),
        name: args.name,
        max_results: assertBoundedInteger(args.max_results, 'max_results', 50, 100),
      }
    case 'vps_read':
      return {
        path: validatePath(args.path),
        start_line: assertBoundedInteger(args.start_line, 'start_line', 1, 10000),
        max_lines: assertBoundedInteger(args.max_lines, 'max_lines', 200, 300),
      }
    case 'vps_git_status':
      return { repo: validatePath(args.repo, 'repo') }
    case 'vps_git_log':
      return {
        repo: validatePath(args.repo, 'repo'),
        max_entries: assertBoundedInteger(args.max_entries, 'max_entries', 20, 50),
      }
    case 'vps_search_read': {
      if (typeof args.name !== 'string' || !NAME_SAFE.test(args.name) || args.name.includes('..')) {
        throw new Error('name must be a literal filename without glob or shell syntax')
      }
      if (!['exact', 'contains'].includes(args.match)) throw new Error('match must be exact or contains')
      const resultIndex = args.result_index === undefined ? 'auto' : args.result_index
      if (typeof resultIndex !== 'string' || (resultIndex !== 'auto' && !/^(0|[1-9][0-9]*)$/.test(resultIndex))) {
        throw new Error('result_index must be auto or a zero-based decimal integer')
      }
      if (resultIndex !== 'auto' && Number(resultIndex) > 99) throw new Error('result_index must be between 0 and 99')
      return {
        root: validatePath(args.root, 'root'),
        name: args.name,
        match: args.match,
        result_index: resultIndex,
        start_line: assertBoundedInteger(args.start_line, 'start_line', 1, 10000),
        max_lines: assertBoundedInteger(args.max_lines, 'max_lines', 200, 300),
      }
    }
    case 'vps_repo_summary':
      return {
        repo: validatePath(args.repo, 'repo'),
        max_entries: assertBoundedInteger(args.max_entries, 'max_entries', 50, 50),
        max_commits: assertBoundedInteger(args.max_commits, 'max_commits', 10, 20),
      }
    default:
      throw new Error('unknown VPS read tool')
  }
}

// This program is fixed package code. Only JSON request data is sent over SSH stdin.
const REMOTE_PROGRAM = String.raw`
import heapq, json, os, posixpath, re, subprocess, sys, time

APPROVED_ROOT = '/srv/ai-hub'
MAX_BYTES = 65536
PATH_SAFE = re.compile(r'^[A-Za-z0-9._/-]+$')
NAME_SAFE = re.compile(r'^[A-Za-z0-9._ -]{1,128}$')

def fail(message):
    raise ValueError(message)

def checked_path(value, field):
    if not isinstance(value, str) or not value or len(value) > 4096:
        fail(field + ' must be a non-empty absolute path under ' + APPROVED_ROOT)
    if not PATH_SAFE.fullmatch(value) or '..' in value or '//' in value:
        fail(field + ' contains unsupported path characters')
    if value != APPROVED_ROOT and not value.startswith(APPROVED_ROOT + '/'):
        fail(field + ' must remain under ' + APPROVED_ROOT)
    if posixpath.normpath(value) != value:
        fail(field + ' must be a canonical path')
    root = os.path.realpath( APPROVED_ROOT )
    actual = os.path.realpath(value)
    if actual != root and not actual.startswith(root + os.sep):
        fail(field + ' resolves outside ' + APPROVED_ROOT)
    return actual

def bounded(value):
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) <= MAX_BYTES:
        return raw
    for key in ('entries', 'results', 'candidates', 'lines', 'recent_commits', 'commits'):
        rows = value.get(key)
        if isinstance(rows, list):
            while rows and len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_BYTES:
                rows.pop()
                truncation = value.get('truncated')
                if isinstance(truncation, dict):
                    truncation['commits' if key in ('recent_commits', 'commits') else 'entries'] = True
                else:
                    value['truncated'] = True
            raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(raw) <= MAX_BYTES:
                return raw
    for key in ('git_status', 'content', 'output', 'error'):
        text = value.get(key)
        if isinstance(text, str):
            value[key] = text.encode('utf-8')[:MAX_BYTES // 4].decode('utf-8', 'ignore')
            truncation = value.get('truncated')
            if isinstance(truncation, dict):
                truncation['status' if key == 'git_status' else 'entries'] = True
            else:
                value['truncated'] = True
            raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if len(raw) <= MAX_BYTES:
                return raw
    return json.dumps({'error': 'serialized result exceeded the safety bound', 'truncated': True}).encode('utf-8')

def checked_limit(value, default, maximum, field):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        fail(field + ' is outside the allowed range')
    return value

def read_file(path, start, count):
    rows = []
    total = 0
    truncated = False
    with open(path, 'rb') as stream:
        if b'\x00' in stream.read(8192):
            fail('binary files are not supported')
        stream.seek(0)
        line_number = 0
        while line_number < start + count - 1:
            raw = stream.readline(MAX_BYTES // 2 + 1)
            if not raw:
                break
            line_number += 1
            if line_number < start:
                continue
            if total + len(raw) > MAX_BYTES // 2:
                raw = raw[:max(0, MAX_BYTES // 2 - total)]
                truncated = True
            if b'\x00' in raw:
                fail('binary files are not supported')
            rows.append(raw.decode('utf-8', 'replace').rstrip('\r\n'))
            total += len(raw)
            if truncated:
                break
        if not truncated and len(rows) == count and stream.read(1):
            truncated = True
    return {'path': path, 'start_line': start, 'lines': rows, 'truncated': truncated}

def find_files(root, name, limit, match='contains', regular_only=False):
    if not isinstance(name, str) or not NAME_SAFE.fullmatch(name) or '..' in name:
        fail('name must be a literal filename substring without glob or shell syntax')
    results = []
    inaccessible = 0
    truncated = False
    deadline = time.monotonic() + 20
    scanned = 0
    walk_errors = [0]
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=lambda _error: walk_errors.__setitem__(0, walk_errors[0] + 1)):
        if time.monotonic() >= deadline or scanned >= 100000:
            truncated = True
            break
        dirs.sort()
        files.sort()
        kept = []
        for dirname in dirs:
            scanned += 1
            candidate = os.path.join(current, dirname)
            try:
                resolved = os.path.realpath(candidate)
                if os.path.islink(candidate) or not (resolved == APPROVED_ROOT or resolved.startswith(APPROVED_ROOT + os.sep)):
                    continue
                kept.append(dirname)
            except OSError:
                inaccessible += 1
        dirs[:] = kept
        for filename in files:
            scanned += 1
            if time.monotonic() >= deadline or scanned >= 100000:
                truncated = True
                break
            if (filename != name if match == 'exact' else name not in filename):
                continue
            candidate = os.path.join(current, filename)
            try:
                resolved = os.path.realpath(candidate)
                if not (resolved == APPROVED_ROOT or resolved.startswith(APPROVED_ROOT + os.sep)):
                    continue
                if regular_only and (os.path.islink(candidate) or not os.path.isfile(candidate) or not os.access(candidate, os.R_OK)):
                    continue
                results.append(candidate if regular_only else resolved)
            except OSError:
                inaccessible += 1
            if len(results) >= limit:
                truncated = True
                break
        if truncated:
            break
    results.sort()
    return {'root': root, 'name': name, 'results': results, 'truncated': truncated, 'inaccessible_entries': inaccessible + walk_errors[0]}

def search_read(root, name, match, result_index, start, count):
    if not isinstance(name, str) or not NAME_SAFE.fullmatch(name) or '..' in name:
        fail('name must be a literal filename without glob or shell syntax')
    if match not in ('exact', 'contains'):
        fail('match must be exact or contains')
    if result_index != 'auto' and (not isinstance(result_index, str) or not re.fullmatch(r'(0|[1-9][0-9]*)', result_index) or int(result_index) > 99):
        fail('result_index must be auto or a zero-based decimal integer from 0 to 99')
    found = find_files(root, name, 100, match, regular_only=True)
    candidates = found['results']
    metadata = {'root': root, 'query': name, 'match': match, 'match_count': len(candidates), 'truncated': found['truncated']}
    if result_index == 'auto':
        if len(candidates) == 0:
            return dict(metadata, status='not_found', candidates=[])
        if len(candidates) != 1 or found['truncated']:
            return dict(metadata, status='ambiguous', candidates=candidates, selected_index=None)
        selected = 0
    else:
        selected = int(result_index)
        if selected >= len(candidates):
            fail('result_index does not identify a returned match')
    selected_path = candidates[selected]
    if os.path.islink(selected_path):
        fail('selected path is a symlink')
    resolved = checked_path(selected_path, 'selected_path')
    if resolved != selected_path or not os.path.isfile(selected_path) or not os.access(selected_path, os.R_OK):
        fail('selected path is not a readable regular file')
    try:
        excerpt = read_file(selected_path, start, count)
    except ValueError as error:
        if 'binary files are not supported' in str(error):
            return dict(metadata, status='rejected', error='not_text_file', selected_path=selected_path)
        raise
    lines = excerpt.pop('lines')
    content = '\n'.join(lines)
    return dict(metadata, status='ok', selected_index=selected, selected_path=selected_path,
                start_line=start, lines=len(lines),
                truncated=found['truncated'] or excerpt['truncated'], content=content)

def checked_git_dir(repo):
    git_dir = os.path.join(repo, '.git')
    if os.path.islink(git_dir) or not os.path.isdir(git_dir):
        fail('repo must use an in-root .git directory; worktrees are not supported')
    actual = os.path.realpath(git_dir)
    if not (actual == APPROVED_ROOT or actual.startswith(APPROVED_ROOT + os.sep)):
        fail('Git metadata resolves outside ' + APPROVED_ROOT)
    for current, dirs, files in os.walk(actual, topdown=True, followlinks=False):
        for name in dirs + files:
            if os.path.islink(os.path.join(current, name)):
                fail('Git metadata contains a symlink; refusing to read it')
    config = os.path.join(actual, 'config')
    try:
        raw_config = open(config, 'rb').read(65537)
    except OSError:
        fail('Git config is not readable')
    if len(raw_config) > 65536:
        fail('Git config exceeds the safety limit')
    if re.search(rb'^\s*\[(?:include|includeIf)(?:\s|\])', raw_config, re.M | re.I) or re.search(rb'^\s*path\s*=', raw_config, re.M | re.I):
        fail('Git config includes are not allowed')
    alternates = os.path.join(actual, 'objects', 'info', 'alternates')
    if os.path.exists(alternates):
        fail('Git object alternates are not allowed')
    return actual

def git(repo, operation, limit=None, output_limit=MAX_BYTES // 2):
    git_dir = checked_git_dir(repo)
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'GIT_PAGER': 'cat', 'GIT_OPTIONAL_LOCKS': '0'}
    base = ['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
            '--no-optional-locks', '--git-dir=' + git_dir, '--work-tree=' + repo]
    if operation == 'status':
        argv = base + ['status', '--short', '--branch', '--untracked-files=no']
    elif operation == 'log':
        argv = base + ['--no-pager', 'log', '--format=%h%x09%ad%x09%s', '--date=short', '-n', str(limit)]
    elif operation == 'branch':
        argv = base + ['branch', '--show-current']
    elif operation == 'head':
        argv = base + ['rev-parse', '--verify', 'HEAD']
    else:
        fail('unsupported fixed Git inspection operation')
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    import selectors, time
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(proc.stderr, selectors.EVENT_READ, 'stderr')
    output = bytearray()
    error = bytearray()
    truncated = False
    deadline = time.monotonic() + 20
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            selector.close()
            proc.wait()
            fail('Git read operation timed out')
        for key, _ in selector.select(remaining):
            chunk = os.read(key.fileobj.fileno(), 4096)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            target = output if key.data == 'stdout' else error
            maximum = output_limit if key.data == 'stdout' else 4096
            if len(target) + len(chunk) > maximum:
                target.extend(chunk[:maximum - len(target)])
                if key.data == 'stdout':
                    truncated = True
                    proc.kill()
                continue
            target.extend(chunk)
    proc.wait()
    selector.close()
    if proc.returncode:
        fail('Git read operation failed: ' + bytes(error[:1024]).decode('utf-8', 'replace'))
    return {'repo': repo, 'output': bytes(output).decode('utf-8', 'replace'), 'truncated': truncated}

def list_directory(path, limit=200):
    deadline = time.monotonic() + 10
    timed_out = [False]
    with os.scandir(path) as stream:
        def candidates():
            for entry in stream:
                if time.monotonic() >= deadline:
                    timed_out[0] = True
                    break
                yield entry
        selected = heapq.nsmallest(limit + 1, candidates(), key=lambda item: item.name)
    truncated = timed_out[0] or len(selected) > limit
    entries = []
    for entry in selected[:limit]:
        try:
            entries.append({'name': entry.name, 'kind': 'directory' if entry.is_dir(follow_symlinks=False) else 'file' if entry.is_file(follow_symlinks=False) else 'other', 'symlink': entry.is_symlink()})
        except OSError:
            entries.append({'name': entry.name, 'kind': 'other', 'symlink': entry.is_symlink()})
    return entries, truncated

def repo_summary(repo, max_entries, max_commits):
    if not os.path.exists(repo):
        return {'repo': repo, 'exists': False, 'is_git_repo': False, 'branch': None, 'head': None,
                'dirty': None, 'entries': [], 'git_status': None, 'recent_commits': [],
                'metadata_files': [], 'truncated': {'entries': False, 'status': False, 'commits': False}}
    if not os.path.isdir(repo):
        fail('repo must be a directory')
    entries, entries_truncated = list_directory(repo, max_entries)
    known_metadata = ('README.md', 'pyproject.toml', 'package.json', 'Cargo.toml', 'go.mod', 'Makefile', 'Dockerfile')
    metadata_files = [name for name in known_metadata
                      if os.path.isfile(os.path.join(repo, name)) and not os.path.islink(os.path.join(repo, name))]
    git_dir = os.path.join(repo, '.git')
    base = {'repo': repo, 'exists': True, 'is_git_repo': False, 'branch': None, 'head': None,
            'dirty': None, 'entries': entries, 'git_status': None, 'recent_commits': [],
            'metadata_files': metadata_files, 'truncated': {'entries': entries_truncated, 'status': False, 'commits': False}}
    if not os.path.lexists(git_dir):
        return base
    # An existing but unsafe or unsupported .git object must fail closed.
    checked_git_dir(repo)
    status = git(repo, 'status', output_limit=MAX_BYTES // 4)
    branch = git(repo, 'branch', output_limit=1024)['output'].strip()
    head = git(repo, 'head', output_limit=1024)['output'].strip()
    log = git(repo, 'log', max_commits + 1, output_limit=MAX_BYTES // 4)
    commits = []
    for line in log['output'].splitlines():
        fields = line.split('\t', 2)
        if len(fields) == 3:
            commits.append({'hash': fields[0], 'date': fields[1], 'subject': fields[2]})
    commits_truncated = log['truncated'] or len(commits) > max_commits
    commits = commits[:max_commits]
    status_text = status['output'].rstrip()
    dirty = None if status['truncated'] else any(line and not line.startswith('##') for line in status_text.splitlines())
    base.update({
        'is_git_repo': True,
        'branch': branch or None,
        'head': head or None,
        'dirty': dirty,
        'git_status': status_text,
        'recent_commits': commits,
        'truncated': {'entries': entries_truncated, 'status': status['truncated'], 'commits': commits_truncated},
        'git_status_scope': 'tracked files only; untracked files are omitted',
    })
    return base

def main():
    request = json.load(sys.stdin)
    op = request.get('tool')
    args = request.get('arguments')
    if not isinstance(args, dict):
        fail('invalid arguments')
    if op == 'vps_list':
        path = checked_path(args.get('path'), 'path')
        if not os.path.isdir(path):
            fail('path is not a directory')
        entries, truncated = list_directory(path)
        return {'path': path, 'entries': entries, 'truncated': truncated}
    if op == 'vps_find':
        root = checked_path(args.get('root'), 'root')
        if not os.path.isdir(root):
            fail('root is not a directory')
        return find_files(root, args.get('name'), checked_limit(args.get('max_results'), 50, 100, 'max_results'))
    if op == 'vps_search_read':
        root = checked_path(args.get('root'), 'root')
        if not os.path.isdir(root):
            fail('root is not a directory')
        start = checked_limit(args.get('start_line'), 1, 10000, 'start_line')
        count = checked_limit(args.get('max_lines'), 200, 300, 'max_lines')
        return search_read(root, args.get('name'), args.get('match'), args.get('result_index', 'auto'), start, count)
    if op == 'vps_read':
        path = checked_path(args.get('path'), 'path')
        if not os.path.isfile(path):
            fail('path is not a regular file')
        start = checked_limit(args.get('start_line'), 1, 1000000, 'start_line')
        count = checked_limit(args.get('max_lines'), 200, 300, 'max_lines')
        return read_file(path, start, count)
    if op in ('vps_git_status', 'vps_git_log'):
        repo = checked_path(args.get('repo'), 'repo')
        return git(repo, 'status') if op == 'vps_git_status' else git(repo, 'log', checked_limit(args.get('max_entries'), 20, 50, 'max_entries'))
    if op == 'vps_repo_summary':
        repo = checked_path(args.get('repo'), 'repo')
        max_entries = checked_limit(args.get('max_entries'), 50, 50, 'max_entries')
        max_commits = checked_limit(args.get('max_commits'), 10, 20, 'max_commits')
        return repo_summary(repo, max_entries, max_commits)
    fail('unknown VPS read tool')

try:
    result = main()
    sys.stdout.buffer.write(bounded(result) + b'\n')
except Exception as error:
    sys.stdout.buffer.write(bounded({'error': str(error)[:2048]}) + b'\n')
    sys.exit(2)
`

export const REMOTE_HELPER_SOURCE_FOR_TESTS = REMOTE_PROGRAM

const REMOTE_COMMAND = `python3 -I -B -c 'import base64;exec(base64.b64decode("${Buffer.from(REMOTE_PROGRAM).toString('base64')}"))'`

function createDefinition(name, description, parameters) {
  return defineTool({
    name,
    description,
    parameters,
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute: async args => {
      const safeArgs = validateArguments(name, args)
      const request = JSON.stringify({ tool: name, arguments: safeArgs })
      try {
        const stdout = await runSsh(request)
        const result = JSON.parse(stdout)
        if (result.error) throw new Error(result.error)
        return JSON.stringify(result)
      } catch (error) {
        throw new Error(`VPS read-only operation failed: ${error.message}`)
      }
    },
  })
}

function runSsh(request) {
  return new Promise((resolve, reject) => {
    const child = spawn('ssh', [
      '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=30',
      SSH_TARGET, REMOTE_COMMAND,
    ], { stdio: ['pipe', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish(new Error('SSH read operation timed out'))
    }, 30000)
    child.once('error', error => finish(error))
    child.stdin.once('error', error => finish(error))
    child.stdout.on('data', chunk => {
      stdoutBytes += chunk.length
      if (stdoutBytes > 96 * 1024) {
        child.kill('SIGKILL')
        finish(new Error('VPS response exceeded 96 KiB'))
        return
      }
      stdout.push(chunk)
    })
    child.stderr.on('data', chunk => {
      const remaining = 4096 - stderrBytes
      if (remaining > 0) {
        const bounded = chunk.subarray(0, remaining)
        stderr.push(bounded)
        stderrBytes += bounded.length
      }
    })
    child.once('close', (code, signal) => {
      if (code !== 0) {
        finish(new Error(`SSH exited ${code ?? signal}: ${Buffer.concat(stderr).toString('utf8')}`))
        return
      }
      finish(undefined, Buffer.concat(stdout).toString('utf8'))
    })
    child.stdin.end(request)
  })
}

const DEFINITIONS = [
  createDefinition('vps_list', 'List at most 200 entries in a directory under /srv/ai-hub. Symlink directories are not followed.', TOOL_SCHEMAS.vps_list),
  createDefinition('vps_find', 'Find filenames containing a literal substring under /srv/ai-hub. At most 100 results; symlink directories are not followed.', TOOL_SCHEMAS.vps_find),
  createDefinition('vps_read', 'Read at most 300 bounded lines from a text file under /srv/ai-hub.', TOOL_SCHEMAS.vps_read),
  createDefinition('vps_git_status', 'Read bounded Git status for a repository under /srv/ai-hub; untracked files and optional index locks are omitted.', TOOL_SCHEMAS.vps_git_status),
  createDefinition('vps_git_log', 'Read at most 50 recent commits from a repository under /srv/ai-hub.', TOOL_SCHEMAS.vps_git_log),
  createDefinition('vps_search_read', 'Search filenames under /srv/ai-hub and read a bounded excerpt from one exactly selected regular text file. Use result_index auto only for a unique match; otherwise select a zero-based index from the returned candidates.', TOOL_SCHEMAS.vps_search_read),
  createDefinition('vps_repo_summary', 'Return a bounded read-only overview of one repository under /srv/ai-hub: top-level entries, safe Git status/branch/HEAD/log, and names of selected common metadata files. No file contents are returned.', TOOL_SCHEMAS.vps_repo_summary),
]

/**
 * @param {{ tools: { register: (definition: object) => unknown } }} ctx
 * @returns {void}
 */
export function apply(ctx) {
  for (const definition of DEFINITIONS) ctx.tools.register(definition)
}

export const name = 'tool-vps-readonly'
/** @type {['tools']} */
export const inject = ['tools']
