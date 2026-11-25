import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  commitCodingSession,
  createCodingSession,
  destroyCodingSession,
  execCodingCommand,
  getCodingSessionDiff,
  listCodingApprovals,
  listCodingSessions,
  resolveCodingApproval,
  revertCodingFile,
  setCodingSessionMode,
  type CodingApproval,
  type CodingExecResponse,
  type CodingSession,
  type CodingSessionDiff
} from './api'
import CodingStudioPane, {
  buildCodingStudioPaneTree,
  CodingStudioPaneView,
  extractCodingErrorMessage,
  parseUnifiedDiffLines,
  type CodingStudioPaneViewProps
} from './components/CodingStudioPane'
import i18n, { detectInitialLanguage, LANGUAGE_STORAGE_KEY, savePreferredLanguage } from './i18n'

const SAMPLE_SESSION_PLAN: CodingSession = {
  session_id: 'wt-a1b2c3d4',
  title: 'Refactor OAuth Guard',
  repo_path: 'D:\\repo\\nachuan',
  worktree_path: 'D:\\repo\\nachuan\\.nachuan-worktrees\\wt-a1b2c3d4',
  branch: 'nachuan/refactor-oauth-guard-c3d4',
  base_ref: 'HEAD',
  mode: 'plan',
  agent_engine: 'codex',
  status: 'active',
  created_at: 1_764_050_000,
  updated_at: 1_764_050_100,
  worktree_exists: true
}

const SAMPLE_SESSION_BUILD: CodingSession = {
  ...SAMPLE_SESSION_PLAN,
  session_id: 'wt-e5f6a7b8',
  title: 'Build Mobile Approvals',
  branch: 'nachuan/build-mobile-approvals-a7b8',
  mode: 'build',
  agent_engine: 'claude-code'
}

const SAMPLE_DIFF: CodingSessionDiff = {
  session_id: 'wt-a1b2c3d4',
  branch: 'nachuan/refactor-oauth-guard-c3d4',
  mode: 'plan',
  agent_engine: 'codex',
  file_count: 2,
  total_additions: 4,
  total_deletions: 2,
  files: [
    {
      path: 'src/auth.ts',
      status: 'M',
      additions: 3,
      deletions: 2,
      diff: [
        'diff --git a/src/auth.ts b/src/auth.ts',
        '--- a/src/auth.ts',
        '+++ b/src/auth.ts',
        '@@ -10,4 +10,5 @@ export function verifyToken() {',
        ' const secret = loadSecret()',
        '-return legacyCheck(secret)',
        '-console.log("debug")',
        '+const ok = strictVerify(secret)',
        '+auditAuth(ok)',
        '+return ok'
      ].join('\n')
    },
    {
      path: 'src/notes.md',
      status: '??',
      additions: 1,
      deletions: 0,
      diff: ['--- /dev/null', '+++ b/src/notes.md', '@@ -0,0 +1,1 @@', '+Security checklist'].join(
        '\n'
      )
    }
  ]
}

const SAMPLE_PENDING_APPROVAL: CodingApproval = {
  approval_id: 'cap-9f8e7d6c5b',
  session_id: 'wt-a1b2c3d4',
  command: 'npm run build && node scripts/verify.mjs',
  reason: '包含复合管道或重定向，需桌面/手机端审批放行',
  status: 'pending',
  created_at: 1_764_050_200,
  expires_at: 1_764_050_800
}

function jsonResponse(payload: unknown, status = 200): {
  status: number
  contentType: string
  body: Uint8Array
} {
  return {
    status,
    contentType: 'application/json',
    body: Uint8Array.from(Buffer.from(JSON.stringify(payload), 'utf8'))
  }
}

function findElementByTestId(
  node: React.ReactNode,
  testId: string
): React.ReactElement<Record<string, unknown>> | null {
  if (!node || typeof node !== 'object') return null
  if (Array.isArray(node)) {
    for (const child of node) {
      const hit = findElementByTestId(child, testId)
      if (hit) return hit
    }
    return null
  }
  if (!React.isValidElement(node)) return null
  const props = node.props as Record<string, unknown>
  if (props['data-testid'] === testId) {
    return node as React.ReactElement<Record<string, unknown>>
  }
  return findElementByTestId(props.children as React.ReactNode, testId)
}

function makeViewProps(
  overrides: Partial<CodingStudioPaneViewProps> = {}
): CodingStudioPaneViewProps {
  return {
    sessions: [SAMPLE_SESSION_PLAN, SAMPLE_SESSION_BUILD],
    selectedSessionId: SAMPLE_SESSION_PLAN.session_id,
    diff: SAMPLE_DIFF,
    activeDiffFilePath: 'src/auth.ts',
    checkedFiles: new Set(['src/auth.ts']),
    approvals: [SAMPLE_PENDING_APPROVAL],
    approvalsFilter: 'pending',
    approvalNotes: {},
    repoPath: 'D:\\repo\\nachuan',
    taskTitle: 'Add worktree studio',
    baseRef: 'HEAD',
    agentEngine: 'codex',
    initialMode: 'plan',
    deleteBranchOnDestroy: true,
    commitMessage: 'feat: harden oauth guard',
    commandInput: 'git status',
    lastExecResponse: null,
    loadingSessions: false,
    loadingDiff: false,
    creatingSession: false,
    switchingMode: false,
    revertingPath: null,
    committing: false,
    destroyingSessionId: null,
    executingCommand: false,
    resolvingApprovalId: null,
    notice: '',
    error: '',
    onRefreshAll: () => undefined,
    onSelectSession: () => undefined,
    onRepoPathChange: () => undefined,
    onTaskTitleChange: () => undefined,
    onBaseRefChange: () => undefined,
    onAgentEngineChange: () => undefined,
    onInitialModeChange: () => undefined,
    onCreateSession: () => undefined,
    onToggleDeleteBranchOnDestroy: () => undefined,
    onDestroySession: () => undefined,
    onSwitchMode: () => undefined,
    onRefreshDiff: () => undefined,
    onSelectDiffFile: () => undefined,
    onToggleFileChecked: () => undefined,
    onSelectAllFiles: () => undefined,
    onClearFileSelection: () => undefined,
    onRevertFile: () => undefined,
    onCommitMessageChange: () => undefined,
    onCommit: () => undefined,
    onCommandInputChange: () => undefined,
    onRunCommand: () => undefined,
    onApprovalsFilterChange: () => undefined,
    onApprovalNoteChange: () => undefined,
    onResolveApproval: () => undefined,
    onDismissBanner: () => undefined,
    ...overrides
  }
}

describe('P3 Coding Studio API, Worktree Diff UI, Plan/Build approvals and P4 i18n detection', () => {
  const engineRequest = vi.fn()
  const cancelEngineRequest = vi.fn()

  beforeEach(async () => {
    vi.restoreAllMocks()
    engineRequest.mockReset()
    cancelEngineRequest.mockReset()
    await i18n.changeLanguage('zh')
    vi.stubGlobal('window', {
      api: {
        runtimeKind: 'electron',
        engineRequest,
        engineStream: vi.fn(),
        engineUpload: vi.fn(),
        cancelEngineRequest
      }
    })
  })

  afterEach(async () => {
    await i18n.changeLanguage('zh')
    vi.unstubAllGlobals()
  })

  it('invokes all 10 /v1/coding/* API endpoints with strict payloads and rejects unsafe IDs', async () => {
    engineRequest.mockImplementation(
      async (req: { method: string; target: string; body?: string }) => {
        if (req.method === 'GET' && req.target === '/v1/coding/sessions') {
          return jsonResponse({ sessions: [SAMPLE_SESSION_PLAN] })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions') {
          return jsonResponse(SAMPLE_SESSION_BUILD)
        }
        if (req.method === 'GET' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/diff') {
          return jsonResponse(SAMPLE_DIFF)
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/mode') {
          const parsed = JSON.parse(req.body ?? '{}') as { mode: 'plan' | 'build' }
          return jsonResponse({ ...SAMPLE_SESSION_PLAN, mode: parsed.mode })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/revert') {
          const parsed = JSON.parse(req.body ?? '{}') as { path: string }
          return jsonResponse({
            ok: true,
            session_id: 'wt-a1b2c3d4',
            path: parsed.path,
            action: 'reverted_to_head'
          })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/commit') {
          const parsed = JSON.parse(req.body ?? '{}') as { message: string; files?: string[] }
          return jsonResponse({
            ok: true,
            session_id: 'wt-a1b2c3d4',
            branch: SAMPLE_SESSION_PLAN.branch,
            commit_sha: '9a8b7c6',
            committed_files: parsed.files ?? ['src/auth.ts']
          })
        }
        if (
          req.method === 'DELETE' &&
          req.target === '/v1/coding/sessions/wt-a1b2c3d4?delete_branch=true'
        ) {
          return jsonResponse({ ok: true, session_id: 'wt-a1b2c3d4', destroyed: true })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/exec') {
          const parsed = JSON.parse(req.body ?? '{}') as { command: string }
          if (parsed.command === 'git status') {
            return jsonResponse({
              status: 'executed',
              result: { exit_code: 0, stdout: 'On branch nachuan\n', stderr: '', duration_ms: 15.2 }
            })
          }
          return jsonResponse({
            status: 'pending_approval',
            approval: SAMPLE_PENDING_APPROVAL
          })
        }
        if (req.method === 'GET' && req.target === '/v1/coding/approvals?status=pending') {
          return jsonResponse({ approvals: [SAMPLE_PENDING_APPROVAL] })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/approvals/cap-9f8e7d6c5b/resolve') {
          const parsed = JSON.parse(req.body ?? '{}') as {
            decision: 'approve' | 'reject'
            note?: string
          }
          return jsonResponse({
            ...SAMPLE_PENDING_APPROVAL,
            status: parsed.decision === 'approve' ? 'approved' : 'rejected',
            resolver_note: parsed.note ?? '',
            ...(parsed.decision === 'approve'
              ? {
                  exec_result: {
                    exit_code: 0,
                    stdout: 'build green',
                    stderr: '',
                    duration_ms: 420
                  }
                }
              : {})
          })
        }
        return jsonResponse({ detail: 'unexpected route' }, 404)
      }
    )

    const sessions = await listCodingSessions()
    expect(sessions).toHaveLength(1)
    expect(sessions[0].session_id).toBe('wt-a1b2c3d4')

    const created = await createCodingSession({
      repo_path: 'D:\\repo\\nachuan',
      title: 'Build Mobile Approvals',
      mode: 'build',
      agent_engine: 'claude-code'
    })
    expect(created.agent_engine).toBe('claude-code')
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'POST',
        target: '/v1/coding/sessions',
        body: JSON.stringify({
          repo_path: 'D:\\repo\\nachuan',
          title: 'Build Mobile Approvals',
          mode: 'build',
          agent_engine: 'claude-code'
        })
      })
    )

    const diff = await getCodingSessionDiff('wt-a1b2c3d4')
    expect(diff.total_additions).toBe(4)
    expect(diff.total_deletions).toBe(2)

    const switched = await setCodingSessionMode('wt-a1b2c3d4', 'build')
    expect(switched.mode).toBe('build')

    const reverted = await revertCodingFile('wt-a1b2c3d4', 'src/auth.ts')
    expect(reverted).toMatchObject({ ok: true, path: 'src/auth.ts', action: 'reverted_to_head' })

    const committed = await commitCodingSession('wt-a1b2c3d4', {
      message: 'feat: harden oauth guard',
      files: ['src/auth.ts']
    })
    expect(committed).toMatchObject({ ok: true, commit_sha: '9a8b7c6', committed_files: ['src/auth.ts'] })

    const directExec = await execCodingCommand('wt-a1b2c3d4', { command: 'git status' })
    expect(directExec.status).toBe('executed')
    if (directExec.status === 'executed') {
      expect(directExec.result.exit_code).toBe(0)
    }

    const pendingExec = await execCodingCommand('wt-a1b2c3d4', {
      command: 'npm run build && node scripts/verify.mjs'
    })
    expect(pendingExec.status).toBe('pending_approval')

    const approvals = await listCodingApprovals('pending')
    expect(approvals).toHaveLength(1)
    expect(approvals[0].approval_id).toBe('cap-9f8e7d6c5b')

    const approved = await resolveCodingApproval('cap-9f8e7d6c5b', {
      decision: 'approve',
      note: 'approved from phone'
    })
    expect(approved.status).toBe('approved')
    expect(approved.exec_result?.stdout).toBe('build green')

    const rejected = await resolveCodingApproval('cap-9f8e7d6c5b', { decision: 'reject' })
    expect(rejected.status).toBe('rejected')

    const destroyed = await destroyCodingSession('wt-a1b2c3d4', true)
    expect(destroyed).toEqual({ ok: true, session_id: 'wt-a1b2c3d4', destroyed: true })

    // 非法 ID 在发往代理前即被拒绝
    await expect(getCodingSessionDiff('../etc')).rejects.toThrow('Invalid coding session_id')
    await expect(resolveCodingApproval('bad/id', { decision: 'approve' })).rejects.toThrow(
      'Invalid coding approval_id'
    )
  })

  it('parses unified diff lines with accurate line numbers and extracts FastAPI error details', () => {
    const lines = parseUnifiedDiffLines(SAMPLE_DIFF.files[0].diff)
    expect(lines.filter((line) => line.kind === 'add')).toHaveLength(3)
    expect(lines.filter((line) => line.kind === 'del')).toHaveLength(2)
    expect(lines.filter((line) => line.kind === 'hunk')).toHaveLength(1)
    const firstDel = lines.find((line) => line.kind === 'del')
    const firstAdd = lines.find((line) => line.kind === 'add')
    expect(firstDel).toMatchObject({ oldLine: 11, newLine: null })
    expect(firstAdd).toMatchObject({ oldLine: null, newLine: 11 })

    expect(
      extractCodingErrorMessage(
        new Error('403 {"detail":"当前处于 Plan 只读规划模式，执行命令前请先切换为 Build 模式"}')
      )
    ).toBe('当前处于 Plan 只读规划模式，执行命令前请先切换为 Build 模式')
  })

  it('renders sessions, Plan/Build shields, red/green unified diff, sandbox output and mobile approvals in zh and en', async () => {
    const executedResponse: CodingExecResponse = {
      status: 'executed',
      result: { exit_code: 0, stdout: '12 passed in 0.42s', stderr: '', duration_ms: 420 }
    }

    // 1) 中文 Plan 模式 + 红绿 Diff + 待审批队列
    await i18n.changeLanguage('zh')
    const zhHtml = renderToStaticMarkup(
      <CodingStudioPaneView {...makeViewProps({ lastExecResponse: executedResponse })} />
    )
    expect(zhHtml).toContain('编码工作台')
    expect(zhHtml).toContain('Refactor OAuth Guard')
    expect(zhHtml).toContain('Build Mobile Approvals')
    expect(zhHtml).toContain('nachuan/refactor-oauth-guard-c3d4')
    expect(zhHtml).toContain('nachuan-shield-badge--plan')
    expect(zhHtml).toContain('nachuan-shield-badge--build')
    expect(zhHtml).toContain('data-testid="plan-readonly-banner"')
    expect(zhHtml).toContain('+4')
    expect(zhHtml).toContain('-2')
    expect(zhHtml).toContain('nachuan-diff-line--add')
    expect(zhHtml).toContain('nachuan-diff-line--del')
    expect(zhHtml).toContain('strictVerify(secret)')
    expect(zhHtml).toContain('legacyCheck(secret)')
    expect(zhHtml).toContain('12 passed in 0.42s')
    expect(zhHtml).toContain('cap-9f8e7d6c5b')
    expect(zhHtml).toContain('批准并执行 (Approve)')
    expect(zhHtml).toContain('驳回 (Reject)')
    // 6 大编码引擎全部出现在下拉列表中
    for (const engine of [
      'codex',
      'claude-code',
      'opencode',
      'kimi-code',
      'local-ollama',
      'byok-cloud'
    ]) {
      expect(zhHtml).toContain(`value="${engine}"`)
    }

    // 2) 英文 Build 模式 + 审批挂起提示
    await i18n.changeLanguage('en')
    const enHtml = renderToStaticMarkup(
      <CodingStudioPaneView
        {...makeViewProps({
          selectedSessionId: SAMPLE_SESSION_BUILD.session_id,
          lastExecResponse: {
            status: 'pending_approval',
            approval: SAMPLE_PENDING_APPROVAL
          }
        })}
      />
    )
    expect(enHtml).toContain('Coding Studio')
    expect(enHtml).toContain('data-testid="build-exec-banner"')
    expect(enHtml).toContain('Accept &amp; Commit')
    expect(enHtml).toContain('Approve &amp; Run')
    expect(enHtml).toContain('Reject')
    expect(enHtml).toContain('data-testid="sandbox-pending-approval-notice"')

    // 3) 默认导出组件可安全 SSR 渲染
    const connectedHtml = renderToStaticMarkup(
      <CodingStudioPane
        initialSessions={[SAMPLE_SESSION_PLAN]}
        initialDiff={SAMPLE_DIFF}
        initialApprovals={[SAMPLE_PENDING_APPROVAL]}
      />
    )
    expect(connectedHtml).toContain('data-testid="coding-studio-pane"')
  })

  it('wires UI actions end-to-end: create worktree, switch Plan/Build, revert file, commit, run command, approve and reject', async () => {
    const calls: string[] = []
    engineRequest.mockImplementation(
      async (req: { method: string; target: string; body?: string }) => {
        calls.push(`${req.method} ${req.target}`)
        if (req.method === 'POST' && req.target === '/v1/coding/sessions') {
          return jsonResponse(SAMPLE_SESSION_BUILD)
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/mode') {
          return jsonResponse({ ...SAMPLE_SESSION_PLAN, mode: 'build' })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/revert') {
          return jsonResponse({
            ok: true,
            session_id: 'wt-a1b2c3d4',
            path: 'src/auth.ts',
            action: 'reverted_to_head'
          })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/commit') {
          return jsonResponse({
            ok: true,
            session_id: 'wt-a1b2c3d4',
            branch: SAMPLE_SESSION_PLAN.branch,
            commit_sha: 'abc1234',
            committed_files: ['src/auth.ts']
          })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/sessions/wt-a1b2c3d4/exec') {
          return jsonResponse({
            status: 'pending_approval',
            approval: SAMPLE_PENDING_APPROVAL
          })
        }
        if (req.method === 'POST' && req.target === '/v1/coding/approvals/cap-9f8e7d6c5b/resolve') {
          const parsed = JSON.parse(req.body ?? '{}') as { decision: 'approve' | 'reject' }
          return jsonResponse({
            ...SAMPLE_PENDING_APPROVAL,
            status: parsed.decision === 'approve' ? 'approved' : 'rejected'
          })
        }
        return jsonResponse({ ok: true })
      }
    )

    let currentMode: 'plan' | 'build' = 'plan'
    let currentExec: CodingExecResponse | null = null
    let lastApprovalStatus: string | null = null

    const tree = buildCodingStudioPaneTree(
      makeViewProps({
        onCreateSession: () => {
          void createCodingSession({
            repo_path: 'D:\\repo\\nachuan',
            title: 'Add worktree studio',
            mode: 'plan',
            agent_engine: 'codex'
          })
        },
        onSwitchMode: (mode) => {
          void setCodingSessionMode(SAMPLE_SESSION_PLAN.session_id, mode).then((res) => {
            currentMode = res.mode
          })
        },
        onRevertFile: (path) => {
          void revertCodingFile(SAMPLE_SESSION_PLAN.session_id, path)
        },
        onCommit: () => {
          void commitCodingSession(SAMPLE_SESSION_PLAN.session_id, {
            message: 'feat: harden oauth guard',
            files: ['src/auth.ts']
          })
        },
        onRunCommand: () => {
          void execCodingCommand(SAMPLE_SESSION_PLAN.session_id, {
            command: 'npm run build && node scripts/verify.mjs'
          }).then((res) => {
            currentExec = res
          })
        },
        onResolveApproval: (approvalId, decision) => {
          void resolveCodingApproval(approvalId, { decision }).then((res) => {
            lastApprovalStatus = res.status
          })
        }
      }),
      (key, opts) => String(i18n.t(key, opts))
    )

    // 1. 创建 Worktree 表单提交
    const createForm = findElementByTestId(tree, 'create-session-form')
    expect(createForm).not.toBeNull()
    ;(createForm!.props.onSubmit as (e: { preventDefault: () => void }) => void)({
      preventDefault: () => undefined
    })

    // 2. 切换 Plan -> Build
    const buildBtn = findElementByTestId(tree, 'btn-mode-build')
    expect(buildBtn).not.toBeNull()
    ;(buildBtn!.props.onClick as () => void)()

    // 3. 单文件回滚
    const revertBtn = findElementByTestId(tree, 'btn-revert-src/auth.ts')
    expect(revertBtn).not.toBeNull()
    ;(revertBtn!.props.onClick as () => void)()

    // 4. 采纳并提交
    const commitForm = findElementByTestId(tree, 'commit-form')
    expect(commitForm).not.toBeNull()
    ;(commitForm!.props.onSubmit as (e: { preventDefault: () => void }) => void)({
      preventDefault: () => undefined
    })

    // 5. 执行沙箱命令触发审批
    const execForm = findElementByTestId(tree, 'sandbox-exec-form')
    expect(execForm).not.toBeNull()
    ;(execForm!.props.onSubmit as (e: { preventDefault: () => void }) => void)({
      preventDefault: () => undefined
    })

    // 6. 审批队列一键 Approve 与 Reject
    const approveBtn = findElementByTestId(tree, 'btn-approve-cap-9f8e7d6c5b')
    const rejectBtn = findElementByTestId(tree, 'btn-reject-cap-9f8e7d6c5b')
    expect(approveBtn).not.toBeNull()
    expect(rejectBtn).not.toBeNull()
    ;(approveBtn!.props.onClick as () => void)()
    await vi.waitFor(() => expect(lastApprovalStatus).toBe('approved'))
    ;(rejectBtn!.props.onClick as () => void)()
    await vi.waitFor(() => expect(lastApprovalStatus).toBe('rejected'))

    expect(currentMode).toBe('build')
    expect(currentExec).toMatchObject({ status: 'pending_approval' })
    expect(calls).toEqual([
      'POST /v1/coding/sessions',
      'POST /v1/coding/sessions/wt-a1b2c3d4/mode',
      'POST /v1/coding/sessions/wt-a1b2c3d4/revert',
      'POST /v1/coding/sessions/wt-a1b2c3d4/commit',
      'POST /v1/coding/sessions/wt-a1b2c3d4/exec',
      'POST /v1/coding/approvals/cap-9f8e7d6c5b/resolve',
      'POST /v1/coding/approvals/cap-9f8e7d6c5b/resolve'
    ])
  })

  it('auto-detects navigator.language (zh* -> zh, global rest -> en) while honoring saved preference', () => {
    // 未保存偏好时：中文区 -> zh，其余全部地区 -> en
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'zh-CN' })).toBe('zh')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'zh-TW' })).toBe('zh')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'zh-HK' })).toBe('zh')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'zh' })).toBe('zh')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'en-US' })).toBe('en')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'en-GB' })).toBe('en')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'ja-JP' })).toBe('en')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'de-DE' })).toBe('en')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: 'fr-FR' })).toBe('en')
    expect(detectInitialLanguage({ savedLanguage: null, navigatorLanguage: '' })).toBe('en')

    // 用户手动选定语言优先于浏览器语言
    const store = new Map<string, string>()
    const fakeStorage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => {
        store.set(key, value)
      }
    }
    savePreferredLanguage('en', fakeStorage)
    expect(store.get(LANGUAGE_STORAGE_KEY)).toBe('en')
    expect(
      detectInitialLanguage({ storage: fakeStorage, navigatorLanguage: 'zh-CN' })
    ).toBe('en')

    savePreferredLanguage('zh', fakeStorage)
    expect(
      detectInitialLanguage({ storage: fakeStorage, navigatorLanguage: 'en-US' })
    ).toBe('zh')
  })
})
