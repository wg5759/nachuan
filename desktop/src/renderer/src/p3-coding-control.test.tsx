import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { RendererEngineProxy } from '../../main/renderer-engine-proxy'
import {
  commitWorkspace,
  createWorktree,
  getWorkspaceDiff,
  listWorktrees,
  removeWorktree,
  revertWorkspaceFile,
  runWorkspaceExecPlan,
  type WorkspaceDiffSnapshot,
  type WorkspaceExecResult,
  type WorkspaceWorktreeList
} from './api'
import CodingControlPane, {
  APPROVAL_CENTER_REFRESH_EVENT,
  applyWorktreeToConversation,
  buildCodingControlPaneTree,
  CodingControlPaneView,
  formatDiffStatusBadge,
  notifyApprovalCenter,
  parseUnifiedDiffLines,
  performCommitWorkspace,
  performCreateWorktree,
  performRemoveWorktree,
  performRevertFile,
  performRunExecPlan,
  type CodingControlPaneViewProps
} from './components/CodingControlPane'
import i18n, {
  detectPreferredLanguage,
  LANG_STORAGE_KEY,
  setAppLanguage
} from './i18n'
import { useAppStore } from './store'

const SESSION = Object.freeze({
  bootToken: '9c'.repeat(32),
  generation: 1,
  pid: 24_680,
  port: 43_210
})

const SAMPLE_WORKTREES: WorkspaceWorktreeList = {
  repo_root: 'D:\\repos\\nachuan',
  is_git_repo: true,
  current_branch: 'main',
  worktrees: [
    {
      path: 'D:\\repos\\nachuan',
      branch: 'main',
      head: '1234567890abcdef',
      is_main: true,
      is_managed: false,
      dirty_files: 0,
      locked: false
    },
    {
      path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      branch: 'feat/auth-fix',
      head: 'abcdef1234567890',
      is_main: false,
      is_managed: true,
      dirty_files: 2,
      locked: false
    }
  ]
}

const SAMPLE_DIFF: WorkspaceDiffSnapshot = {
  worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
  branch: 'feat/auth-fix',
  summary: {
    total_files: 2,
    additions: 3,
    deletions: 1
  },
  files: [
    {
      path: 'src/auth.ts',
      status: 'M',
      additions: 2,
      deletions: 1,
      truncated: false,
      diff: [
        'diff --git a/src/auth.ts b/src/auth.ts',
        'index 1111111..2222222 100644',
        '--- a/src/auth.ts',
        '+++ b/src/auth.ts',
        '@@ -10,3 +10,4 @@ export function verifyToken(token: string) {',
        '   if (!token) return false',
        '-  return token.length > 4',
        '+  const trimmed = token.trim()',
        '+  return trimmed.length >= 16',
        ' }'
      ].join('\n')
    },
    {
      path: 'src/new-helper.ts',
      status: 'A',
      additions: 1,
      deletions: 0,
      truncated: false,
      diff: '@@ -0,0 +1,1 @@\n+export const AUTH_VERSION = 2'
    }
  ]
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

function fakeLocalStorage(initial: Record<string, string> = {}): Storage {
  const values = new Map(Object.entries(initial))
  return {
    get length() {
      return values.size
    },
    clear: vi.fn(() => values.clear()),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    key: vi.fn((index: number) => [...values.keys()][index] ?? null),
    removeItem: vi.fn((key: string) => {
      values.delete(key)
    }),
    setItem: vi.fn((key: string, value: string) => {
      values.set(key, value)
    })
  }
}

function makeBaseViewProps(
  overrides: Partial<CodingControlPaneViewProps> = {}
): CodingControlPaneViewProps {
  return {
    repoPath: 'D:\\repos\\nachuan',
    activeWorkdir: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
    worktreeList: SAMPLE_WORKTREES,
    selectedWorktreePath: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
    loadingWorktrees: false,
    newTaskName: 'feat-diff-panel',
    newBaseRef: 'main',
    creatingWorktree: false,
    removingPath: null,
    removeDeleteBranch: false,
    removeForce: false,
    diffSnapshot: SAMPLE_DIFF,
    stagedOnly: false,
    loadingDiff: false,
    selectedFilePath: 'src/auth.ts',
    checkedFiles: ['src/auth.ts'],
    revertingFilePath: null,
    commitMessage: 'feat: harden token check',
    committing: false,
    execMode: 'plan',
    execCommand: 'git status --short',
    execRunning: false,
    execResult: null,
    approvalIdInput: '',
    onRepoPathChange: () => undefined,
    onLoadRepo: () => undefined,
    onNewTaskNameChange: () => undefined,
    onNewBaseRefChange: () => undefined,
    onCreateWorktree: () => undefined,
    onSelectWorktree: () => undefined,
    onRemoveWorktree: () => undefined,
    onToggleRemoveDeleteBranch: () => undefined,
    onToggleRemoveForce: () => undefined,
    onToggleStaged: () => undefined,
    onRefreshDiff: () => undefined,
    onSelectFile: () => undefined,
    onToggleCheckFile: () => undefined,
    onSelectAllFiles: () => undefined,
    onClearCheckedFiles: () => undefined,
    onRevertFile: () => undefined,
    onCommitMessageChange: () => undefined,
    onCommit: () => undefined,
    onExecModeChange: () => undefined,
    onExecCommandChange: () => undefined,
    onRunExec: () => undefined,
    onApprovalIdInputChange: () => undefined,
    onOpenApprovalCenter: () => undefined,
    onRetryWithApproval: () => undefined,
    ...overrides
  }
}

describe('P3 Coding Control Plane: proxy allowlist, worktree/diff/exec-plan flows, and i18n detection', () => {
  const engineRequest = vi.fn()
  const cancelEngineRequest = vi.fn()

  beforeEach(async () => {
    vi.restoreAllMocks()
    engineRequest.mockReset()
    cancelEngineRequest.mockReset()
    await i18n.changeLanguage('zh')
    useAppStore.setState({
      conversations: [],
      currentConvId: null,
      view: 'coding'
    })
    vi.stubGlobal('window', {
      dispatchEvent: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
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

  it('enforces RendererEngineProxy allowlist and closed-set body validation on all 7 /v1/workspace/* routes', async () => {
    const transport = vi.fn(async () => jsonResponse({ ok: true }))
    const proxy = new RendererEngineProxy({
      session: () => SESSION,
      runtimeKey: () => 'sk-local-' + 'p'.repeat(64),
      transport
    })

    const allowed = [
      {
        requestId: '41414141-4141-4141-8141-414141414101',
        method: 'GET' as const,
        target: `/v1/workspace/worktrees?repo_path=${encodeURIComponent('D:\\repos\\nachuan')}`,
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414102',
        method: 'POST' as const,
        target: '/v1/workspace/worktrees',
        bodyKind: 'json' as const,
        body: JSON.stringify({ repo_path: 'D:\\repos\\nachuan', task_name: 'feat-p3' }),
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414103',
        method: 'POST' as const,
        target: '/v1/workspace/worktrees/remove',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          repo_path: 'D:\\repos\\nachuan',
          worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-p3',
          force: true,
          delete_branch: true
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414104',
        method: 'GET' as const,
        target: `/v1/workspace/diff?worktree_path=${encodeURIComponent('D:\\repos\\nachuan')}&staged=true`,
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414105',
        method: 'POST' as const,
        target: '/v1/workspace/revert-file',
        bodyKind: 'json' as const,
        body: JSON.stringify({ worktree_path: 'D:\\repos\\nachuan', file_path: 'src/auth.ts' }),
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414106',
        method: 'POST' as const,
        target: '/v1/workspace/commit',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan',
          message: 'feat: p3 control plane',
          files: ['src/auth.ts']
        }),
        responseKind: 'json' as const
      },
      {
        requestId: '41414141-4141-4141-8141-414141414107',
        method: 'POST' as const,
        target: '/v1/workspace/exec-plan',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan',
          mode: 'plan',
          command: 'git status'
        }),
        responseKind: 'json' as const
      }
    ]

    for (const req of allowed) {
      await expect(proxy.request(req)).resolves.toMatchObject({ status: 200 })
    }
    expect(transport).toHaveBeenCalledTimes(7)

    // 非法字段 / 类型 / 路径全部拦截
    const forbiddenCases = [
      // 额外未知字段
      {
        requestId: '41414141-4141-4141-8141-414141414111',
        method: 'POST' as const,
        target: '/v1/workspace/commit',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan',
          message: 'ok',
          amend: true
        }),
        responseKind: 'json' as const
      },
      // 缺少必填字段
      {
        requestId: '41414141-4141-4141-8141-414141414112',
        method: 'POST' as const,
        target: '/v1/workspace/revert-file',
        bodyKind: 'json' as const,
        body: JSON.stringify({ worktree_path: 'D:\\repos\\nachuan' }),
        responseKind: 'json' as const
      },
      // 非法 mode 枚举
      {
        requestId: '41414141-4141-4141-8141-414141414113',
        method: 'POST' as const,
        target: '/v1/workspace/exec-plan',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan',
          mode: 'yolo',
          command: 'rm -rf /'
        }),
        responseKind: 'json' as const
      },
      // files 数组元素类型错误
      {
        requestId: '41414141-4141-4141-8141-414141414114',
        method: 'POST' as const,
        target: '/v1/workspace/commit',
        bodyKind: 'json' as const,
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan',
          message: 'bad files',
          files: [123]
        }),
        responseKind: 'json' as const
      },
      // 非法 query 参数
      {
        requestId: '41414141-4141-4141-8141-414141414115',
        method: 'GET' as const,
        target: '/v1/workspace/diff?worktree_path=abc&staged=maybe',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      },
      // 未白名单路径
      {
        requestId: '41414141-4141-4141-8141-414141414116',
        method: 'DELETE' as const,
        target: '/v1/workspace/worktrees',
        bodyKind: 'none' as const,
        responseKind: 'json' as const
      }
    ]

    for (const req of forbiddenCases) {
      await expect(proxy.request(req)).rejects.toThrow('Renderer Engine request is not permitted')
    }
    expect(transport).toHaveBeenCalledTimes(7)
  })

  it('invokes all 7 /v1/workspace/* frontend API wrappers cleanly with canonical contracts', async () => {
    engineRequest.mockImplementation(async (req: { method: string; target: string; body?: string }) => {
      if (req.method === 'GET' && req.target.startsWith('/v1/workspace/worktrees')) {
        return jsonResponse(SAMPLE_WORKTREES)
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/worktrees') {
        return jsonResponse({ ok: true, worktree: SAMPLE_WORKTREES.worktrees[1] })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/worktrees/remove') {
        return jsonResponse({ ok: true, removed: SAMPLE_WORKTREES.worktrees[1].path })
      }
      if (req.method === 'GET' && req.target.startsWith('/v1/workspace/diff')) {
        return jsonResponse(SAMPLE_DIFF)
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/revert-file') {
        return jsonResponse({ ok: true, file_path: 'src/auth.ts' })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/commit') {
        return jsonResponse({
          ok: true,
          commit_sha: 'deadbeef12345678',
          branch: 'feat/auth-fix',
          files_committed: 1
        })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/exec-plan') {
        const parsed = JSON.parse(req.body ?? '{}') as { mode: 'plan' | 'build'; command: string; approval_id?: string }
        if (parsed.mode === 'build' && !parsed.approval_id) {
          return jsonResponse({
            status: 'approval_required',
            mode: 'build',
            command: parsed.command,
            approval_id: 'appr-9001',
            risk_level: 'high',
            reason: 'mutating build command requires approval'
          })
        }
        return jsonResponse({
          status: 'executed',
          mode: parsed.mode,
          command: parsed.command,
          exit_code: 0,
          stdout: 'all tests passed',
          stderr: ''
        })
      }
      return jsonResponse({ detail: 'not found' }, 404)
    })

    const listed = await listWorktrees('D:\\repos\\nachuan')
    expect(listed.worktrees).toHaveLength(2)
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        target: `/v1/workspace/worktrees?repo_path=${encodeURIComponent('D:\\repos\\nachuan')}`
      })
    )

    const created = await createWorktree('D:\\repos\\nachuan', 'feat-auth-fix', 'main')
    expect(created.ok).toBe(true)
    expect(created.worktree.branch).toBe('feat/auth-fix')

    const removed = await removeWorktree(
      'D:\\repos\\nachuan',
      'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      { force: false, delete_branch: true }
    )
    expect(removed.ok).toBe(true)

    const diff = await getWorkspaceDiff('D:\\repos\\nachuan\\.worktrees\\feat-auth-fix', false)
    expect(diff.summary.additions).toBe(3)
    expect(diff.files).toHaveLength(2)

    const reverted = await revertWorkspaceFile(
      'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      'src/auth.ts'
    )
    expect(reverted).toEqual({ ok: true, file_path: 'src/auth.ts' })

    const committed = await commitWorkspace(
      'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      'feat: harden token check',
      ['src/auth.ts']
    )
    expect(committed).toMatchObject({ ok: true, commit_sha: 'deadbeef12345678', files_committed: 1 })

    const planRes = await runWorkspaceExecPlan({
      worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      mode: 'plan',
      command: 'git status --short'
    })
    expect(planRes.status).toBe('executed')

    const buildHold = await runWorkspaceExecPlan({
      worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      mode: 'build',
      command: 'npm test'
    })
    expect(buildHold).toMatchObject({
      status: 'approval_required',
      approval_id: 'appr-9001',
      risk_level: 'high'
    })

    const buildApproved = await runWorkspaceExecPlan({
      worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      mode: 'build',
      command: 'npm test',
      approval_id: 'appr-9001'
    })
    expect(buildApproved).toMatchObject({
      status: 'executed',
      exit_code: 0,
      stdout: 'all tests passed'
    })
  })

  it('renders worktree scheduler, green/red unified diff viewer, revert/commit controls, and Plan vs Build approval loop', async () => {
    // 1) 验证 Unified Diff 解析器行号和绿/红着色分类
    const parsedLines = parseUnifiedDiffLines(SAMPLE_DIFF.files[0].diff)
    const addLines = parsedLines.filter((line) => line.kind === 'add')
    const delLines = parsedLines.filter((line) => line.kind === 'del')
    expect(addLines).toHaveLength(2)
    expect(addLines[0]).toMatchObject({ oldLine: null, newLine: 11 })
    expect(addLines[1]).toMatchObject({ oldLine: null, newLine: 12 })
    expect(delLines).toHaveLength(1)
    expect(delLines[0]).toMatchObject({ oldLine: 11, newLine: null })
    expect(formatDiffStatusBadge('M')).toEqual({ code: 'M', tone: 'modified' })
    expect(formatDiffStatusBadge('A')).toEqual({ code: 'A', tone: 'added' })
    expect(formatDiffStatusBadge('D')).toEqual({ code: 'D', tone: 'deleted' })
    expect(formatDiffStatusBadge('?')).toEqual({ code: '?', tone: 'untracked' })

    // 2) 验证切换 Worktree 自动绑定当前会话 workdir（无会话时自动创建 code 会话）
    const store = useAppStore.getState()
    const boundConvId = applyWorktreeToConversation(
      'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
      {
        currentConvId: store.currentConvId,
        newConversation: store.newConversation,
        setConvWorkdir: store.setConvWorkdir
      }
    )
    const updatedConv = useAppStore.getState().conversations.find((c) => c.id === boundConvId)
    expect(updatedConv?.kind).toBe('code')
    expect(updatedConv?.workdir).toBe('D:\\repos\\nachuan\\.worktrees\\feat-auth-fix')

    // 3) 完整视图渲染（中文）：Worktree 列表 + Diff 绿红着色 + Plan 执行输出
    const planExecuted: WorkspaceExecResult = {
      status: 'executed',
      mode: 'plan',
      command: 'git status --short',
      exit_code: 0,
      stdout: ' M src/auth.ts\n A src/new-helper.ts',
      stderr: ''
    }
    const zhHtml = renderToStaticMarkup(
      <CodingControlPaneView {...makeBaseViewProps({ execMode: 'plan', execResult: planExecuted })} />
    )
    expect(zhHtml).toContain('编码控制面')
    expect(zhHtml).toContain('feat/auth-fix')
    expect(zhHtml).toContain('2 处未提交')
    expect(zhHtml).toContain('托管隔离')
    expect(zhHtml).toContain('src/auth.ts')
    expect(zhHtml).toContain('data-diff-kind="add"')
    expect(zhHtml).toContain('data-diff-kind="del"')
    expect(zhHtml).toContain('data-testid="exec-result-executed"')
    expect(zhHtml).toContain('退出码 0')
    expect(zhHtml).toContain('M src/auth.ts')

    // 4) Build 模式触发 approval_required 与 blocked 展示
    const buildApproval: WorkspaceExecResult = {
      status: 'approval_required',
      mode: 'build',
      command: 'npm test',
      approval_id: 'appr-7788',
      risk_level: 'high',
      reason: 'Build mode requires approval'
    }
    const approvalHtml = renderToStaticMarkup(
      <CodingControlPaneView
        {...makeBaseViewProps({
          execMode: 'build',
          execCommand: 'npm test',
          execResult: buildApproval,
          approvalIdInput: 'appr-7788'
        })}
      />
    )
    expect(approvalHtml).toContain('data-testid="exec-result-approval"')
    expect(approvalHtml).toContain('appr-7788')
    expect(approvalHtml).toContain('风险等级：high')
    expect(approvalHtml).toContain('前往审批中心批准')
    expect(approvalHtml).toContain('用该审批号继续执行')

    const blockedHtml = renderToStaticMarkup(
      <CodingControlPaneView
        {...makeBaseViewProps({
          execMode: 'plan',
          execCommand: 'rm -rf src',
          execResult: {
            status: 'blocked',
            mode: 'plan',
            command: 'rm -rf src',
            risk_level: 'critical',
            reason: 'Destructive command blocked in read-only Plan mode'
          }
        })}
      />
    )
    expect(blockedHtml).toContain('data-testid="exec-result-blocked"')
    expect(blockedHtml).toContain('Destructive command blocked in read-only Plan mode')

    // 5) 交互闭环：创建 Worktree、切换 Worktree、单文件 Revert、Commit、前往审批中心、携带 approval_id 重跑
    engineRequest.mockImplementation(async (req: { method: string; target: string; body?: string }) => {
      if (req.method === 'POST' && req.target === '/v1/workspace/worktrees') {
        return jsonResponse({ ok: true, worktree: SAMPLE_WORKTREES.worktrees[1] })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/worktrees/remove') {
        return jsonResponse({ ok: true, removed: SAMPLE_WORKTREES.worktrees[1].path })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/revert-file') {
        return jsonResponse({ ok: true, file_path: 'src/auth.ts' })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/commit') {
        return jsonResponse({
          ok: true,
          commit_sha: 'cafebabe98765432',
          branch: 'feat/auth-fix',
          files_committed: 1
        })
      }
      if (req.method === 'POST' && req.target === '/v1/workspace/exec-plan') {
        const parsed = JSON.parse(req.body ?? '{}') as { approval_id?: string; command: string }
        return jsonResponse({
          status: 'executed',
          mode: 'build',
          command: parsed.command,
          exit_code: 0,
          stdout: `approved run ${parsed.approval_id}`
        })
      }
      return jsonResponse({ ok: true })
    })

    const onSelectWorktree = vi.fn()
    const onCreateWorktree = vi.fn(async () => {
      await performCreateWorktree('D:\\repos\\nachuan', 'feat-diff-panel', 'main')
    })
    const onRemoveWorktree = vi.fn(async () => {
      await performRemoveWorktree(
        'D:\\repos\\nachuan',
        'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
        { delete_branch: true, force: false }
      )
    })
    const onRevertFile = vi.fn(async (filePath: string) => {
      await performRevertFile('D:\\repos\\nachuan\\.worktrees\\feat-auth-fix', filePath)
    })
    const onCommit = vi.fn(async () => {
      await performCommitWorkspace(
        'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
        'feat: harden token check',
        ['src/auth.ts']
      )
    })
    const onOpenApprovalCenter = vi.fn(() => {
      notifyApprovalCenter('appr-7788')
    })
    let retryResult: WorkspaceExecResult | null = null
    const onRetryWithApproval = vi.fn(async () => {
      retryResult = await performRunExecPlan({
        worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
        mode: 'build',
        command: 'npm test',
        approval_id: 'appr-7788'
      })
    })

    const tree = buildCodingControlPaneTree(
      makeBaseViewProps({
        execMode: 'build',
        execCommand: 'npm test',
        execResult: buildApproval,
        approvalIdInput: 'appr-7788',
        onSelectWorktree,
        onCreateWorktree,
        onRemoveWorktree,
        onRevertFile,
        onCommit,
        onOpenApprovalCenter,
        onRetryWithApproval
      }),
      (key, opts) => String(i18n.t(key, opts))
    )

    await (findElementByTestId(tree, 'create-worktree-btn')!.props.onClick as () => Promise<void>)()
    ;(findElementByTestId(tree, 'worktree-select-feat/auth-fix')!.props.onClick as () => void)()
    await (
      findElementByTestId(tree, 'remove-worktree-feat/auth-fix')!.props.onClick as () => Promise<void>
    )()
    await (findElementByTestId(tree, 'revert-file-src/auth.ts')!.props.onClick as () => Promise<void>)()
    await (findElementByTestId(tree, 'commit-submit-btn')!.props.onClick as () => Promise<void>)()
    ;(findElementByTestId(tree, 'exec-open-approval-center')!.props.onClick as () => void)()
    await (findElementByTestId(tree, 'exec-retry-with-approval')!.props.onClick as () => Promise<void>)()

    expect(onSelectWorktree).toHaveBeenCalledWith(SAMPLE_WORKTREES.worktrees[1])
    expect(window.dispatchEvent).toHaveBeenCalledWith(
      expect.objectContaining({ type: APPROVAL_CENTER_REFRESH_EVENT })
    )
    expect(retryResult).toMatchObject({
      status: 'executed',
      exit_code: 0,
      stdout: 'approved run appr-7788'
    })
    expect(engineRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'POST',
        target: '/v1/workspace/exec-plan',
        body: JSON.stringify({
          worktree_path: 'D:\\repos\\nachuan\\.worktrees\\feat-auth-fix',
          mode: 'build',
          command: 'npm test',
          approval_id: 'appr-7788'
        })
      })
    )

    // 6) 英文双语完整覆盖 & 默认导出组件安全 SSR
    await i18n.changeLanguage('en')
    const enHtml = renderToStaticMarkup(
      <CodingControlPane
        initialRepoPath="D:\\repos\\nachuan"
        initialWorktreeList={SAMPLE_WORKTREES}
        initialDiffSnapshot={SAMPLE_DIFF}
      />
    )
    expect(enHtml).toContain('Coding Control Plane')
    expect(enHtml).toContain('Parallel Worktrees')
    expect(enHtml).toContain('Visual Diff Review')
    expect(enHtml).toContain('Plan / Build Command Console')
    expect(enHtml).toContain('Commit locally')
    expect(enHtml).not.toContain('编码控制面')
  })

  it('auto-detects system navigator language for global i18n and honors explicit user overrides', async () => {
    const storage = fakeLocalStorage()
    vi.stubGlobal('localStorage', storage)

    // 英文系统与国际系统默认展示英文界面
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: ['en-US', 'en'],
        navigatorLanguage: 'en-US'
      })
    ).toBe('en')
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: ['ja-JP'],
        navigatorLanguage: 'ja-JP'
      })
    ).toBe('en')
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: ['en-GB', 'zh-CN'],
        navigatorLanguage: 'en-GB'
      })
    ).toBe('en')

    // 中文系统默认展示中文界面
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: ['zh-CN', 'en-US'],
        navigatorLanguage: 'zh-CN'
      })
    ).toBe('zh')
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: ['zh-TW'],
        navigatorLanguage: 'zh-TW'
      })
    ).toBe('zh')

    // 无 navigator 信息时回退中文
    expect(
      detectPreferredLanguage({
        storedLanguage: null,
        navigatorLanguages: [],
        navigatorLanguage: ''
      })
    ).toBe('zh')

    // 用户手工切换后写入持久化偏好并压过系统 navigator.language
    await setAppLanguage('en')
    expect(localStorage.getItem(LANG_STORAGE_KEY)).toBe('en')
    expect(i18n.language).toBe('en')
    expect(
      detectPreferredLanguage({
        navigatorLanguages: ['zh-CN'],
        navigatorLanguage: 'zh-CN'
      })
    ).toBe('en')

    await setAppLanguage('zh')
    expect(localStorage.getItem(LANG_STORAGE_KEY)).toBe('zh')
    expect(i18n.language).toBe('zh')
    expect(
      detectPreferredLanguage({
        navigatorLanguages: ['en-US'],
        navigatorLanguage: 'en-US'
      })
    ).toBe('zh')
  })
})
