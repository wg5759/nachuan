import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'

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
  type CodingAgentEngine,
  type CodingApproval,
  type CodingDiffFile,
  type CodingExecResponse,
  type CodingExecResultDetail,
  type CodingSession,
  type CodingSessionDiff,
  type CodingSessionMode
} from '../api'
import { useTranslation } from '../i18n'

export const CODING_AGENT_ENGINES: readonly CodingAgentEngine[] = [
  'codex',
  'claude-code',
  'opencode',
  'kimi-code',
  'local-ollama',
  'byok-cloud'
]

export const QUICK_SANDBOX_COMMANDS: readonly string[] = [
  'git status',
  'git diff',
  'npm run typecheck',
  'pytest'
]

export const CODING_APPROVALS_POLL_INTERVAL_MS = 5000

export type CodingApprovalsFilter = 'pending' | 'all'

export interface ParsedDiffLine {
  kind: 'meta' | 'hunk' | 'add' | 'del' | 'context'
  text: string
  oldLine: number | null
  newLine: number | null
}

const HUNK_HEADER_RE = /^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/

/**
 * 将后端返回的 Unified Diff 字符串解析为带左右行号与语义类型的结构化行列表，
 * 用于中栏逐行红绿着色预览器渲染。
 */
export function parseUnifiedDiffLines(diff: string): ParsedDiffLine[] {
  if (!diff) return []
  const lines = diff.replace(/\r\n/g, '\n').split('\n')
  const parsed: ParsedDiffLine[] = []
  let oldNum: number | null = null
  let newNum: number | null = null

  for (const text of lines) {
    const hunkMatch = HUNK_HEADER_RE.exec(text)
    if (hunkMatch) {
      oldNum = Number(hunkMatch[1])
      newNum = Number(hunkMatch[2])
      parsed.push({ kind: 'hunk', text, oldLine: null, newLine: null })
      continue
    }
    if (
      text.startsWith('diff --git ') ||
      text.startsWith('index ') ||
      text.startsWith('--- ') ||
      text.startsWith('+++ ') ||
      text.startsWith('new file mode ') ||
      text.startsWith('deleted file mode ')
    ) {
      parsed.push({ kind: 'meta', text, oldLine: null, newLine: null })
      continue
    }
    if (text.startsWith('+')) {
      const currentNew = newNum
      if (newNum !== null) newNum += 1
      parsed.push({ kind: 'add', text, oldLine: null, newLine: currentNew })
      continue
    }
    if (text.startsWith('-')) {
      const currentOld = oldNum
      if (oldNum !== null) oldNum += 1
      parsed.push({ kind: 'del', text, oldLine: currentOld, newLine: null })
      continue
    }
    const currentOld = oldNum
    const currentNew = newNum
    if (oldNum !== null) oldNum += 1
    if (newNum !== null) newNum += 1
    parsed.push({ kind: 'context', text, oldLine: currentOld, newLine: currentNew })
  }
  return parsed
}

/** 从 FastAPI 风格错误文本（例如 `403 {"detail":"..."}`）中提取友好可读的错误说明。 */
export function extractCodingErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error ?? 'Unknown error')
  const jsonStart = raw.indexOf('{')
  if (jsonStart >= 0) {
    try {
      const parsed = JSON.parse(raw.slice(jsonStart)) as { detail?: unknown; message?: unknown }
      if (typeof parsed.detail === 'string' && parsed.detail.trim()) {
        return parsed.detail.trim()
      }
      if (typeof parsed.message === 'string' && parsed.message.trim()) {
        return parsed.message.trim()
      }
    } catch {
      // 回退到原始错误消息
    }
  }
  return raw
}

function ShieldIcon({ mode }: { mode: CodingSessionMode }): React.ReactElement {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.9}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 3 19 6v5.4c0 4.3-2.8 7.8-7 9.6-4.2-1.8-7-5.3-7-9.6V6l7-3Z" />
      {mode === 'plan' ? (
        <path d="M9.5 12h5M12 9.5v5" />
      ) : (
        <path d="m9 12.2 2 2 4.2-4.4" />
      )}
    </svg>
  )
}

export type CodingStudioTranslate = (key: string, opts?: Record<string, unknown>) => string

export interface CodingStudioPaneViewProps {
  sessions: readonly CodingSession[]
  selectedSessionId: string | null
  diff: CodingSessionDiff | null
  activeDiffFilePath: string | null
  checkedFiles: ReadonlySet<string>
  approvals: readonly CodingApproval[]
  approvalsFilter: CodingApprovalsFilter
  approvalNotes: Readonly<Record<string, string>>
  // 创建表单状态
  repoPath: string
  taskTitle: string
  baseRef: string
  agentEngine: CodingAgentEngine
  initialMode: CodingSessionMode
  deleteBranchOnDestroy: boolean
  // 提交 & 命令沙箱状态
  commitMessage: string
  commandInput: string
  lastExecResponse: CodingExecResponse | null
  // 加载 / 操作态
  loadingSessions: boolean
  loadingDiff: boolean
  creatingSession: boolean
  switchingMode: boolean
  revertingPath: string | null
  committing: boolean
  destroyingSessionId: string | null
  executingCommand: boolean
  resolvingApprovalId: string | null
  notice?: string
  error?: string
  // 回调
  onRefreshAll: () => void
  onSelectSession: (sessionId: string) => void
  onRepoPathChange: (value: string) => void
  onTaskTitleChange: (value: string) => void
  onBaseRefChange: (value: string) => void
  onAgentEngineChange: (engine: CodingAgentEngine) => void
  onInitialModeChange: (mode: CodingSessionMode) => void
  onCreateSession: () => void
  onToggleDeleteBranchOnDestroy: (checked: boolean) => void
  onDestroySession: (session: CodingSession) => void
  onSwitchMode: (mode: CodingSessionMode) => void
  onRefreshDiff: () => void
  onSelectDiffFile: (path: string) => void
  onToggleFileChecked: (path: string) => void
  onSelectAllFiles: () => void
  onClearFileSelection: () => void
  onRevertFile: (path: string) => void
  onCommitMessageChange: (value: string) => void
  onCommit: () => void
  onCommandInputChange: (value: string) => void
  onRunCommand: (overrideCommand?: string) => void
  onApprovalsFilterChange: (filter: CodingApprovalsFilter) => void
  onApprovalNoteChange: (approvalId: string, note: string) => void
  onResolveApproval: (approvalId: string, decision: 'approve' | 'reject') => void
  onDismissBanner?: () => void
}

function renderExecResultBox(
  result: CodingExecResultDetail,
  t: CodingStudioTranslate,
  testId = 'sandbox-exec-output'
): React.ReactElement {
  const ok = result.exit_code === 0
  return (
    <div
      className={`nachuan-coding-terminal${ok ? ' is-ok' : ' is-fail'}`}
      data-testid={testId}
    >
      <div className="nachuan-coding-terminal-head">
        <span className={`nachuan-coding-exit-badge${ok ? ' is-ok' : ' is-fail'}`}>
          {t('codingStudio.exitCode', { code: result.exit_code })}
        </span>
        <span className="nachuan-coding-duration">
          {t('codingStudio.durationMs', { ms: Math.round(result.duration_ms) })}
        </span>
      </div>
      <div className="nachuan-coding-terminal-stream">
        <span className="nachuan-coding-stream-label">{t('codingStudio.stdoutLabel')}</span>
        <pre>{result.stdout || t('codingStudio.emptyOutput')}</pre>
      </div>
      {result.stderr ? (
        <div className="nachuan-coding-terminal-stream is-stderr">
          <span className="nachuan-coding-stream-label">{t('codingStudio.stderrLabel')}</span>
          <pre>{result.stderr}</pre>
        </div>
      ) : null}
    </div>
  )
}

function approvalStatusLabel(status: CodingApproval['status'], t: CodingStudioTranslate): string {
  if (status === 'approved') return t('codingStudio.statusApproved')
  if (status === 'rejected') return t('codingStudio.statusRejected')
  if (status === 'expired') return t('codingStudio.statusExpired')
  return t('codingStudio.statusPending')
}

export function buildCodingStudioPaneTree(
  props: CodingStudioPaneViewProps,
  t: CodingStudioTranslate
): React.ReactElement {
  const {
    sessions,
    selectedSessionId,
    diff,
    activeDiffFilePath,
    checkedFiles,
    approvals,
    approvalsFilter,
    approvalNotes,
    repoPath,
    taskTitle,
    baseRef,
    agentEngine,
    initialMode,
    deleteBranchOnDestroy,
    commitMessage,
    commandInput,
    lastExecResponse,
    loadingSessions,
    loadingDiff,
    creatingSession,
    switchingMode,
    revertingPath,
    committing,
    destroyingSessionId,
    executingCommand,
    resolvingApprovalId,
    notice = '',
    error = '',
    onRefreshAll,
    onSelectSession,
    onRepoPathChange,
    onTaskTitleChange,
    onBaseRefChange,
    onAgentEngineChange,
    onInitialModeChange,
    onCreateSession,
    onToggleDeleteBranchOnDestroy,
    onDestroySession,
    onSwitchMode,
    onRefreshDiff,
    onSelectDiffFile,
    onToggleFileChecked,
    onSelectAllFiles,
    onClearFileSelection,
    onRevertFile,
    onCommitMessageChange,
    onCommit,
    onCommandInputChange,
    onRunCommand,
    onApprovalsFilterChange,
    onApprovalNoteChange,
    onResolveApproval,
    onDismissBanner
  } = props

  const selectedSession =
    sessions.find((item) => item.session_id === selectedSessionId) ?? null
  const pendingApprovalCount = approvals.filter((item) => item.status === 'pending').length
  const visibleApprovals =
    approvalsFilter === 'pending'
      ? approvals.filter((item) => item.status === 'pending')
      : approvals
  const diffFiles: readonly CodingDiffFile[] = diff?.files ?? []
  const activeFile =
    diffFiles.find((file) => file.path === activeDiffFilePath) ?? diffFiles[0] ?? null
  const parsedDiffLines = activeFile ? parseUnifiedDiffLines(activeFile.diff) : []
  const checkedCount = diffFiles.filter((file) => checkedFiles.has(file.path)).length

  return (
    <main
      className="nachuan-coding-studio"
      data-testid="coding-studio-pane"
      aria-labelledby="coding-studio-title"
    >
      <header className="nachuan-coding-header">
        <div className="nachuan-coding-header-copy">
          <span className="nachuan-eyebrow">{t('codingStudio.eyebrow')}</span>
          <div className="nachuan-coding-title-row">
            <h1 id="coding-studio-title">{t('codingStudio.title')}</h1>
            <span className="nachuan-coding-pill" data-testid="coding-active-count">
              {t('codingStudio.activeCount', { n: sessions.length })}
            </span>
            <span
              className={`nachuan-coding-pill${pendingApprovalCount > 0 ? ' is-alert' : ''}`}
              data-testid="coding-pending-count"
            >
              {t('codingStudio.pendingCount', { n: pendingApprovalCount })}
            </span>
          </div>
          <p>{t('codingStudio.subtitle')}</p>
        </div>
        <div className="nachuan-coding-header-actions">
          <button
            type="button"
            data-testid="coding-refresh-all"
            className="nachuan-coding-btn"
            disabled={loadingSessions}
            onClick={onRefreshAll}
          >
            {loadingSessions ? t('codingStudio.refreshing') : t('codingStudio.refresh')}
          </button>
        </div>
      </header>

      {notice ? (
        <div className="nachuan-coding-banner is-ok" role="status" data-testid="coding-notice">
          <span>{notice}</span>
          {onDismissBanner ? (
            <button type="button" onClick={onDismissBanner}>
              {t('codingStudio.dismiss')}
            </button>
          ) : null}
        </div>
      ) : null}

      {error ? (
        <div className="nachuan-coding-banner is-error" role="alert" data-testid="coding-error">
          <span>{error}</span>
          {onDismissBanner ? (
            <button type="button" onClick={onDismissBanner}>
              {t('codingStudio.dismiss')}
            </button>
          ) : null}
        </div>
      ) : null}

      <div className="nachuan-coding-grid">
        {/* ── 左栏：并发 Worktree 管理 ─────────────────────────────────── */}
        <section
          className="nachuan-coding-col nachuan-coding-col--sessions"
          data-testid="coding-sessions-column"
          aria-label={t('codingStudio.sessionsTitle')}
        >
          <div className="nachuan-coding-card">
            <h2 className="nachuan-coding-section-title">{t('codingStudio.newSessionTitle')}</h2>
            <form
              className="nachuan-coding-form"
              data-testid="create-session-form"
              onSubmit={(event) => {
                event.preventDefault()
                onCreateSession()
              }}
            >
              <label className="nachuan-coding-field">
                <span>{t('codingStudio.repoPathLabel')}</span>
                <input
                  type="text"
                  data-testid="input-repo-path"
                  value={repoPath}
                  onChange={(event) => onRepoPathChange(event.target.value)}
                  placeholder={t('codingStudio.repoPathPh')}
                  spellCheck={false}
                />
              </label>

              <label className="nachuan-coding-field">
                <span>{t('codingStudio.taskTitleLabel')}</span>
                <input
                  type="text"
                  data-testid="input-session-title"
                  value={taskTitle}
                  onChange={(event) => onTaskTitleChange(event.target.value)}
                  placeholder={t('codingStudio.taskTitlePh')}
                />
              </label>

              <div className="nachuan-coding-field-row">
                <label className="nachuan-coding-field">
                  <span>{t('codingStudio.engineLabel')}</span>
                  <select
                    data-testid="select-agent-engine"
                    value={agentEngine}
                    onChange={(event) =>
                      onAgentEngineChange(event.target.value as CodingAgentEngine)
                    }
                  >
                    {CODING_AGENT_ENGINES.map((engine) => (
                      <option key={engine} value={engine}>
                        {t(`codingStudio.engines.${engine}`)}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="nachuan-coding-field">
                  <span>{t('codingStudio.baseRefLabel')}</span>
                  <input
                    type="text"
                    data-testid="input-base-ref"
                    value={baseRef}
                    onChange={(event) => onBaseRefChange(event.target.value)}
                    placeholder={t('codingStudio.baseRefPh')}
                    spellCheck={false}
                  />
                </label>
              </div>

              <div className="nachuan-coding-field">
                <span>{t('codingStudio.initialModeLabel')}</span>
                <div
                  className="nachuan-coding-mode-switch"
                  role="group"
                  aria-label={t('codingStudio.initialModeLabel')}
                >
                  <button
                    type="button"
                    data-testid="create-mode-plan"
                    aria-pressed={initialMode === 'plan'}
                    className={`nachuan-coding-mode-btn is-plan${
                      initialMode === 'plan' ? ' is-active' : ''
                    }`}
                    onClick={() => onInitialModeChange('plan')}
                  >
                    <ShieldIcon mode="plan" />
                    <span>{t('codingStudio.modePlanShort')}</span>
                  </button>
                  <button
                    type="button"
                    data-testid="create-mode-build"
                    aria-pressed={initialMode === 'build'}
                    className={`nachuan-coding-mode-btn is-build${
                      initialMode === 'build' ? ' is-active' : ''
                    }`}
                    onClick={() => onInitialModeChange('build')}
                  >
                    <ShieldIcon mode="build" />
                    <span>{t('codingStudio.modeBuildShort')}</span>
                  </button>
                </div>
              </div>

              <button
                type="submit"
                data-testid="btn-create-session"
                className="nachuan-coding-btn nachuan-coding-btn--primary"
                disabled={creatingSession}
              >
                {creatingSession ? t('codingStudio.creatingBtn') : t('codingStudio.createBtn')}
              </button>
            </form>
          </div>

          <div className="nachuan-coding-card nachuan-coding-sessions-card">
            <div className="nachuan-coding-section-head">
              <h2 className="nachuan-coding-section-title">{t('codingStudio.sessionsTitle')}</h2>
              <label className="nachuan-coding-inline-check">
                <input
                  type="checkbox"
                  data-testid="checkbox-delete-branch"
                  checked={deleteBranchOnDestroy}
                  onChange={(event) => onToggleDeleteBranchOnDestroy(event.target.checked)}
                />
                <span>{t('codingStudio.deleteBranchLabel')}</span>
              </label>
            </div>

            <div className="nachuan-coding-session-list" data-testid="coding-session-list">
              {sessions.length === 0 ? (
                <p className="nachuan-coding-empty">{t('codingStudio.emptySessions')}</p>
              ) : (
                sessions.map((session) => {
                  const active = session.session_id === selectedSessionId
                  const destroying = destroyingSessionId === session.session_id
                  return (
                    <article
                      key={session.session_id}
                      data-testid={`session-item-${session.session_id}`}
                      data-session-mode={session.mode}
                      className={`nachuan-coding-session-item${active ? ' is-active' : ''}`}
                    >
                      <button
                        type="button"
                        data-testid={`btn-select-session-${session.session_id}`}
                        className="nachuan-coding-session-select"
                        onClick={() => onSelectSession(session.session_id)}
                      >
                        <div className="nachuan-coding-session-top">
                          <strong className="nachuan-coding-session-title">{session.title}</strong>
                          <span
                            className={`nachuan-shield-badge nachuan-shield-badge--${session.mode}`}
                          >
                            <ShieldIcon mode={session.mode} />
                            <span>
                              {session.mode === 'plan'
                                ? t('codingStudio.modePlanShort')
                                : t('codingStudio.modeBuildShort')}
                            </span>
                          </span>
                        </div>
                        <div className="nachuan-coding-session-meta">
                          <code className="nachuan-coding-branch">{session.branch}</code>
                          <span className="nachuan-coding-engine-tag">
                            {session.agent_engine}
                          </span>
                        </div>
                        {session.worktree_exists === false ? (
                          <span className="nachuan-coding-missing-tag">
                            {t('codingStudio.worktreeMissing')}
                          </span>
                        ) : null}
                      </button>
                      <button
                        type="button"
                        data-testid={`btn-destroy-${session.session_id}`}
                        className="nachuan-coding-btn nachuan-coding-btn--danger-ghost"
                        disabled={destroying}
                        onClick={() => onDestroySession(session)}
                      >
                        {destroying ? t('codingStudio.destroyingBtn') : t('codingStudio.destroyBtn')}
                      </button>
                    </article>
                  )
                })
              )}
            </div>
          </div>
        </section>

        {/* ── 中栏：可视化 Diff 审阅 + 精准回滚/采纳 ────────────────────── */}
        <section
          className="nachuan-coding-col nachuan-coding-col--diff"
          data-testid="coding-diff-column"
          aria-label={t('codingStudio.diffTitle')}
        >
          {!selectedSession ? (
            <div className="nachuan-coding-card nachuan-coding-empty-panel">
              <p>{t('codingStudio.noSessionSelected')}</p>
            </div>
          ) : (
            <div className="nachuan-coding-card nachuan-coding-diff-card">
              <div className="nachuan-coding-session-banner">
                <div className="nachuan-coding-session-banner-info">
                  <div className="nachuan-coding-session-banner-title">
                    <h2>{selectedSession.title}</h2>
                    <span className="nachuan-coding-engine-tag">
                      {selectedSession.agent_engine}
                    </span>
                  </div>
                  <div className="nachuan-coding-session-paths">
                    <code className="nachuan-coding-branch">{selectedSession.branch}</code>
                    <span className="nachuan-coding-wt-path" title={selectedSession.worktree_path}>
                      {selectedSession.worktree_path}
                    </span>
                  </div>
                </div>

                <div
                  className="nachuan-coding-mode-switch"
                  role="group"
                  aria-label={t('codingStudio.initialModeLabel')}
                >
                  <button
                    type="button"
                    data-testid="btn-mode-plan"
                    aria-pressed={selectedSession.mode === 'plan'}
                    disabled={switchingMode}
                    className={`nachuan-coding-mode-btn is-plan${
                      selectedSession.mode === 'plan' ? ' is-active' : ''
                    }`}
                    onClick={() => onSwitchMode('plan')}
                  >
                    <ShieldIcon mode="plan" />
                    <span>{t('codingStudio.modePlan')}</span>
                  </button>
                  <button
                    type="button"
                    data-testid="btn-mode-build"
                    aria-pressed={selectedSession.mode === 'build'}
                    disabled={switchingMode}
                    className={`nachuan-coding-mode-btn is-build${
                      selectedSession.mode === 'build' ? ' is-active' : ''
                    }`}
                    onClick={() => onSwitchMode('build')}
                  >
                    <ShieldIcon mode="build" />
                    <span>{t('codingStudio.modeBuild')}</span>
                  </button>
                </div>
              </div>

              <div className="nachuan-coding-diff-summary" data-testid="diff-summary-bar">
                <div className="nachuan-coding-diff-stats">
                  <strong>
                    {t('codingStudio.filesChanged', { n: diff?.file_count ?? diffFiles.length })}
                  </strong>
                  <span className="nachuan-diff-stat is-add" data-testid="diff-total-additions">
                    +{diff?.total_additions ?? 0}
                  </span>
                  <span className="nachuan-diff-stat is-del" data-testid="diff-total-deletions">
                    -{diff?.total_deletions ?? 0}
                  </span>
                  {diffFiles.length > 0 ? (
                    <span className="nachuan-coding-muted-note">
                      {t('codingStudio.selectedFilesCount', {
                        selected: checkedCount,
                        total: diffFiles.length
                      })}
                    </span>
                  ) : null}
                </div>

                <div className="nachuan-coding-diff-toolbar">
                  {diffFiles.length > 0 ? (
                    <>
                      <button
                        type="button"
                        data-testid="btn-select-all-files"
                        className="nachuan-coding-btn nachuan-coding-btn--sm"
                        onClick={onSelectAllFiles}
                      >
                        {t('codingStudio.selectAll')}
                      </button>
                      <button
                        type="button"
                        data-testid="btn-clear-file-selection"
                        className="nachuan-coding-btn nachuan-coding-btn--sm"
                        onClick={onClearFileSelection}
                      >
                        {t('codingStudio.selectNone')}
                      </button>
                    </>
                  ) : null}
                  <button
                    type="button"
                    data-testid="btn-refresh-diff"
                    className="nachuan-coding-btn nachuan-coding-btn--sm"
                    disabled={loadingDiff}
                    onClick={onRefreshDiff}
                  >
                    {loadingDiff ? t('codingStudio.refreshing') : t('codingStudio.refresh')}
                  </button>
                </div>
              </div>

              {diffFiles.length === 0 ? (
                <p className="nachuan-coding-empty" data-testid="diff-clean-state">
                  {t('codingStudio.noChanges')}
                </p>
              ) : (
                <>
                  <ul className="nachuan-coding-file-list" data-testid="diff-file-list">
                    {diffFiles.map((file) => {
                      const isChecked = checkedFiles.has(file.path)
                      const isActive = activeFile?.path === file.path
                      const reverting = revertingPath === file.path
                      return (
                        <li
                          key={file.path}
                          data-testid={`diff-file-row-${file.path}`}
                          className={`nachuan-coding-file-row${isActive ? ' is-active' : ''}`}
                        >
                          <input
                            type="checkbox"
                            data-testid={`checkbox-file-${file.path}`}
                            checked={isChecked}
                            aria-label={file.path}
                            onChange={() => onToggleFileChecked(file.path)}
                          />
                          <button
                            type="button"
                            data-testid={`btn-open-diff-${file.path}`}
                            className="nachuan-coding-file-trigger"
                            onClick={() => onSelectDiffFile(file.path)}
                          >
                            <span className="nachuan-coding-file-status">{file.status}</span>
                            <code className="nachuan-coding-file-path">{file.path}</code>
                            <span className="nachuan-diff-stat is-add">+{file.additions}</span>
                            <span className="nachuan-diff-stat is-del">-{file.deletions}</span>
                          </button>
                          <button
                            type="button"
                            data-testid={`btn-revert-${file.path}`}
                            className="nachuan-coding-btn nachuan-coding-btn--sm nachuan-coding-btn--danger-ghost"
                            disabled={reverting}
                            onClick={() => onRevertFile(file.path)}
                          >
                            {reverting
                              ? t('codingStudio.revertingBtn')
                              : t('codingStudio.revertBtn')}
                          </button>
                        </li>
                      )
                    })}
                  </ul>

                  <div className="nachuan-coding-diff-viewer" data-testid="unified-diff-viewer">
                    {activeFile ? (
                      <>
                        <div className="nachuan-coding-diff-viewer-head">
                          <code>{activeFile.path}</code>
                          <span>
                            <em className="nachuan-diff-stat is-add">+{activeFile.additions}</em>{' '}
                            <em className="nachuan-diff-stat is-del">-{activeFile.deletions}</em>
                          </span>
                        </div>
                        <div className="nachuan-coding-diff-code" role="region" aria-label={activeFile.path}>
                          {parsedDiffLines.map((line, index) => (
                            <div
                              key={`${activeFile.path}-${index}`}
                              className={`nachuan-diff-line nachuan-diff-line--${line.kind}`}
                              data-diff-kind={line.kind}
                            >
                              <span className="nachuan-diff-ln">{line.oldLine ?? ''}</span>
                              <span className="nachuan-diff-ln">{line.newLine ?? ''}</span>
                              <span className="nachuan-diff-text">{line.text || ' '}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <p className="nachuan-coding-empty">{t('codingStudio.diffEmptyHint')}</p>
                    )}
                  </div>
                </>
              )}

              <form
                className="nachuan-coding-commit-bar"
                data-testid="commit-form"
                onSubmit={(event) => {
                  event.preventDefault()
                  onCommit()
                }}
              >
                <div className="nachuan-coding-commit-input-wrap">
                  <label htmlFor="coding-commit-message">
                    {t('codingStudio.commitMessageLabel')}
                  </label>
                  <input
                    id="coding-commit-message"
                    type="text"
                    data-testid="input-commit-message"
                    value={commitMessage}
                    onChange={(event) => onCommitMessageChange(event.target.value)}
                    placeholder={t('codingStudio.commitMessagePh')}
                  />
                  <small className="nachuan-coding-muted-note">
                    {checkedCount > 0
                      ? t('codingStudio.commitSelectedHint', { n: checkedCount })
                      : t('codingStudio.commitAllHint')}
                  </small>
                </div>
                <button
                  type="submit"
                  data-testid="btn-commit-session"
                  className="nachuan-coding-btn nachuan-coding-btn--primary"
                  disabled={committing || diffFiles.length === 0}
                >
                  {committing ? t('codingStudio.committingBtn') : t('codingStudio.commitBtn')}
                </button>
              </form>
            </div>
          )}
        </section>

        {/* ── 右/下栏：Plan/Build 命令沙箱 & 跨端移动审批队列 ────────────── */}
        <section
          className="nachuan-coding-col nachuan-coding-col--sandbox"
          data-testid="coding-sandbox-column"
          aria-label={t('codingStudio.sandboxTitle')}
        >
          <div className="nachuan-coding-card">
            <h2 className="nachuan-coding-section-title">{t('codingStudio.sandboxTitle')}</h2>

            {selectedSession ? (
              selectedSession.mode === 'plan' ? (
                <div
                  className="nachuan-coding-shield-banner is-plan"
                  data-testid="plan-readonly-banner"
                >
                  <div className="nachuan-coding-shield-banner-text">
                    <ShieldIcon mode="plan" />
                    <span>{t('codingStudio.planShieldNotice')}</span>
                  </div>
                  <button
                    type="button"
                    data-testid="btn-banner-switch-build"
                    className="nachuan-coding-btn nachuan-coding-btn--sm"
                    disabled={switchingMode}
                    onClick={() => onSwitchMode('build')}
                  >
                    {t('codingStudio.switchToBuildBtn')}
                  </button>
                </div>
              ) : (
                <div
                  className="nachuan-coding-shield-banner is-build"
                  data-testid="build-exec-banner"
                >
                  <div className="nachuan-coding-shield-banner-text">
                    <ShieldIcon mode="build" />
                    <span>{t('codingStudio.buildShieldNotice')}</span>
                  </div>
                  <button
                    type="button"
                    data-testid="btn-banner-switch-plan"
                    className="nachuan-coding-btn nachuan-coding-btn--sm"
                    disabled={switchingMode}
                    onClick={() => onSwitchMode('plan')}
                  >
                    {t('codingStudio.switchToPlanBtn')}
                  </button>
                </div>
              )
            ) : null}

            <form
              className="nachuan-coding-exec-form"
              data-testid="sandbox-exec-form"
              onSubmit={(event) => {
                event.preventDefault()
                onRunCommand()
              }}
            >
              <input
                type="text"
                data-testid="input-sandbox-command"
                value={commandInput}
                onChange={(event) => onCommandInputChange(event.target.value)}
                placeholder={t('codingStudio.commandPh')}
                disabled={!selectedSession || executingCommand}
                spellCheck={false}
              />
              <button
                type="submit"
                data-testid="btn-exec-command"
                className="nachuan-coding-btn nachuan-coding-btn--primary"
                disabled={!selectedSession || executingCommand}
              >
                {executingCommand ? t('codingStudio.runningBtn') : t('codingStudio.runBtn')}
              </button>
            </form>

            <div className="nachuan-coding-quick-cmds" aria-label={t('codingStudio.quickCommands')}>
              {QUICK_SANDBOX_COMMANDS.map((cmd) => (
                <button
                  key={cmd}
                  type="button"
                  className="nachuan-coding-quick-chip"
                  disabled={!selectedSession || executingCommand}
                  onClick={() => onRunCommand(cmd)}
                >
                  {cmd}
                </button>
              ))}
            </div>

            {lastExecResponse ? (
              lastExecResponse.status === 'executed' ? (
                renderExecResultBox(lastExecResponse.result, t, 'sandbox-exec-output')
              ) : (
                <div
                  className="nachuan-coding-pending-alert"
                  data-testid="sandbox-pending-approval-notice"
                  role="status"
                >
                  <strong>
                    {t('codingStudio.queuedForApprovalNotice', {
                      id: lastExecResponse.approval.approval_id
                    })}
                  </strong>
                  <code>{lastExecResponse.approval.command}</code>
                  <p>{lastExecResponse.approval.reason}</p>
                </div>
              )
            ) : null}
          </div>

          <div
            className="nachuan-coding-card nachuan-coding-approvals-card"
            data-testid="coding-approvals-panel"
          >
            <div className="nachuan-coding-section-head">
              <div>
                <h2 className="nachuan-coding-section-title">{t('codingStudio.approvalsTitle')}</h2>
                <p className="nachuan-coding-muted-note">{t('codingStudio.approvalsHint')}</p>
              </div>
              <div className="nachuan-segmented" role="group" aria-label={t('codingStudio.approvalsTitle')}>
                <button
                  type="button"
                  data-testid="approvals-filter-pending"
                  aria-pressed={approvalsFilter === 'pending'}
                  onClick={() => onApprovalsFilterChange('pending')}
                >
                  {t('codingStudio.filterPending')}
                </button>
                <button
                  type="button"
                  data-testid="approvals-filter-all"
                  aria-pressed={approvalsFilter === 'all'}
                  onClick={() => onApprovalsFilterChange('all')}
                >
                  {t('codingStudio.filterAll')}
                </button>
              </div>
            </div>

            {visibleApprovals.length === 0 ? (
              <p className="nachuan-coding-empty" data-testid="approvals-empty-state">
                {t('codingStudio.emptyApprovals')}
              </p>
            ) : (
              <div className="nachuan-coding-approval-list">
                {visibleApprovals.map((approval) => {
                  const isPending = approval.status === 'pending'
                  const resolving = resolvingApprovalId === approval.approval_id
                  const noteValue = approvalNotes[approval.approval_id] ?? ''
                  return (
                    <article
                      key={approval.approval_id}
                      data-testid={`approval-card-${approval.approval_id}`}
                      data-approval-status={approval.status}
                      className={`nachuan-coding-approval-card is-${approval.status}`}
                    >
                      <div className="nachuan-coding-approval-top">
                        <span className={`nachuan-coding-approval-status is-${approval.status}`}>
                          {approvalStatusLabel(approval.status, t)}
                        </span>
                        <code className="nachuan-coding-approval-id">{approval.approval_id}</code>
                        <span className="nachuan-coding-muted-note">
                          {t('codingStudio.approvalSession')}: {approval.session_id}
                        </span>
                      </div>

                      <pre className="nachuan-coding-approval-cmd">{approval.command}</pre>

                      <p className="nachuan-coding-approval-reason">
                        <strong>{t('codingStudio.approvalReason')}:</strong> {approval.reason}
                      </p>

                      {isPending ? (
                        <>
                          <input
                            type="text"
                            className="nachuan-coding-approval-note"
                            data-testid={`input-approval-note-${approval.approval_id}`}
                            value={noteValue}
                            onChange={(event) =>
                              onApprovalNoteChange(approval.approval_id, event.target.value)
                            }
                            placeholder={t('codingStudio.approvalNotePh')}
                            maxLength={300}
                          />
                          <div className="nachuan-coding-approval-actions">
                            <button
                              type="button"
                              data-testid={`btn-approve-${approval.approval_id}`}
                              className="nachuan-coding-touch-btn is-approve"
                              disabled={resolving}
                              onClick={() => onResolveApproval(approval.approval_id, 'approve')}
                            >
                              {resolving
                                ? t('codingStudio.approvingBtn')
                                : t('codingStudio.approveBtn')}
                            </button>
                            <button
                              type="button"
                              data-testid={`btn-reject-${approval.approval_id}`}
                              className="nachuan-coding-touch-btn is-reject"
                              disabled={resolving}
                              onClick={() => onResolveApproval(approval.approval_id, 'reject')}
                            >
                              {resolving
                                ? t('codingStudio.rejectingBtn')
                                : t('codingStudio.rejectBtn')}
                            </button>
                          </div>
                        </>
                      ) : null}

                      {approval.exec_result
                        ? renderExecResultBox(
                            approval.exec_result,
                            t,
                            `approval-exec-result-${approval.approval_id}`
                          )
                        : null}
                    </article>
                  )
                })}
              </div>
            )}
          </div>
        </section>
      </div>
    </main>
  )
}

export function CodingStudioPaneView(props: CodingStudioPaneViewProps): React.ReactElement {
  const { t } = useTranslation()
  return buildCodingStudioPaneTree(props, t)
}

export interface CodingStudioPaneProps {
  initialSessions?: CodingSession[]
  initialDiff?: CodingSessionDiff | null
  initialApprovals?: CodingApproval[]
  pollIntervalMs?: number
}

export default function CodingStudioPane({
  initialSessions = [],
  initialDiff = null,
  initialApprovals = [],
  pollIntervalMs = CODING_APPROVALS_POLL_INTERVAL_MS
}: CodingStudioPaneProps = {}): React.ReactElement {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<CodingSession[]>(initialSessions)
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    initialSessions[0]?.session_id ?? null
  )
  const [diff, setDiff] = useState<CodingSessionDiff | null>(initialDiff)
  const [activeDiffFilePath, setActiveDiffFilePath] = useState<string | null>(
    initialDiff?.files[0]?.path ?? null
  )
  const [checkedFiles, setCheckedFiles] = useState<Set<string>>(() => new Set())
  const [approvals, setApprovals] = useState<CodingApproval[]>(initialApprovals)
  const [approvalsFilter, setApprovalsFilter] = useState<CodingApprovalsFilter>('pending')
  const [approvalNotes, setApprovalNotes] = useState<Record<string, string>>({})

  const [repoPath, setRepoPath] = useState('')
  const [taskTitle, setTaskTitle] = useState('')
  const [baseRef, setBaseRef] = useState('HEAD')
  const [agentEngine, setAgentEngine] = useState<CodingAgentEngine>('codex')
  const [initialMode, setInitialMode] = useState<CodingSessionMode>('plan')
  const [deleteBranchOnDestroy, setDeleteBranchOnDestroy] = useState(true)

  const [commitMessage, setCommitMessage] = useState('')
  const [commandInput, setCommandInput] = useState('')
  const [lastExecResponse, setLastExecResponse] = useState<CodingExecResponse | null>(null)

  const [loadingSessions, setLoadingSessions] = useState(false)
  const [loadingDiff, setLoadingDiff] = useState(false)
  const [creatingSession, setCreatingSession] = useState(false)
  const [switchingMode, setSwitchingMode] = useState(false)
  const [revertingPath, setRevertingPath] = useState<string | null>(null)
  const [committing, setCommitting] = useState(false)
  const [destroyingSessionId, setDestroyingSessionId] = useState<string | null>(null)
  const [executingCommand, setExecutingCommand] = useState(false)
  const [resolvingApprovalId, setResolvingApprovalId] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  const mountedRef = useRef(true)

  const loadApprovals = useCallback(async (filter: CodingApprovalsFilter) => {
    try {
      const next = await listCodingApprovals(filter === 'pending' ? 'pending' : undefined)
      if (!mountedRef.current) return
      setApprovals(next)
    } catch {
      // 后台轮询失败不打断用户当前操作
    }
  }, [])

  const loadDiff = useCallback(async (sessionId: string | null) => {
    if (!sessionId) {
      setDiff(null)
      setActiveDiffFilePath(null)
      setCheckedFiles(new Set())
      return
    }
    setLoadingDiff(true)
    try {
      const next = await getCodingSessionDiff(sessionId)
      if (!mountedRef.current) return
      setDiff(next)
      setActiveDiffFilePath((current) =>
        current && next.files.some((file) => file.path === current)
          ? current
          : (next.files[0]?.path ?? null)
      )
      setCheckedFiles((current) => {
        const valid = new Set(next.files.map((file) => file.path))
        const filtered = new Set<string>()
        for (const path of current) {
          if (valid.has(path)) filtered.add(path)
        }
        return filtered
      })
    } catch (caught) {
      if (!mountedRef.current) return
      setError(extractCodingErrorMessage(caught))
    } finally {
      if (mountedRef.current) setLoadingDiff(false)
    }
  }, [])

  const refreshAll = useCallback(async () => {
    setLoadingSessions(true)
    try {
      const [nextSessions, nextApprovals] = await Promise.all([
        listCodingSessions(),
        listCodingApprovals(approvalsFilter === 'pending' ? 'pending' : undefined)
      ])
      if (!mountedRef.current) return
      setSessions(nextSessions)
      setApprovals(nextApprovals)
      const nextSelected =
        selectedSessionId && nextSessions.some((s) => s.session_id === selectedSessionId)
          ? selectedSessionId
          : (nextSessions[0]?.session_id ?? null)
      setSelectedSessionId(nextSelected)
      if (nextSelected) {
        await loadDiff(nextSelected)
      } else {
        setDiff(null)
        setActiveDiffFilePath(null)
      }
    } catch (caught) {
      if (!mountedRef.current) return
      setError(extractCodingErrorMessage(caught))
    } finally {
      if (mountedRef.current) setLoadingSessions(false)
    }
  }, [approvalsFilter, loadDiff, selectedSessionId])

  useEffect(() => {
    mountedRef.current = true
    void refreshAll()
    return () => {
      mountedRef.current = false
    }
    // 仅首次挂载拉取全量状态
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (pollIntervalMs <= 0) return
    const timer = window.setInterval(() => {
      void loadApprovals(approvalsFilter)
    }, pollIntervalMs)
    return () => window.clearInterval(timer)
  }, [approvalsFilter, loadApprovals, pollIntervalMs])

  const selectedSession = useMemo(
    () => sessions.find((item) => item.session_id === selectedSessionId) ?? null,
    [sessions, selectedSessionId]
  )

  const handleSelectSession = useCallback(
    (sessionId: string) => {
      setSelectedSessionId(sessionId)
      setLastExecResponse(null)
      setError('')
      void loadDiff(sessionId)
    },
    [loadDiff]
  )

  const handleCreateSession = useCallback(async () => {
    if (!repoPath.trim() || !taskTitle.trim()) {
      setError(t('codingStudio.validationRepoAndTitle'))
      return
    }
    setCreatingSession(true)
    setError('')
    setNotice('')
    try {
      const created = await createCodingSession({
        repo_path: repoPath.trim(),
        title: taskTitle.trim(),
        base_ref: baseRef.trim() || 'HEAD',
        mode: initialMode,
        agent_engine: agentEngine
      })
      if (!mountedRef.current) return
      setSessions((prev) => [created, ...prev.filter((s) => s.session_id !== created.session_id)])
      setSelectedSessionId(created.session_id)
      setTaskTitle('')
      setLastExecResponse(null)
      setNotice(
        t('codingStudio.noticeSessionCreated', {
          title: created.title,
          branch: created.branch
        })
      )
      await loadDiff(created.session_id)
    } catch (caught) {
      if (!mountedRef.current) return
      setError(extractCodingErrorMessage(caught))
    } finally {
      if (mountedRef.current) setCreatingSession(false)
    }
  }, [agentEngine, baseRef, initialMode, loadDiff, repoPath, t, taskTitle])

  const handleDestroySession = useCallback(
    async (session: CodingSession) => {
      if (
        typeof window !== 'undefined' &&
        typeof window.confirm === 'function' &&
        !window.confirm(t('codingStudio.destroyConfirm', { title: session.title }))
      ) {
        return
      }
      setDestroyingSessionId(session.session_id)
      setError('')
      setNotice('')
      try {
        await destroyCodingSession(session.session_id, deleteBranchOnDestroy)
        if (!mountedRef.current) return
        let nextId: string | null = null
        setSessions((prev) => {
          const remaining = prev.filter((item) => item.session_id !== session.session_id)
          nextId =
            selectedSessionId === session.session_id
              ? (remaining[0]?.session_id ?? null)
              : selectedSessionId
          return remaining
        })
        setSelectedSessionId(nextId)
        setNotice(t('codingStudio.noticeDestroyed', { id: session.session_id }))
        await loadDiff(nextId)
      } catch (caught) {
        if (!mountedRef.current) return
        setError(extractCodingErrorMessage(caught))
      } finally {
        if (mountedRef.current) setDestroyingSessionId(null)
      }
    },
    [deleteBranchOnDestroy, loadDiff, selectedSessionId, t]
  )

  const handleSwitchMode = useCallback(
    async (mode: CodingSessionMode) => {
      if (!selectedSession || selectedSession.mode === mode) return
      setSwitchingMode(true)
      setError('')
      setNotice('')
      try {
        const updated = await setCodingSessionMode(selectedSession.session_id, mode)
        if (!mountedRef.current) return
        setSessions((prev) =>
          prev.map((item) =>
            item.session_id === updated.session_id ? { ...item, ...updated } : item
          )
        )
        setDiff((prev) =>
          prev && prev.session_id === updated.session_id ? { ...prev, mode: updated.mode } : prev
        )
        setNotice(
          t('codingStudio.noticeModeSwitched', {
            mode:
              updated.mode === 'plan'
                ? t('codingStudio.modePlan')
                : t('codingStudio.modeBuild')
          })
        )
      } catch (caught) {
        if (!mountedRef.current) return
        setError(extractCodingErrorMessage(caught))
      } finally {
        if (mountedRef.current) setSwitchingMode(false)
      }
    },
    [selectedSession, t]
  )

  const handleRevertFile = useCallback(
    async (path: string) => {
      if (!selectedSession) return
      setRevertingPath(path)
      setError('')
      setNotice('')
      try {
        await revertCodingFile(selectedSession.session_id, path)
        if (!mountedRef.current) return
        setCheckedFiles((prev) => {
          const next = new Set(prev)
          next.delete(path)
          return next
        })
        setNotice(t('codingStudio.noticeFileReverted', { path }))
        await loadDiff(selectedSession.session_id)
      } catch (caught) {
        if (!mountedRef.current) return
        setError(extractCodingErrorMessage(caught))
      } finally {
        if (mountedRef.current) setRevertingPath(null)
      }
    },
    [loadDiff, selectedSession, t]
  )

  const handleCommit = useCallback(async () => {
    if (!selectedSession) return
    if (!commitMessage.trim()) {
      setError(t('codingStudio.validationCommitMessage'))
      return
    }
    setCommitting(true)
    setError('')
    setNotice('')
    try {
      const selectedPaths = [...checkedFiles]
      const res = await commitCodingSession(selectedSession.session_id, {
        message: commitMessage.trim(),
        ...(selectedPaths.length > 0 ? { files: selectedPaths } : {})
      })
      if (!mountedRef.current) return
      setCommitMessage('')
      setCheckedFiles(new Set())
      setNotice(
        t('codingStudio.noticeCommitted', {
          branch: res.branch,
          sha: res.commit_sha,
          n: res.committed_files.length
        })
      )
      await loadDiff(selectedSession.session_id)
    } catch (caught) {
      if (!mountedRef.current) return
      setError(extractCodingErrorMessage(caught))
    } finally {
      if (mountedRef.current) setCommitting(false)
    }
  }, [checkedFiles, commitMessage, loadDiff, selectedSession, t])

  const handleRunCommand = useCallback(
    async (overrideCommand?: string) => {
      if (!selectedSession) return
      const targetCommand = (overrideCommand ?? commandInput).trim()
      if (!targetCommand) {
        setError(t('codingStudio.validationCommand'))
        return
      }
      if (overrideCommand) setCommandInput(overrideCommand)
      setExecutingCommand(true)
      setError('')
      setNotice('')
      try {
        const res = await execCodingCommand(selectedSession.session_id, {
          command: targetCommand
        })
        if (!mountedRef.current) return
        setLastExecResponse(res)
        if (res.status === 'pending_approval') {
          setApprovals((prev) => [
            res.approval,
            ...prev.filter((item) => item.approval_id !== res.approval.approval_id)
          ])
          setNotice(
            t('codingStudio.queuedForApprovalNotice', {
              id: res.approval.approval_id
            })
          )
        } else {
          await loadDiff(selectedSession.session_id)
        }
      } catch (caught) {
        if (!mountedRef.current) return
        setError(extractCodingErrorMessage(caught))
      } finally {
        if (mountedRef.current) setExecutingCommand(false)
      }
    },
    [commandInput, loadDiff, selectedSession, t]
  )

  const handleApprovalsFilterChange = useCallback(
    (next: CodingApprovalsFilter) => {
      setApprovalsFilter(next)
      void loadApprovals(next)
    },
    [loadApprovals]
  )

  const handleResolveApproval = useCallback(
    async (approvalId: string, decision: 'approve' | 'reject') => {
      setResolvingApprovalId(approvalId)
      setError('')
      setNotice('')
      try {
        const note = approvalNotes[approvalId]?.trim()
        const resolved = await resolveCodingApproval(approvalId, {
          decision,
          ...(note ? { note } : {})
        })
        if (!mountedRef.current) return
        setApprovals((prev) =>
          prev.map((item) => (item.approval_id === resolved.approval_id ? resolved : item))
        )
        if (resolved.exec_result) {
          setLastExecResponse({
            status: 'executed',
            session_id: resolved.session_id,
            result: resolved.exec_result
          })
        }
        setNotice(
          decision === 'approve'
            ? t('codingStudio.noticeApproved', { id: approvalId })
            : t('codingStudio.noticeRejected', { id: approvalId })
        )
        if (selectedSessionId && resolved.session_id === selectedSessionId) {
          await loadDiff(selectedSessionId)
        }
        await loadApprovals(approvalsFilter)
      } catch (caught) {
        if (!mountedRef.current) return
        setError(extractCodingErrorMessage(caught))
      } finally {
        if (mountedRef.current) setResolvingApprovalId(null)
      }
    },
    [approvalNotes, approvalsFilter, loadApprovals, loadDiff, selectedSessionId, t]
  )

  return (
    <CodingStudioPaneView
      sessions={sessions}
      selectedSessionId={selectedSessionId}
      diff={diff}
      activeDiffFilePath={activeDiffFilePath}
      checkedFiles={checkedFiles}
      approvals={approvals}
      approvalsFilter={approvalsFilter}
      approvalNotes={approvalNotes}
      repoPath={repoPath}
      taskTitle={taskTitle}
      baseRef={baseRef}
      agentEngine={agentEngine}
      initialMode={initialMode}
      deleteBranchOnDestroy={deleteBranchOnDestroy}
      commitMessage={commitMessage}
      commandInput={commandInput}
      lastExecResponse={lastExecResponse}
      loadingSessions={loadingSessions}
      loadingDiff={loadingDiff}
      creatingSession={creatingSession}
      switchingMode={switchingMode}
      revertingPath={revertingPath}
      committing={committing}
      destroyingSessionId={destroyingSessionId}
      executingCommand={executingCommand}
      resolvingApprovalId={resolvingApprovalId}
      notice={notice}
      error={error}
      onRefreshAll={() => void refreshAll()}
      onSelectSession={handleSelectSession}
      onRepoPathChange={setRepoPath}
      onTaskTitleChange={setTaskTitle}
      onBaseRefChange={setBaseRef}
      onAgentEngineChange={setAgentEngine}
      onInitialModeChange={setInitialMode}
      onCreateSession={() => void handleCreateSession()}
      onToggleDeleteBranchOnDestroy={setDeleteBranchOnDestroy}
      onDestroySession={(session) => void handleDestroySession(session)}
      onSwitchMode={(mode) => void handleSwitchMode(mode)}
      onRefreshDiff={() => void loadDiff(selectedSessionId)}
      onSelectDiffFile={setActiveDiffFilePath}
      onToggleFileChecked={(path) =>
        setCheckedFiles((prev) => {
          const next = new Set(prev)
          if (next.has(path)) next.delete(path)
          else next.add(path)
          return next
        })
      }
      onSelectAllFiles={() =>
        setCheckedFiles(new Set((diff?.files ?? []).map((file) => file.path)))
      }
      onClearFileSelection={() => setCheckedFiles(new Set())}
      onRevertFile={(path) => void handleRevertFile(path)}
      onCommitMessageChange={setCommitMessage}
      onCommit={() => void handleCommit()}
      onCommandInputChange={setCommandInput}
      onRunCommand={(override) => void handleRunCommand(override)}
      onApprovalsFilterChange={handleApprovalsFilterChange}
      onApprovalNoteChange={(approvalId, note) =>
        setApprovalNotes((prev) => ({ ...prev, [approvalId]: note }))
      }
      onResolveApproval={(approvalId, decision) => void handleResolveApproval(approvalId, decision)}
      onDismissBanner={() => {
        setNotice('')
        setError('')
      }}
    />
  )
}
