import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  commitWorkspace,
  createWorktree,
  getWorkspaceDiff,
  listWorktrees,
  removeWorktree,
  revertWorkspaceFile,
  runWorkspaceExecPlan,
  type WorkspaceDiffFile,
  type WorkspaceDiffSnapshot,
  type WorkspaceExecResult,
  type WorkspaceWorktree,
  type WorkspaceWorktreeList
} from '../api'
import { useTranslation } from '../i18n'
import { useAppStore, type ConversationKind } from '../store'

export type CodingExecMode = 'plan' | 'build'

export type DiffLineKind = 'meta' | 'hunk' | 'add' | 'del' | 'context'

export interface ParsedDiffLine {
  kind: DiffLineKind
  oldLine: number | null
  newLine: number | null
  text: string
}

export const APPROVAL_CENTER_REFRESH_EVENT = 'nachuan:approvals-refresh'

export type CodingTranslate = (key: string, opts?: Record<string, unknown>) => string

export function parseUnifiedDiffLines(diff: string): ParsedDiffLine[] {
  if (!diff) return []
  const rawLines = diff.replace(/\r\n/g, '\n').split('\n')
  const parsed: ParsedDiffLine[] = []
  let oldLine = 0
  let newLine = 0
  let inHunk = false

  for (const line of rawLines) {
    if (line.startsWith('@@')) {
      const match = /^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/.exec(line)
      if (match) {
        oldLine = Number(match[1])
        newLine = Number(match[2])
        inHunk = true
      }
      parsed.push({ kind: 'hunk', oldLine: null, newLine: null, text: line })
      continue
    }
    if (
      !inHunk &&
      (line.startsWith('diff --git') ||
        line.startsWith('index ') ||
        line.startsWith('--- ') ||
        line.startsWith('+++ ') ||
        line.startsWith('new file mode') ||
        line.startsWith('deleted file mode') ||
        line.startsWith('rename '))
    ) {
      parsed.push({ kind: 'meta', oldLine: null, newLine: null, text: line })
      continue
    }
    if (inHunk && line.startsWith('+') && !line.startsWith('+++')) {
      parsed.push({ kind: 'add', oldLine: null, newLine: newLine++, text: line })
      continue
    }
    if (inHunk && line.startsWith('-') && !line.startsWith('---')) {
      parsed.push({ kind: 'del', oldLine: oldLine++, newLine: null, text: line })
      continue
    }
    if (inHunk && line.startsWith('\\')) {
      parsed.push({ kind: 'meta', oldLine: null, newLine: null, text: line })
      continue
    }
    if (inHunk) {
      parsed.push({ kind: 'context', oldLine: oldLine++, newLine: newLine++, text: line })
    } else {
      parsed.push({ kind: 'meta', oldLine: null, newLine: null, text: line })
    }
  }
  return parsed
}

export function formatDiffStatusBadge(status: string): {
  code: string
  tone: 'modified' | 'added' | 'deleted' | 'untracked' | 'renamed'
} {
  const normalized = status.trim().toUpperCase()
  if (normalized === 'A' || normalized === 'ADDED') return { code: 'A', tone: 'added' }
  if (normalized === 'D' || normalized === 'DELETED') return { code: 'D', tone: 'deleted' }
  if (normalized === '?' || normalized === '??' || normalized === 'UNTRACKED') {
    return { code: '?', tone: 'untracked' }
  }
  if (normalized.startsWith('R') || normalized === 'RENAMED') {
    return { code: 'R', tone: 'renamed' }
  }
  return { code: normalized ? normalized[0] : 'M', tone: 'modified' }
}

export function applyWorktreeToConversation(
  worktreePath: string,
  actions: {
    currentConvId: string | null
    newConversation: (kind?: ConversationKind) => string
    setConvWorkdir: (id: string, workdir: string) => void
  }
): string {
  const convId = actions.currentConvId ?? actions.newConversation('code')
  actions.setConvWorkdir(convId, worktreePath)
  return convId
}

export function notifyApprovalCenter(approvalId?: string): void {
  if (typeof window === 'undefined' || typeof window.dispatchEvent !== 'function') return
  const EventCtor = typeof CustomEvent === 'function' ? CustomEvent : null
  if (EventCtor) {
    window.dispatchEvent(new EventCtor(APPROVAL_CENTER_REFRESH_EVENT, { detail: { approvalId } }))
  }
}

export async function performCreateWorktree(
  repoPath: string,
  taskName: string,
  baseRef?: string
): Promise<{ ok: boolean; worktree: WorkspaceWorktree }> {
  return createWorktree(repoPath.trim(), taskName.trim(), baseRef?.trim() || undefined)
}

export async function performRemoveWorktree(
  repoPath: string,
  worktreePath: string,
  opts?: { force?: boolean; delete_branch?: boolean }
): Promise<{ ok: boolean; removed: string }> {
  return removeWorktree(repoPath.trim(), worktreePath, opts)
}

export async function performRevertFile(
  worktreePath: string,
  filePath: string
): Promise<{ ok: boolean; file_path: string }> {
  return revertWorkspaceFile(worktreePath, filePath)
}

export async function performCommitWorkspace(
  worktreePath: string,
  message: string,
  files?: string[]
): Promise<{ ok: boolean; commit_sha: string; branch: string; files_committed: number }> {
  return commitWorkspace(worktreePath, message.trim(), files && files.length > 0 ? files : undefined)
}

export async function performRunExecPlan(payload: {
  worktree_path: string
  mode: CodingExecMode
  command: string
  approval_id?: string
}): Promise<WorkspaceExecResult> {
  return runWorkspaceExecPlan({
    worktree_path: payload.worktree_path,
    mode: payload.mode,
    command: payload.command.trim(),
    ...(payload.approval_id?.trim() ? { approval_id: payload.approval_id.trim() } : {})
  })
}

export interface CodingControlPaneViewProps {
  repoPath: string
  activeWorkdir: string
  worktreeList: WorkspaceWorktreeList | null
  selectedWorktreePath: string
  loadingWorktrees: boolean
  newTaskName: string
  newBaseRef: string
  creatingWorktree: boolean
  removingPath: string | null
  removeDeleteBranch: boolean
  removeForce: boolean
  diffSnapshot: WorkspaceDiffSnapshot | null
  stagedOnly: boolean
  loadingDiff: boolean
  selectedFilePath: string
  checkedFiles: readonly string[]
  revertingFilePath: string | null
  commitMessage: string
  committing: boolean
  execMode: CodingExecMode
  execCommand: string
  execRunning: boolean
  execResult: WorkspaceExecResult | null
  approvalIdInput: string
  notice?: string
  error?: string
  canPickDirectory?: boolean
  onRepoPathChange: (value: string) => void
  onPickRepoDirectory?: () => void
  onLoadRepo: () => void
  onNewTaskNameChange: (value: string) => void
  onNewBaseRefChange: (value: string) => void
  onCreateWorktree: () => void
  onSelectWorktree: (worktree: WorkspaceWorktree) => void
  onRemoveWorktree: (worktree: WorkspaceWorktree) => void
  onToggleRemoveDeleteBranch: (value: boolean) => void
  onToggleRemoveForce: (value: boolean) => void
  onToggleStaged: (staged: boolean) => void
  onRefreshDiff: () => void
  onSelectFile: (filePath: string) => void
  onToggleCheckFile: (filePath: string) => void
  onSelectAllFiles: () => void
  onClearCheckedFiles: () => void
  onRevertFile: (filePath: string) => void
  onCommitMessageChange: (value: string) => void
  onCommit: () => void
  onExecModeChange: (mode: CodingExecMode) => void
  onExecCommandChange: (value: string) => void
  onRunExec: () => void
  onApprovalIdInputChange: (value: string) => void
  onOpenApprovalCenter: () => void
  onRetryWithApproval: () => void
  onOpenChat?: () => void
}

export function buildCodingControlPaneTree(
  props: CodingControlPaneViewProps,
  t: CodingTranslate
): React.ReactNode {
  const {
    repoPath,
    activeWorkdir,
    worktreeList,
    selectedWorktreePath,
    loadingWorktrees,
    newTaskName,
    newBaseRef,
    creatingWorktree,
    removingPath,
    removeDeleteBranch,
    removeForce,
    diffSnapshot,
    stagedOnly,
    loadingDiff,
    selectedFilePath,
    checkedFiles,
    revertingFilePath,
    commitMessage,
    committing,
    execMode,
    execCommand,
    execRunning,
    execResult,
    approvalIdInput,
    notice = '',
    error = '',
    canPickDirectory = false,
    onRepoPathChange,
    onPickRepoDirectory,
    onLoadRepo,
    onNewTaskNameChange,
    onNewBaseRefChange,
    onCreateWorktree,
    onSelectWorktree,
    onRemoveWorktree,
    onToggleRemoveDeleteBranch,
    onToggleRemoveForce,
    onToggleStaged,
    onRefreshDiff,
    onSelectFile,
    onToggleCheckFile,
    onSelectAllFiles,
    onClearCheckedFiles,
    onRevertFile,
    onCommitMessageChange,
    onCommit,
    onExecModeChange,
    onExecCommandChange,
    onRunExec,
    onApprovalIdInputChange,
    onOpenApprovalCenter,
    onRetryWithApproval,
    onOpenChat
  } = props

  const worktrees = worktreeList?.worktrees ?? []
  const diffFiles = diffSnapshot?.files ?? []
  const checkedSet = new Set(checkedFiles)
  const activeFile: WorkspaceDiffFile | null =
    diffFiles.find((file) => file.path === selectedFilePath) ?? diffFiles[0] ?? null
  const parsedDiffLines = activeFile ? parseUnifiedDiffLines(activeFile.diff) : []
  const effectiveApprovalId = approvalIdInput.trim() || execResult?.approval_id || ''

  return (
    <main
      className="nachuan-coding-plane"
      data-testid="coding-control-pane"
      aria-labelledby="coding-control-title"
    >
      <header className="nachuan-coding-topbar">
        <div className="nachuan-coding-heading">
          <span className="nachuan-eyebrow">{t('coding.eyebrow')}</span>
          <h1 id="coding-control-title">{t('coding.title')}</h1>
          <p>{t('coding.subtitle')}</p>
        </div>

        <div className="nachuan-coding-topbar-meta">
          <div className="nachuan-coding-workdir-pill" data-testid="coding-active-workdir">
            <span>{t('coding.activeWorkdir')}</span>
            <code>{activeWorkdir || t('coding.unboundWorkdir')}</code>
          </div>
          {onOpenChat && (
            <button
              type="button"
              data-testid="coding-open-chat-btn"
              className="nachuan-coding-btn nachuan-coding-btn--primary"
              onClick={onOpenChat}
            >
              {t('coding.backToChat')}
            </button>
          )}
        </div>
      </header>

      {notice && (
        <div className="nachuan-coding-banner is-ok" data-testid="coding-notice" role="status">
          {notice}
        </div>
      )}
      {error && (
        <div className="nachuan-coding-banner is-error" data-testid="coding-error" role="alert">
          {error}
        </div>
      )}

      <div className="nachuan-coding-grid">
        {/* 左栏：多 Git Worktree 并行调度器 */}
        <section
          className="nachuan-coding-card nachuan-coding-worktrees"
          data-testid="coding-worktree-pane"
          aria-label={t('coding.worktreeTitle')}
        >
          <div className="nachuan-coding-card-header">
            <h2>{t('coding.worktreeTitle')}</h2>
            <button
              type="button"
              data-testid="refresh-worktrees-btn"
              className="nachuan-coding-btn"
              disabled={loadingWorktrees}
              onClick={onLoadRepo}
            >
              {loadingWorktrees ? t('coding.refreshing') : t('coding.refreshAll')}
            </button>
          </div>

          <div className="nachuan-coding-repo-bar">
            <label className="nachuan-coding-field">
              <span>{t('coding.repoPathLabel')}</span>
              <div className="nachuan-coding-input-row">
                <input
                  data-testid="repo-path-input"
                  value={repoPath}
                  onChange={(event) => onRepoPathChange(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') onLoadRepo()
                  }}
                  placeholder={t('coding.repoPathPh')}
                  spellCheck={false}
                />
                {canPickDirectory && onPickRepoDirectory && (
                  <button
                    type="button"
                    data-testid="pick-repo-btn"
                    className="nachuan-coding-btn"
                    onClick={onPickRepoDirectory}
                  >
                    {t('coding.pickFolder')}
                  </button>
                )}
                <button
                  type="button"
                  data-testid="load-repo-btn"
                  className="nachuan-coding-btn nachuan-coding-btn--primary"
                  disabled={loadingWorktrees || !repoPath.trim()}
                  onClick={onLoadRepo}
                >
                  {t('coding.loadRepo')}
                </button>
              </div>
            </label>
          </div>

          {worktreeList && !worktreeList.is_git_repo && (
            <p className="nachuan-coding-empty is-warn" data-testid="not-git-repo-warning">
              {t('coding.notGitRepo')}
            </p>
          )}

          <div className="nachuan-coding-create-box">
            <div className="nachuan-coding-subhead">{t('coding.newWorktreeTitle')}</div>
            <input
              data-testid="new-worktree-task-input"
              value={newTaskName}
              onChange={(event) => onNewTaskNameChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') onCreateWorktree()
              }}
              placeholder={t('coding.taskNamePh')}
              spellCheck={false}
            />
            <div className="nachuan-coding-input-row">
              <input
                data-testid="new-worktree-base-input"
                value={newBaseRef}
                onChange={(event) => onNewBaseRefChange(event.target.value)}
                placeholder={t('coding.baseRefPh')}
                spellCheck={false}
              />
              <button
                type="button"
                data-testid="create-worktree-btn"
                className="nachuan-coding-btn nachuan-coding-btn--brand"
                disabled={creatingWorktree || !repoPath.trim() || !newTaskName.trim()}
                onClick={onCreateWorktree}
              >
                {creatingWorktree ? t('coding.creatingWorktree') : t('coding.createWorktree')}
              </button>
            </div>
          </div>

          <div className="nachuan-coding-remove-opts">
            <label>
              <input
                type="checkbox"
                data-testid="remove-delete-branch-toggle"
                checked={removeDeleteBranch}
                onChange={(event) => onToggleRemoveDeleteBranch(event.target.checked)}
              />
              <span>{t('coding.removeDeleteBranch')}</span>
            </label>
            <label>
              <input
                type="checkbox"
                data-testid="remove-force-toggle"
                checked={removeForce}
                onChange={(event) => onToggleRemoveForce(event.target.checked)}
              />
              <span>{t('coding.removeForce')}</span>
            </label>
          </div>

          <div className="nachuan-coding-worktree-list" data-testid="worktree-list">
            {worktrees.length === 0 ? (
              <p className="nachuan-coding-empty">{t('coding.worktreeEmpty')}</p>
            ) : (
              worktrees.map((wt) => {
                const isSelected = wt.path === selectedWorktreePath
                const isBound = Boolean(activeWorkdir) && activeWorkdir === wt.path
                const isRemoving = removingPath === wt.path
                return (
                  <article
                    key={wt.path}
                    data-testid="worktree-card"
                    data-worktree-path={wt.path}
                    data-worktree-selected={isSelected ? 'true' : 'false'}
                    data-worktree-bound={isBound ? 'true' : 'false'}
                    className={`nachuan-worktree-card${isSelected ? ' is-selected' : ''}${
                      isBound ? ' is-bound' : ''
                    }`}
                  >
                    <button
                      type="button"
                      data-testid={`worktree-select-${wt.branch}`}
                      className="nachuan-worktree-main-btn"
                      onClick={() => onSelectWorktree(wt)}
                    >
                      <div className="nachuan-worktree-title-row">
                        <strong className="nachuan-worktree-branch">{wt.branch || '(detached)'}</strong>
                        <span className="nachuan-worktree-head">{wt.head.slice(0, 8)}</span>
                      </div>
                      <div className="nachuan-worktree-path" title={wt.path}>
                        {wt.path}
                      </div>
                      <div className="nachuan-worktree-badges">
                        {wt.is_main && (
                          <span className="nachuan-wt-badge is-main">{t('coding.badgeMain')}</span>
                        )}
                        {wt.is_managed && (
                          <span className="nachuan-wt-badge is-managed">
                            {t('coding.badgeManaged')}
                          </span>
                        )}
                        {wt.locked && (
                          <span className="nachuan-wt-badge is-locked">
                            {t('coding.badgeLocked')}
                          </span>
                        )}
                        <span
                          className={`nachuan-wt-badge${
                            wt.dirty_files > 0 ? ' is-dirty' : ' is-clean'
                          }`}
                        >
                          {wt.dirty_files > 0
                            ? t('coding.dirtyFiles', { n: wt.dirty_files })
                            : t('coding.cleanTree')}
                        </span>
                        {isBound && (
                          <span className="nachuan-wt-badge is-bound">
                            {t('coding.badgeBound')}
                          </span>
                        )}
                      </div>
                    </button>

                    <div className="nachuan-worktree-actions">
                      <button
                        type="button"
                        data-testid={`worktree-bind-${wt.branch}`}
                        className="nachuan-coding-btn nachuan-coding-btn--xs"
                        onClick={() => onSelectWorktree(wt)}
                      >
                        {t('coding.useInChat')}
                      </button>
                      {wt.is_managed && !wt.is_main && (
                        <button
                          type="button"
                          data-testid={`remove-worktree-${wt.branch}`}
                          className="nachuan-coding-btn nachuan-coding-btn--xs nachuan-coding-btn--danger"
                          disabled={isRemoving}
                          onClick={() => onRemoveWorktree(wt)}
                        >
                          {isRemoving ? t('coding.removingWorktree') : t('coding.removeWorktree')}
                        </button>
                      )}
                    </div>
                  </article>
                )
              })
            )}
          </div>
        </section>

        {/* 中栏：可视化逐行 Git Diff 审阅器 */}
        <section
          className="nachuan-coding-card nachuan-coding-diff"
          data-testid="coding-diff-pane"
          aria-label={t('coding.diffTitle')}
        >
          <div className="nachuan-coding-card-header">
            <div className="nachuan-coding-diff-title-group">
              <h2>{t('coding.diffTitle')}</h2>
              {diffSnapshot && (
                <div className="nachuan-coding-diff-stats" data-testid="diff-summary-stats">
                  <span className="nachuan-diff-branch">{diffSnapshot.branch}</span>
                  <span>
                    {t('coding.diffSummary', { files: diffSnapshot.summary.total_files })}
                  </span>
                  <span className="nachuan-diff-stat-add">+{diffSnapshot.summary.additions}</span>
                  <span className="nachuan-diff-stat-del">-{diffSnapshot.summary.deletions}</span>
                </div>
              )}
            </div>

            <div className="nachuan-coding-diff-controls">
              <div className="nachuan-segmented" role="group" aria-label={t('coding.diffTitle')}>
                <button
                  type="button"
                  data-testid="diff-tab-unstaged"
                  aria-pressed={!stagedOnly}
                  onClick={() => onToggleStaged(false)}
                >
                  {t('coding.diffUnstaged')}
                </button>
                <button
                  type="button"
                  data-testid="diff-tab-staged"
                  aria-pressed={stagedOnly}
                  onClick={() => onToggleStaged(true)}
                >
                  {t('coding.diffStaged')}
                </button>
              </div>
              <button
                type="button"
                data-testid="refresh-diff-btn"
                className="nachuan-coding-btn"
                disabled={loadingDiff || !selectedWorktreePath}
                onClick={onRefreshDiff}
              >
                {loadingDiff ? t('coding.refreshing') : t('coding.refreshAll')}
              </button>
            </div>
          </div>

          <div className="nachuan-coding-diff-workspace">
            {/* 变更文件列表 */}
            <div className="nachuan-diff-file-sidebar" data-testid="diff-file-list">
              {diffFiles.length > 0 && (
                <div className="nachuan-diff-file-bulk">
                  <button
                    type="button"
                    data-testid="diff-select-all-btn"
                    className="nachuan-coding-link-btn"
                    onClick={onSelectAllFiles}
                  >
                    {t('coding.selectAllFiles')}
                  </button>
                  <button
                    type="button"
                    data-testid="diff-clear-selection-btn"
                    className="nachuan-coding-link-btn"
                    onClick={onClearCheckedFiles}
                  >
                    {t('coding.clearSelectedFiles')}
                  </button>
                </div>
              )}

              {diffFiles.length === 0 ? (
                <p className="nachuan-coding-empty">{t('coding.diffEmpty')}</p>
              ) : (
                diffFiles.map((file) => {
                  const badge = formatDiffStatusBadge(file.status)
                  const isActive = activeFile?.path === file.path
                  const isChecked = checkedSet.has(file.path)
                  const isReverting = revertingFilePath === file.path
                  return (
                    <div
                      key={file.path}
                      data-testid="diff-file-row"
                      data-file-path={file.path}
                      className={`nachuan-diff-file-row${isActive ? ' is-active' : ''}`}
                    >
                      <input
                        type="checkbox"
                        data-testid={`diff-check-${file.path}`}
                        checked={isChecked}
                        onChange={() => onToggleCheckFile(file.path)}
                        aria-label={file.path}
                      />
                      <button
                        type="button"
                        data-testid={`diff-select-${file.path}`}
                        className="nachuan-diff-file-select"
                        onClick={() => onSelectFile(file.path)}
                      >
                        <span className={`nachuan-diff-status is-${badge.tone}`}>
                          {badge.code}
                        </span>
                        <span className="nachuan-diff-file-path" title={file.path}>
                          {file.path}
                        </span>
                        <span className="nachuan-diff-file-delta">
                          <em className="is-add">+{file.additions}</em>
                          <em className="is-del">-{file.deletions}</em>
                        </span>
                      </button>
                      <button
                        type="button"
                        data-testid={`revert-file-${file.path}`}
                        className="nachuan-coding-btn nachuan-coding-btn--xs nachuan-coding-btn--danger"
                        disabled={isReverting}
                        onClick={() => onRevertFile(file.path)}
                      >
                        {isReverting ? t('coding.revertingFile') : t('coding.revertFile')}
                      </button>
                    </div>
                  )
                })
              )}
            </div>

            {/* 右侧高清晰逐行 Unified Diff 视图 */}
            <div className="nachuan-diff-viewer-wrap" data-testid="diff-viewer">
              {!activeFile ? (
                <p className="nachuan-coding-empty">{t('coding.diffSelectHint')}</p>
              ) : (
                <>
                  <div className="nachuan-diff-viewer-header">
                    <code>{activeFile.path}</code>
                    <div className="nachuan-diff-viewer-counts">
                      <span className="nachuan-diff-stat-add">+{activeFile.additions}</span>
                      <span className="nachuan-diff-stat-del">-{activeFile.deletions}</span>
                    </div>
                  </div>
                  {activeFile.truncated && (
                    <div className="nachuan-diff-truncated">{t('coding.diffTruncated')}</div>
                  )}
                  <div className="nachuan-diff-code-scroll">
                    <table className="nachuan-diff-table">
                      <tbody>
                        {parsedDiffLines.map((line, index) => (
                          <tr
                            key={index}
                            data-diff-kind={line.kind}
                            className={`nachuan-diff-line is-${line.kind}`}
                          >
                            <td className="nachuan-diff-ln">{line.oldLine ?? ''}</td>
                            <td className="nachuan-diff-ln">{line.newLine ?? ''}</td>
                            <td className="nachuan-diff-code">
                              <pre>{line.text || ' '}</pre>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* 本地提交 Commit 操作栏 */}
          <div className="nachuan-coding-commit-bar">
            <span className="nachuan-coding-commit-hint">
              {checkedFiles.length > 0
                ? t('coding.commitSelectedHint', { n: checkedFiles.length })
                : t('coding.commitAllHint')}
            </span>
            <div className="nachuan-coding-input-row">
              <input
                data-testid="commit-message-input"
                value={commitMessage}
                onChange={(event) => onCommitMessageChange(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') onCommit()
                }}
                placeholder={t('coding.commitPlaceholder')}
              />
              <button
                type="button"
                data-testid="commit-submit-btn"
                className="nachuan-coding-btn nachuan-coding-btn--brand"
                disabled={committing || !selectedWorktreePath || !commitMessage.trim()}
                onClick={onCommit}
              >
                {committing ? t('coding.committingBtn') : t('coding.commitBtn')}
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* 底栏：Plan（只读）/ Build（审批执行）受控命令台 */}
      <section
        className="nachuan-coding-card nachuan-coding-exec"
        data-testid="coding-exec-pane"
        aria-label={t('coding.execTitle')}
      >
        <div className="nachuan-coding-card-header">
          <div>
            <h2>{t('coding.execTitle')}</h2>
            <p className="nachuan-coding-exec-hint">
              {execMode === 'plan' ? t('coding.modePlanHint') : t('coding.modeBuildHint')}
            </p>
          </div>

          <div className="nachuan-segmented" role="group" aria-label={t('coding.execTitle')}>
            <button
              type="button"
              data-testid="exec-mode-plan"
              aria-pressed={execMode === 'plan'}
              onClick={() => onExecModeChange('plan')}
            >
              {t('coding.modePlan')}
            </button>
            <button
              type="button"
              data-testid="exec-mode-build"
              aria-pressed={execMode === 'build'}
              onClick={() => onExecModeChange('build')}
            >
              {t('coding.modeBuild')}
            </button>
          </div>
        </div>

        <div className="nachuan-coding-input-row">
          <input
            data-testid="exec-command-input"
            className="nachuan-coding-cmd-input"
            value={execCommand}
            onChange={(event) => onExecCommandChange(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') onRunExec()
            }}
            placeholder={t('coding.commandPh')}
            spellCheck={false}
          />
          <button
            type="button"
            data-testid="exec-run-btn"
            className={`nachuan-coding-btn ${
              execMode === 'build' ? 'nachuan-coding-btn--warn' : 'nachuan-coding-btn--brand'
            }`}
            disabled={execRunning || !selectedWorktreePath || !execCommand.trim()}
            onClick={onRunExec}
          >
            {execRunning ? t('coding.runningCommand') : t('coding.runCommand')}
          </button>
        </div>

        {execResult && execResult.status === 'executed' && (
          <div className="nachuan-exec-card is-executed" data-testid="exec-result-executed">
            <div className="nachuan-exec-card-head">
              <div className="nachuan-exec-card-title">
                <span className="nachuan-exec-pill is-mode">{execResult.mode.toUpperCase()}</span>
                <strong>{t('coding.execExecuted')}</strong>
                <code>{execResult.command}</code>
              </div>
              <span
                data-testid="exec-exit-code"
                className={`nachuan-exec-pill${
                  (execResult.exit_code ?? 0) === 0 ? ' is-ok' : ' is-fail'
                }`}
              >
                {t('coding.execExitCode', { code: execResult.exit_code ?? 0 })}
              </span>
            </div>
            {execResult.stdout ? (
              <div className="nachuan-exec-output-block">
                <span>{t('coding.execStdout')}</span>
                <pre data-testid="exec-stdout">{execResult.stdout}</pre>
              </div>
            ) : null}
            {execResult.stderr ? (
              <div className="nachuan-exec-output-block is-stderr">
                <span>{t('coding.execStderr')}</span>
                <pre data-testid="exec-stderr">{execResult.stderr}</pre>
              </div>
            ) : null}
            {!execResult.stdout && !execResult.stderr && (
              <div className="nachuan-exec-empty">{t('coding.execEmptyOutput')}</div>
            )}
          </div>
        )}

        {execResult && execResult.status === 'approval_required' && (
          <div className="nachuan-exec-card is-approval" data-testid="exec-result-approval">
            <div className="nachuan-exec-card-head">
              <div className="nachuan-exec-card-title">
                <strong>{t('coding.execApprovalTitle')}</strong>
                {execResult.risk_level && (
                  <span data-testid="exec-risk-level" className="nachuan-exec-pill is-risk">
                    {t('coding.execRiskLevel', { level: execResult.risk_level })}
                  </span>
                )}
              </div>
              {execResult.approval_id && (
                <span data-testid="exec-approval-id-badge" className="nachuan-exec-pill is-id">
                  {t('coding.execApprovalId')}: {execResult.approval_id}
                </span>
              )}
            </div>
            {execResult.reason && (
              <p className="nachuan-exec-reason">
                {t('coding.execReason', { reason: execResult.reason })}
              </p>
            )}
            <p className="nachuan-exec-approval-hint">{t('coding.execApprovalHint')}</p>
            <div className="nachuan-exec-approval-actions">
              <button
                type="button"
                data-testid="exec-open-approval-center"
                className="nachuan-coding-btn"
                onClick={onOpenApprovalCenter}
              >
                {t('coding.openApprovalCenter')}
              </button>
              <input
                data-testid="exec-approval-id-input"
                className="nachuan-coding-approval-input"
                value={approvalIdInput}
                onChange={(event) => onApprovalIdInputChange(event.target.value)}
                placeholder={execResult.approval_id || t('coding.execApprovalId')}
                spellCheck={false}
              />
              <button
                type="button"
                data-testid="exec-retry-with-approval"
                className="nachuan-coding-btn nachuan-coding-btn--brand"
                disabled={execRunning || !effectiveApprovalId}
                onClick={onRetryWithApproval}
              >
                {execRunning ? t('coding.runningCommand') : t('coding.retryWithApproval')}
              </button>
            </div>
          </div>
        )}

        {execResult && execResult.status === 'blocked' && (
          <div className="nachuan-exec-card is-blocked" data-testid="exec-result-blocked">
            <div className="nachuan-exec-card-head">
              <div className="nachuan-exec-card-title">
                <strong>{t('coding.execBlockedTitle')}</strong>
                {execResult.risk_level && (
                  <span className="nachuan-exec-pill is-fail">
                    {t('coding.execRiskLevel', { level: execResult.risk_level })}
                  </span>
                )}
              </div>
              <code>{execResult.command}</code>
            </div>
            {execResult.reason && (
              <p className="nachuan-exec-reason" data-testid="exec-blocked-reason">
                {t('coding.execReason', { reason: execResult.reason })}
              </p>
            )}
          </div>
        )}
      </section>
    </main>
  )
}

export function CodingControlPaneView(props: CodingControlPaneViewProps): React.ReactNode {
  const { t } = useTranslation()
  return buildCodingControlPaneTree(props, t)
}

export interface CodingControlPaneProps {
  initialRepoPath?: string
  initialWorktreeList?: WorkspaceWorktreeList | null
  initialDiffSnapshot?: WorkspaceDiffSnapshot | null
  onOpenChat?: () => void
}

export default function CodingControlPane({
  initialRepoPath,
  initialWorktreeList = null,
  initialDiffSnapshot = null,
  onOpenChat
}: CodingControlPaneProps = {}): React.ReactNode {
  const { t } = useTranslation()
  const conversations = useAppStore((s) => s.conversations)
  const currentConvId = useAppStore((s) => s.currentConvId)
  const newConversation = useAppStore((s) => s.newConversation)
  const setConvWorkdir = useAppStore((s) => s.setConvWorkdir)

  const activeConv = useMemo(
    () => conversations.find((c) => c.id === currentConvId) ?? null,
    [conversations, currentConvId]
  )
  const activeWorkdir = activeConv?.workdir ?? ''

  const [repoPath, setRepoPath] = useState<string>(initialRepoPath ?? activeWorkdir)
  const [worktreeList, setWorktreeList] = useState<WorkspaceWorktreeList | null>(
    initialWorktreeList
  )
  const [selectedWorktreePath, setSelectedWorktreePath] = useState<string>(
    initialDiffSnapshot?.worktree_path ??
      initialWorktreeList?.worktrees[0]?.path ??
      activeWorkdir ??
      ''
  )
  const [loadingWorktrees, setLoadingWorktrees] = useState(false)
  const [newTaskName, setNewTaskName] = useState('')
  const [newBaseRef, setNewBaseRef] = useState('')
  const [creatingWorktree, setCreatingWorktree] = useState(false)
  const [removingPath, setRemovingPath] = useState<string | null>(null)
  const [removeDeleteBranch, setRemoveDeleteBranch] = useState(false)
  const [removeForce, setRemoveForce] = useState(false)

  const [diffSnapshot, setDiffSnapshot] = useState<WorkspaceDiffSnapshot | null>(
    initialDiffSnapshot
  )
  const [stagedOnly, setStagedOnly] = useState(false)
  const [loadingDiff, setLoadingDiff] = useState(false)
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    initialDiffSnapshot?.files[0]?.path ?? ''
  )
  const [checkedFiles, setCheckedFiles] = useState<string[]>([])
  const [revertingFilePath, setRevertingFilePath] = useState<string | null>(null)
  const [commitMessage, setCommitMessage] = useState('')
  const [committing, setCommitting] = useState(false)

  const [execMode, setExecMode] = useState<CodingExecMode>('plan')
  const [execCommand, setExecCommand] = useState('')
  const [execRunning, setExecRunning] = useState(false)
  const [execResult, setExecResult] = useState<WorkspaceExecResult | null>(null)
  const [approvalIdInput, setApprovalIdInput] = useState('')

  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const loadDiffFor = useCallback(
    async (targetPath: string, staged: boolean): Promise<void> => {
      if (!targetPath.trim()) {
        setDiffSnapshot(null)
        return
      }
      setLoadingDiff(true)
      try {
        const snap = await getWorkspaceDiff(targetPath, staged)
        if (!mountedRef.current) return
        setDiffSnapshot(snap)
        setSelectedFilePath((prev) =>
          snap.files.some((item) => item.path === prev) ? prev : (snap.files[0]?.path ?? '')
        )
        setCheckedFiles((prev) =>
          prev.filter((path) => snap.files.some((item) => item.path === path))
        )
      } catch (caught) {
        if (!mountedRef.current) return
        setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
      } finally {
        if (mountedRef.current) setLoadingDiff(false)
      }
    },
    [t]
  )

  const loadRepo = useCallback(
    async (overridePath?: string): Promise<void> => {
      const targetRepo = (overridePath ?? repoPath).trim()
      if (!targetRepo) return
      setLoadingWorktrees(true)
      setError('')
      try {
        const list = await listWorktrees(targetRepo)
        if (!mountedRef.current) return
        setWorktreeList(list)
        const nextSelected =
          list.worktrees.find((w) => w.path === selectedWorktreePath)?.path ??
          list.worktrees.find((w) => w.path === activeWorkdir)?.path ??
          list.worktrees[0]?.path ??
          ''
        setSelectedWorktreePath(nextSelected)
        if (nextSelected && list.is_git_repo) {
          await loadDiffFor(nextSelected, stagedOnly)
        } else {
          setDiffSnapshot(null)
        }
      } catch (caught) {
        if (!mountedRef.current) return
        setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
      } finally {
        if (mountedRef.current) setLoadingWorktrees(false)
      }
    },
    [activeWorkdir, loadDiffFor, repoPath, selectedWorktreePath, stagedOnly, t]
  )

  useEffect(() => {
    if (!initialWorktreeList && repoPath.trim()) {
      void loadRepo(repoPath)
    }
    // 仅在首次挂载且带入默认仓库路径时自动拉取
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const canPickDirectory =
    typeof window !== 'undefined' &&
    window.api?.runtimeKind === 'electron' &&
    typeof window.api?.pickDirectory === 'function'

  const handlePickRepoDirectory = useCallback(async () => {
    if (!canPickDirectory) return
    const chosen = await window.api.pickDirectory()
    if (chosen) {
      setRepoPath(chosen)
      await loadRepo(chosen)
    }
  }, [canPickDirectory, loadRepo])

  const handleSelectWorktree = useCallback(
    (worktree: WorkspaceWorktree) => {
      setSelectedWorktreePath(worktree.path)
      setError('')
      applyWorktreeToConversation(worktree.path, {
        currentConvId,
        newConversation,
        setConvWorkdir
      })
      setNotice(t('coding.worktreeSwitched', { path: worktree.path }))
      void loadDiffFor(worktree.path, stagedOnly)
    },
    [currentConvId, loadDiffFor, newConversation, setConvWorkdir, stagedOnly, t]
  )

  const handleCreateWorktree = useCallback(async () => {
    if (!repoPath.trim() || !newTaskName.trim()) return
    setCreatingWorktree(true)
    setError('')
    setNotice('')
    try {
      const res = await performCreateWorktree(repoPath, newTaskName, newBaseRef)
      if (!mountedRef.current) return
      setNewTaskName('')
      setNewBaseRef('')
      setNotice(t('coding.worktreeCreated', { branch: res.worktree.branch }))
      setSelectedWorktreePath(res.worktree.path)
      applyWorktreeToConversation(res.worktree.path, {
        currentConvId,
        newConversation,
        setConvWorkdir
      })
      await loadRepo(repoPath)
    } catch (caught) {
      if (!mountedRef.current) return
      setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
    } finally {
      if (mountedRef.current) setCreatingWorktree(false)
    }
  }, [
    currentConvId,
    loadRepo,
    newBaseRef,
    newConversation,
    newTaskName,
    repoPath,
    setConvWorkdir,
    t
  ])

  const handleRemoveWorktree = useCallback(
    async (worktree: WorkspaceWorktree) => {
      const confirmed =
        typeof window === 'undefined' ||
        typeof window.confirm !== 'function' ||
        window.confirm(
          t('coding.confirmRemove', { branch: worktree.branch, path: worktree.path })
        )
      if (!confirmed) return
      setRemovingPath(worktree.path)
      setError('')
      setNotice('')
      try {
        const res = await performRemoveWorktree(
          worktreeList?.repo_root || repoPath,
          worktree.path,
          { force: removeForce, delete_branch: removeDeleteBranch }
        )
        if (!mountedRef.current) return
        setNotice(t('coding.worktreeRemoved', { path: res.removed }))
        await loadRepo(repoPath)
      } catch (caught) {
        if (!mountedRef.current) return
        setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
      } finally {
        if (mountedRef.current) setRemovingPath(null)
      }
    },
    [loadRepo, removeDeleteBranch, removeForce, repoPath, t, worktreeList?.repo_root]
  )

  const handleToggleStaged = useCallback(
    (staged: boolean) => {
      setStagedOnly(staged)
      if (selectedWorktreePath) {
        void loadDiffFor(selectedWorktreePath, staged)
      }
    },
    [loadDiffFor, selectedWorktreePath]
  )

  const handleToggleCheckFile = useCallback((filePath: string) => {
    setCheckedFiles((prev) =>
      prev.includes(filePath) ? prev.filter((item) => item !== filePath) : [...prev, filePath]
    )
  }, [])

  const handleRevertFile = useCallback(
    async (filePath: string) => {
      if (!selectedWorktreePath) return
      const confirmed =
        typeof window === 'undefined' ||
        typeof window.confirm !== 'function' ||
        window.confirm(t('coding.confirmRevert', { path: filePath }))
      if (!confirmed) return
      setRevertingFilePath(filePath)
      setError('')
      setNotice('')
      try {
        const res = await performRevertFile(selectedWorktreePath, filePath)
        if (!mountedRef.current) return
        setNotice(t('coding.revertSuccess', { path: res.file_path }))
        await loadDiffFor(selectedWorktreePath, stagedOnly)
        if (repoPath.trim()) void loadRepo(repoPath)
      } catch (caught) {
        if (!mountedRef.current) return
        setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
      } finally {
        if (mountedRef.current) setRevertingFilePath(null)
      }
    },
    [loadDiffFor, loadRepo, repoPath, selectedWorktreePath, stagedOnly, t]
  )

  const handleCommit = useCallback(async () => {
    if (!selectedWorktreePath || !commitMessage.trim()) return
    setCommitting(true)
    setError('')
    setNotice('')
    try {
      const res = await performCommitWorkspace(
        selectedWorktreePath,
        commitMessage,
        checkedFiles.length > 0 ? checkedFiles : undefined
      )
      if (!mountedRef.current) return
      setCommitMessage('')
      setCheckedFiles([])
      setNotice(
        t('coding.commitSuccess', {
          sha: res.commit_sha.slice(0, 8),
          branch: res.branch,
          n: res.files_committed
        })
      )
      await loadDiffFor(selectedWorktreePath, stagedOnly)
      if (repoPath.trim()) void loadRepo(repoPath)
    } catch (caught) {
      if (!mountedRef.current) return
      setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
    } finally {
      if (mountedRef.current) setCommitting(false)
    }
  }, [checkedFiles, commitMessage, loadDiffFor, loadRepo, repoPath, selectedWorktreePath, stagedOnly, t])

  const executePlan = useCallback(
    async (approvalId?: string) => {
      if (!selectedWorktreePath) {
        setError(t('coding.needWorktree'))
        return
      }
      if (!execCommand.trim()) return
      setExecRunning(true)
      setError('')
      try {
        const result = await performRunExecPlan({
          worktree_path: selectedWorktreePath,
          mode: execMode,
          command: execCommand,
          ...(approvalId ? { approval_id: approvalId } : {})
        })
        if (!mountedRef.current) return
        setExecResult(result)
        if (result.status === 'approval_required' && result.approval_id) {
          setApprovalIdInput(result.approval_id)
        } else if (result.status === 'executed') {
          setApprovalIdInput('')
          // 构建或执行命令可能改变了工作区文件，自动刷新 Diff
          if (execMode === 'build') {
            void loadDiffFor(selectedWorktreePath, stagedOnly)
          }
        }
      } catch (caught) {
        if (!mountedRef.current) return
        setError(t('coding.errorPrefix', { e: caught instanceof Error ? caught.message : String(caught) }))
      } finally {
        if (mountedRef.current) setExecRunning(false)
      }
    },
    [execCommand, execMode, loadDiffFor, selectedWorktreePath, stagedOnly, t]
  )

  const handleOpenApprovalCenter = useCallback(() => {
    const id = approvalIdInput.trim() || execResult?.approval_id
    notifyApprovalCenter(id)
    setNotice(t('coding.approvalCenterTriggered'))
  }, [approvalIdInput, execResult?.approval_id, t])

  const handleRetryWithApproval = useCallback(() => {
    const id = approvalIdInput.trim() || execResult?.approval_id || ''
    if (!id) return
    void executePlan(id)
  }, [approvalIdInput, execResult?.approval_id, executePlan])

  return (
    <CodingControlPaneView
      repoPath={repoPath}
      activeWorkdir={activeWorkdir}
      worktreeList={worktreeList}
      selectedWorktreePath={selectedWorktreePath}
      loadingWorktrees={loadingWorktrees}
      newTaskName={newTaskName}
      newBaseRef={newBaseRef}
      creatingWorktree={creatingWorktree}
      removingPath={removingPath}
      removeDeleteBranch={removeDeleteBranch}
      removeForce={removeForce}
      diffSnapshot={diffSnapshot}
      stagedOnly={stagedOnly}
      loadingDiff={loadingDiff}
      selectedFilePath={selectedFilePath}
      checkedFiles={checkedFiles}
      revertingFilePath={revertingFilePath}
      commitMessage={commitMessage}
      committing={committing}
      execMode={execMode}
      execCommand={execCommand}
      execRunning={execRunning}
      execResult={execResult}
      approvalIdInput={approvalIdInput}
      notice={notice}
      error={error}
      canPickDirectory={canPickDirectory}
      onRepoPathChange={setRepoPath}
      onPickRepoDirectory={() => void handlePickRepoDirectory()}
      onLoadRepo={() => void loadRepo()}
      onNewTaskNameChange={setNewTaskName}
      onNewBaseRefChange={setNewBaseRef}
      onCreateWorktree={() => void handleCreateWorktree()}
      onSelectWorktree={handleSelectWorktree}
      onRemoveWorktree={(wt) => void handleRemoveWorktree(wt)}
      onToggleRemoveDeleteBranch={setRemoveDeleteBranch}
      onToggleRemoveForce={setRemoveForce}
      onToggleStaged={handleToggleStaged}
      onRefreshDiff={() => void loadDiffFor(selectedWorktreePath, stagedOnly)}
      onSelectFile={setSelectedFilePath}
      onToggleCheckFile={handleToggleCheckFile}
      onSelectAllFiles={() => setCheckedFiles(diffSnapshot?.files.map((f) => f.path) ?? [])}
      onClearCheckedFiles={() => setCheckedFiles([])}
      onRevertFile={(filePath) => void handleRevertFile(filePath)}
      onCommitMessageChange={setCommitMessage}
      onCommit={() => void handleCommit()}
      onExecModeChange={setExecMode}
      onExecCommandChange={setExecCommand}
      onRunExec={() => void executePlan()}
      onApprovalIdInputChange={setApprovalIdInput}
      onOpenApprovalCenter={handleOpenApprovalCenter}
      onRetryWithApproval={handleRetryWithApproval}
      onOpenChat={onOpenChat}
    />
  )
}
