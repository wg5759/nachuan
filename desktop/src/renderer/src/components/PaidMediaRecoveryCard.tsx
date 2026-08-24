import React from 'react'

export interface PaidMediaRecoveryCardProps {
  operationId: string
  blocked: boolean
  recovering: boolean
  onRetry: () => void
  onDiscard: () => void
}

export function PaidMediaRecoveryCard({
  operationId,
  blocked,
  recovering,
  onRetry,
  onDiscard
}: PaidMediaRecoveryCardProps): React.JSX.Element {
  return (
    <div className="mt-1 inline-flex max-w-[85%] flex-wrap items-center gap-2 rounded-md border border-amber-700/70 bg-amber-950/30 px-2 py-1.5 text-xs text-amber-200">
      <span>
        {blocked
          ? '该操作已停止自动恢复，请先人工核对。'
          : '保留了原付费操作编号，可安全查询/恢复。'}
      </span>
      <span className="basis-full">
        纳川诊断编号：
        <code
          aria-label="付费媒体诊断编号"
          className="break-all font-mono text-amber-100 select-text"
        >
          {operationId}
        </code>
      </span>
      <button
        onClick={onRetry}
        disabled={blocked || recovering}
        className="rounded bg-amber-700 px-2 py-0.5 text-white hover:bg-amber-600 disabled:opacity-40"
      >
        {recovering ? '查询恢复中…' : '查询/恢复原操作'}
      </button>
      <button
        onClick={onDiscard}
        disabled={recovering}
        className="text-amber-300 hover:text-white disabled:opacity-40"
      >
        人工核对后移除
      </button>
    </div>
  )
}
