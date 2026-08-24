import React, { useState } from 'react'

import KbPane from './KbPane'
import MediaPane from './MediaPane'

type FilesSection = 'knowledge' | 'media'

export default function FilesPane(): React.ReactNode {
  const [section, setSection] = useState<FilesSection>('knowledge')

  return (
    <div data-files-workspace="true" className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-1 border-b border-neutral-800 px-3 py-2">
        <button
          type="button"
          aria-pressed={section === 'knowledge'}
          onClick={() => setSection('knowledge')}
          className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
            section === 'knowledge'
              ? 'bg-neutral-800 text-neutral-100'
              : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-200'
          }`}
        >
          知识库
        </button>
        <button
          type="button"
          aria-pressed={section === 'media'}
          onClick={() => setSection('media')}
          className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
            section === 'media'
              ? 'bg-neutral-800 text-neutral-100'
              : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-200'
          }`}
        >
          媒体工具
        </button>
      </div>
      <div className="min-h-0 flex-1">{section === 'knowledge' ? <KbPane /> : <MediaPane />}</div>
    </div>
  )
}
