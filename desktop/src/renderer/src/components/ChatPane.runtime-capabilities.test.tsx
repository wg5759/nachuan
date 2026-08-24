import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'

import { CLIENT_PORT_CAPABILITIES } from '../../../runtime-capabilities'
import i18n from '../i18n'
import { ComposerAttachmentRow } from './ChatPane'

describe('chat composer runtime capabilities', () => {
  it('hides the unsupported directory picker on Web while keeping it on Electron', async () => {
    await i18n.changeLanguage('zh')
    const callbacks = {
      onPickFile: () => undefined,
      onPickFolder: () => undefined
    }

    const webHtml = renderToStaticMarkup(
      <ComposerAttachmentRow
        runtimeKind="web"
        runtimeCapabilities={CLIENT_PORT_CAPABILITIES}
        {...callbacks}
      />
    )
    const electronHtml = renderToStaticMarkup(
      <ComposerAttachmentRow
        runtimeKind="electron"
        runtimeCapabilities={CLIENT_PORT_CAPABILITIES}
        {...callbacks}
      />
    )

    expect(webHtml).toContain(i18n.t('chat.addFile'))
    expect(webHtml).not.toContain(i18n.t('chat.addFolder'))
    expect(electronHtml).toContain(i18n.t('chat.addFile'))
    expect(electronHtml).toContain(i18n.t('chat.addFolder'))
  })
})
