import React from 'react'
import { useTranslation } from 'react-i18next'

import type { ModelInfo } from '../store'

export type CreativeMode = 'image' | 'video'

export interface CreativeSubmission {
  mode: CreativeMode
  model: string
  prompt: string
  referenceImage: string | null
}

export interface CreativeDrawerProps {
  mode: CreativeMode
  onModeChange: (mode: CreativeMode) => void
  models: ModelInfo[]
  currentModel: string
  onCurrentModelChange: (model: string) => void
  prompt: string
  onPromptChange: (prompt: string) => void
  referenceImage: string | null
  onReferenceImageChange: (referenceImage: string | null) => void
  onSubmit: (submission: CreativeSubmission) => void
  disabled?: boolean
}

export function buildCreativeSubmission(
  mode: CreativeMode,
  model: string,
  prompt: string,
  referenceImage: string | null
): CreativeSubmission {
  return {
    mode,
    model,
    prompt,
    referenceImage: mode === 'video' ? referenceImage : null
  }
}

export function CreativeDrawer({
  mode,
  onModeChange,
  models,
  currentModel,
  onCurrentModelChange,
  prompt,
  onPromptChange,
  referenceImage,
  onReferenceImageChange,
  onSubmit,
  disabled = false
}: CreativeDrawerProps): React.ReactNode {
  const { t } = useTranslation()
  const availableModels = models.filter((model) => model.modality === mode)
  const selectedModelIsAvailable = availableModels.some((model) => model.id === currentModel)
  const canSubmit = !disabled && selectedModelIsAvailable && prompt.trim().length > 0

  return (
    <form
      className="nachuan-creative-drawer"
      data-creative-mode={mode}
      aria-label={t('creative.aria')}
      onSubmit={(event) => {
        event.preventDefault()
        if (!canSubmit) return
        onSubmit(buildCreativeSubmission(mode, currentModel, prompt, referenceImage))
      }}
    >
      <header className="nachuan-creative-drawer-header">
        <div>
          <strong>{t('creative.title')}</strong>
          <p>{t('creative.subtitle')}</p>
        </div>
        <div role="group" aria-label={t('creative.type')}>
          <button
            type="button"
            aria-pressed={mode === 'image'}
            onClick={() => onModeChange('image')}
          >
            {t('creative.image')}
          </button>
          <button
            type="button"
            aria-pressed={mode === 'video'}
            onClick={() => onModeChange('video')}
          >
            {t('creative.video')}
          </button>
        </div>
      </header>

      <label>
        <span>{t('creative.model')}</span>
        <select
          aria-label={t('creative.modelAria')}
          value={currentModel}
          onChange={(event) => onCurrentModelChange(event.currentTarget.value)}
        >
          {availableModels.map((model) => (
            <option key={model.id} value={model.id}>
              {model.description || model.id}
            </option>
          ))}
        </select>
      </label>

      <label>
        <span>{t('creative.prompt')}</span>
        <textarea
          aria-label={t('creative.promptAria')}
          value={prompt}
          onChange={(event) => onPromptChange(event.currentTarget.value)}
          placeholder={mode === 'image' ? t('creative.promptImage') : t('creative.promptVideo')}
        />
      </label>

      {mode === 'video' && !referenceImage ? (
        <label className="nachuan-creative-file-picker">
          <span>{t('creative.referenceOptional')}</span>
          <input
            type="file"
            accept="image/*"
            onChange={(event) => {
              const file = event.currentTarget.files?.[0]
              event.currentTarget.value = ''
              if (!file || !file.type.startsWith('image/')) return
              const reader = new FileReader()
              reader.addEventListener('load', () => {
                if (typeof reader.result === 'string') onReferenceImageChange(reader.result)
              })
              reader.readAsDataURL(file)
            }}
          />
          <span className="nachuan-creative-file-action">{t('creative.addReference')}</span>
        </label>
      ) : null}

      {mode === 'video' && referenceImage ? (
        <figure className="nachuan-creative-reference">
          <img src={referenceImage} alt={t('creative.previewAlt')} />
          <figcaption>{t('creative.referenceReady')}</figcaption>
          <button type="button" onClick={() => onReferenceImageChange(null)}>
            {t('creative.removeReference')}
          </button>
        </figure>
      ) : null}

      {availableModels.length === 0 ? (
        <p role="status">{t('creative.noModels')}</p>
      ) : null}

      <button type="submit" disabled={!canSubmit}>
        {mode === 'image' ? t('creative.generateImage') : t('creative.generateVideo')}
      </button>
    </form>
  )
}
