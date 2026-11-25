import React, { useCallback, useEffect, useState } from 'react'
import { isDurablePaidMediaAssetRef } from '../../api'

export function observePaidMediaNearViewport(
  target: Element,
  onVisibilityChange: (nearViewport: boolean) => void,
  Observer: typeof IntersectionObserver | undefined =
    typeof globalThis.IntersectionObserver === 'function'
      ? globalThis.IntersectionObserver
      : undefined
): () => void {
  if (!Observer) return () => {}
  const observer = new Observer(
    (entries) => {
      const entry = entries.find((candidate) => candidate.target === target)
      if (entry) onVisibilityChange(entry.isIntersecting)
    },
    { rootMargin: '512px 0px' }
  )
  observer.observe(target)
  return () => observer.disconnect()
}

export function useResolvedMediaSource<T extends Element>(
  src: string | undefined
): [string | undefined, React.RefCallback<T>] {
  const durable = Boolean(src && isDurablePaidMediaAssetRef(src))
  const [resolved, setResolved] = useState<string | undefined>(durable ? undefined : src)
  const [target, setTargetElement] = useState<T | null>(null)
  const setTarget = useCallback((node: T | null) => setTargetElement(node), [])
  useEffect(() => {
    setResolved(durable ? undefined : src)
    if (!src || !durable || !target || !window.api?.resolvePaidMediaAsset) {
      return
    }
    let disposed = false
    let nearViewport = false
    let owned = false
    let requestGeneration = 0
    const release = (): void => {
      if (owned) {
        window.api?.releasePaidMediaAsset?.(src)
        owned = false
      }
    }
    const stopObserving = observePaidMediaNearViewport(target, (isNearViewport) => {
      if (isNearViewport === nearViewport) return
      nearViewport = isNearViewport
      requestGeneration += 1
      const generation = requestGeneration
      if (!nearViewport) {
        setResolved(undefined)
        release()
        return
      }
      void window.api
        ?.resolvePaidMediaAsset?.(src)
        .then((url) => {
          owned = true
          if (disposed || !nearViewport || generation !== requestGeneration) {
            release()
            return
          }
          setResolved(url)
        })
        .catch(() => {
          // Keep the durable reference in state for later retry/reload; never expose it as src.
        })
    })
    return () => {
      disposed = true
      requestGeneration += 1
      stopObserving()
      release()
    }
  }, [durable, src, target])
  return [resolved, setTarget]
}

export function ResolvedPaidMediaImage(
  props: React.ImgHTMLAttributes<HTMLImageElement>
): React.JSX.Element {
  const [resolved, setTarget] = useResolvedMediaSource<HTMLImageElement>(
    typeof props.src === 'string' ? props.src : undefined
  )
  return <img {...props} ref={setTarget} src={resolved} loading={props.loading ?? 'lazy'} />
}

export function ResolvedPaidMediaVideo(
  props: React.VideoHTMLAttributes<HTMLVideoElement>
): React.JSX.Element {
  const [resolved, setTarget] = useResolvedMediaSource<HTMLVideoElement>(
    typeof props.src === 'string' ? props.src : undefined
  )
  return <video {...props} ref={setTarget} src={resolved} preload={props.preload ?? 'metadata'} />
}
