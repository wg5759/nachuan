import type {
  PaidMediaRecoverableMutationDescriptor,
  PaidMediaRecoverableMutationExecutor
} from './paid-media-installation-root'

export class PaidMediaRecoveryExecutorSlot implements PaidMediaRecoverableMutationExecutor {
  private bindingState: 'unbound' | 'binding' | 'bound' = 'unbound'
  private delegateExecute:
    | ((descriptor: Readonly<PaidMediaRecoverableMutationDescriptor>) => Promise<void>)
    | undefined

  bind(delegate: PaidMediaRecoverableMutationExecutor): void {
    if (this.bindingState !== 'unbound') {
      throw new Error('Paid media recovery executor slot is already bound')
    }
    if (
      typeof delegate !== 'object' ||
      delegate === null ||
      delegate === this
    ) {
      throw new Error('Paid media recovery executor slot delegate is invalid')
    }
    this.bindingState = 'binding'
    let execute: unknown
    try {
      execute = delegate.execute
    } catch {
      this.bindingState = 'unbound'
      throw new Error('Paid media recovery executor slot delegate is invalid')
    }
    if (typeof execute !== 'function') {
      this.bindingState = 'unbound'
      throw new Error('Paid media recovery executor slot delegate is invalid')
    }
    this.delegateExecute = (descriptor) =>
      Reflect.apply(execute, delegate, [descriptor]) as Promise<void>
    this.bindingState = 'bound'
  }

  async execute(descriptor: Readonly<PaidMediaRecoverableMutationDescriptor>): Promise<void> {
    const delegateExecute = this.delegateExecute
    if (delegateExecute === undefined) {
      throw new Error('Paid media recovery executor slot is not bound')
    }
    await delegateExecute(descriptor)
  }
}
