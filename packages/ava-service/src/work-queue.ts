export class WorkQueueFullError extends Error { override name = 'WorkQueueFullError'; }
export class WorkQueueCancelledError extends Error {
  override name = 'AbortError';
  constructor() { super('Queued work cancelled'); }
}

interface Work {
  key?: string;
  start: () => void;
  detach: () => void;
}

/** Bounded in-process work; keyed operations keep one owner without blocking other keys. */
export class WorkQueue {
  private active = 0;
  private readonly keys = new Set<string>();
  private readonly pending: Work[] = [];
  private readonly idleWaiters = new Set<() => void>();

  constructor(private readonly concurrency: number, private readonly maxPending: number) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1
        || !Number.isSafeInteger(maxPending) || maxPending < 0) {
      throw new Error('Work concurrency must be positive and pending limit nonnegative integers');
    }
  }

  /**
   * Cancel queued admission with signal; once started, operation owns its cancellation.
   * Equal keys serialize until settlement. Other keys may pass a blocked waiter.
   */
  run<T>(operation: () => Promise<T>, options: { key?: string; signal?: AbortSignal } = {}): Promise<T> {
    if (options.signal?.aborted) return Promise.reject(new WorkQueueCancelledError());
    return new Promise<T>((resolve, reject) => {
      const cancel = () => {
        const index = this.pending.indexOf(job);
        if (index < 0) return;
        this.pending.splice(index, 1);
        job.detach();
        reject(new WorkQueueCancelledError());
        this.pump();
      };
      const job: Work = {
        key: options.key,
        detach: () => options.signal?.removeEventListener('abort', cancel),
        start: () => {
          job.detach();
          this.active++;
          if (job.key !== undefined) this.keys.add(job.key);
          const complete = () => {
            this.active--;
            if (job.key !== undefined) this.keys.delete(job.key);
            this.pump();
          };
          void Promise.resolve().then(operation).then(
            value => { complete(); resolve(value); }, error => { complete(); reject(error); });
        },
      };
      if (this.active < this.concurrency && this.available(job)) job.start();
      else if (this.pending.length >= this.maxPending) reject(new WorkQueueFullError('Work queue is full'));
      else {
        this.pending.push(job);
        options.signal?.addEventListener('abort', cancel, { once: true });
      }
    });
  }

  idle(): Promise<void> {
    return this.active === 0 && this.pending.length === 0 ? Promise.resolve()
      : new Promise<void>(resolve => { this.idleWaiters.add(resolve); });
  }

  private available(job: Work): boolean { return job.key === undefined || !this.keys.has(job.key); }
  private pump(): void {
    while (this.active < this.concurrency) {
      const index = this.pending.findIndex(job => this.available(job));
      if (index < 0) break;
      this.pending.splice(index, 1)[0]!.start();
    }
    if (this.active === 0 && this.pending.length === 0) {
      for (const resolve of this.idleWaiters) resolve();
      this.idleWaiters.clear();
    }
  }
}
