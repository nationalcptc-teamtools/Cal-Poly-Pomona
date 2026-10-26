// Type surface of relay-inbox.mjs for the TypeScript side (tests + tsc).

export declare const INBOX_BATCH: number;
export declare const INBOX_MAX_QUEUED: number;
export declare const INBOX_MAX_QUEUED_BYTES: number;

export interface RelayInboxOptions<M> {
  deliver: (batch: M[]) => void;
  schedule?: (fn: () => void) => void;
  onOverflow?: (info: { messages: number; bytes: number }) => void;
  /** False once the socket has left OPEN: the next turn applies everything queued. */
  isOpen?: () => boolean;
  batch?: number;
  maxQueued?: number;
  maxQueuedBytes?: number;
}

export interface RelayInbox<M> {
  push(message: M): boolean;
  flush(): void;
  discard(): void;
  readonly size: number;
  readonly bytes: number;
  readonly closed: boolean;
}

export declare function createRelayInbox<M = Uint8Array>(opts: RelayInboxOptions<M>): RelayInbox<M>;
