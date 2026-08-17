/** Runtime-only Vitest shim; production Wrangler resolves Cloudflare modules. */
export class DurableObject<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;

  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}

export class WorkerEntrypoint<Env = unknown, Props = unknown> {
  protected ctx: unknown;
  protected env: Env;
  protected props: Props | undefined;

  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}

export class WorkflowEntrypoint<Env = unknown, Params = unknown> extends WorkerEntrypoint<Env, Params> {}

export class NonRetryableError extends Error {}

export function connect(): never {
  throw new Error("cloudflare:sockets is unavailable in the Node test runtime; inject a socket connector.");
}
