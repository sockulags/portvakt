import type { AuditEvent } from "../domain/audit.js";
import type { Logger } from "../logging/logger.js";
import type { AuditRepository } from "../repositories/audit.js";
import { auditEvent, type AuditAction, type CatalogueEvent } from "./catalogue.js";

/**
 * Where committed audit events go besides the append-only table: the starter kit's log service
 * later. v1 forwards nothing ({@link NOOP_AUDIT_SINK}). A sink receives only events whose write
 * has committed; it must not throw for a single bad event and never blocks the caller.
 */
export interface AuditSink {
  forward(events: readonly AuditEvent[]): Promise<void>;
}

export const NOOP_AUDIT_SINK: AuditSink = {
  forward: () => Promise.resolve(),
};

export interface AuditLogOptions {
  /** The pool-backed repository, for events written on their own. */
  readonly audit: AuditRepository;
  readonly logger: Logger;
  readonly sink?: AuditSink;
}

/**
 * Writes catalogue events (`catalogue.ts`) to the append-only audit log.
 *
 * - {@link record}: on its own statement, outside any business transaction. Failure events
 *   (refused logins, refused refreshes, denied representations) go here, so they are kept even
 *   when the work they belong to is rolled back. A failed write is logged, never thrown: auditing
 *   never breaks the flow it observes.
 * - {@link recordIn}: through a transaction's repository, for success events that commit (or
 *   roll back) with the change they describe. Throws, so the transaction rolls back when the
 *   event cannot be written. Call {@link forward} with the result once the transaction committed.
 */
export class AuditLog {
  readonly #audit: AuditRepository;
  readonly #logger: Logger;
  readonly #sink: AuditSink;

  constructor(options: AuditLogOptions) {
    this.#audit = options.audit;
    this.#logger = options.logger.child({ component: "audit" });
    this.#sink = options.sink ?? NOOP_AUDIT_SINK;
  }

  async record<A extends AuditAction>(event: CatalogueEvent<A>): Promise<AuditEvent | undefined> {
    try {
      const stored = await this.#audit.append(auditEvent(event));
      this.forward([stored]);
      return stored;
    } catch (error) {
      this.#logger.error({ err: error, action: event.action }, "audit event could not be written");
      return undefined;
    }
  }

  async recordIn<A extends AuditAction>(
    audit: AuditRepository,
    event: CatalogueEvent<A>,
  ): Promise<AuditEvent> {
    return audit.append(auditEvent(event));
  }

  /** Hands committed events to the sink without waiting; sink failures are logged. */
  forward(events: readonly AuditEvent[]): void {
    if (events.length === 0) return;
    this.#sink.forward(events).catch((error: unknown) => {
      this.#logger.warn({ err: error, events: events.length }, "audit sink failed");
    });
  }
}
