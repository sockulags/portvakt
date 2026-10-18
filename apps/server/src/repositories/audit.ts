import { z } from "zod";
import type { Db } from "../db/database.js";
import {
  appendAuditEventInputSchema,
  type AppendAuditEventInput,
  type AuditActorType,
  type AuditEvent,
  type AuditEventPage,
  auditFilterSchema,
  type AuditFilter,
  type AuditOutcome,
  auditPageSchema,
  type AuditPage,
} from "../domain/audit.js";
import { jsonValueSchema } from "../domain/schemas.js";
import { mapDbErrors, parseInput, requireUuids } from "./errors.js";
import { requireRow, SqlParams } from "./sql.js";

interface AuditRow {
  seq: string;
  id: string;
  occurred_at: Date;
  tenant_id: string | null;
  actor_type: AuditActorType;
  actor_id: string | null;
  subject_type: string | null;
  subject_id: string | null;
  action: string;
  outcome: AuditOutcome;
  details: unknown;
}

const COLUMNS =
  "seq, id, occurred_at, tenant_id, actor_type, actor_id, subject_type, subject_id, action, outcome, details";

const detailsSchema = z.record(z.string(), jsonValueSchema);

function toEvent(row: AuditRow): AuditEvent {
  return {
    id: row.id,
    seq: row.seq,
    occurredAt: row.occurred_at,
    tenantId: row.tenant_id,
    actor: { type: row.actor_type, id: row.actor_id },
    subject:
      row.subject_type === null || row.subject_id === null
        ? null
        : { type: row.subject_type, id: row.subject_id },
    action: row.action,
    outcome: row.outcome,
    details: detailsSchema.parse(row.details),
  };
}

/** Which tenants a query covers. */
export type AuditScope =
  | { readonly tenantId: string }
  /** Platform administration: every tenant; `tenantId: null` narrows to platform-level events. */
  | { readonly allTenants: true; readonly tenantId?: string | null };

/** Append-only audit log. The table rejects UPDATE, DELETE and TRUNCATE by trigger. */
export class AuditRepository {
  readonly #db: Db;

  constructor(db: Db) {
    this.#db = db;
  }

  async append(input: AppendAuditEventInput): Promise<AuditEvent> {
    const data = parseInput(appendAuditEventInputSchema, input);
    const rows = await mapDbErrors(() =>
      this.#db.query<AuditRow>(
        `INSERT INTO audit_events
           (tenant_id, actor_type, actor_id, subject_type, subject_id, action, outcome, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
         RETURNING ${COLUMNS}`,
        [
          data.tenantId,
          data.actor.type,
          data.actor.id,
          data.subject?.type ?? null,
          data.subject?.id ?? null,
          data.action,
          data.outcome,
          JSON.stringify(data.details),
        ],
      ),
    );
    return toEvent(requireRow(rows));
  }

  /** Newest first, keyset paginated. */
  async query(
    scope: AuditScope,
    filter: AuditFilter = {},
    page: AuditPage = {},
  ): Promise<AuditEventPage> {
    requireUuids({ tenantId: scope.tenantId });
    const f = parseInput(auditFilterSchema, filter);
    const p = parseInput(auditPageSchema, page);
    const params = new SqlParams();
    const where: string[] = [];

    if ("allTenants" in scope) {
      if (scope.tenantId === null) where.push("tenant_id IS NULL");
      else if (scope.tenantId !== undefined)
        where.push(`tenant_id = ${params.add(scope.tenantId)}`);
    } else {
      where.push(`tenant_id = ${params.add(scope.tenantId)}`);
    }
    if (f.actions !== undefined) where.push(`action = ANY (${params.add(f.actions)}::text[])`);
    if (f.actionPrefix !== undefined) {
      const prefix = params.add(f.actionPrefix);
      where.push(`(action = ${prefix} OR starts_with(action, ${prefix} || '.'))`);
    }
    if (f.actorId !== undefined) where.push(`actor_id = ${params.add(f.actorId)}`);
    if (f.subjectId !== undefined) where.push(`subject_id = ${params.add(f.subjectId)}`);
    if (f.outcome !== undefined) where.push(`outcome = ${params.add(f.outcome)}`);
    if (f.from !== undefined) where.push(`occurred_at >= ${params.add(f.from)}`);
    if (f.to !== undefined) where.push(`occurred_at < ${params.add(f.to)}`);
    if (p.cursor !== undefined) where.push(`seq < ${params.add(p.cursor)}::bigint`);

    const rows = await this.#db.query<AuditRow>(
      `SELECT ${COLUMNS} FROM audit_events
        ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY seq DESC
        LIMIT ${params.add(p.limit + 1)}`,
      params.values,
    );
    const hasMore = rows.length > p.limit;
    const events = rows.slice(0, p.limit).map(toEvent);
    return { events, nextCursor: hasMore ? (events.at(-1)?.seq ?? null) : null };
  }
}
