import { z } from "zod";
import { jsonValueSchema, type JsonValue } from "./schemas.js";

export const AUDIT_ACTOR_TYPES = ["person", "application", "system"] as const;
export type AuditActorType = (typeof AUDIT_ACTOR_TYPES)[number];

export const AUDIT_OUTCOMES = ["success", "failure"] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

/** Dotted lowercase action names, for example `login.success` or `admin.tenant.create`. */
export const auditActionSchema = z
  .string()
  .max(100)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/, "must be a dotted lowercase name");

export interface AuditEvent {
  readonly id: string;
  /** Monotonic sequence, used as pagination cursor. */
  readonly seq: string;
  readonly occurredAt: Date;
  /** `null` for platform-level events. */
  readonly tenantId: string | null;
  readonly actor: { readonly type: AuditActorType; readonly id: string | null };
  readonly subject: { readonly type: string; readonly id: string } | null;
  readonly action: string;
  readonly outcome: AuditOutcome;
  /** Free-form context. Callers must not put personal data or secrets here. */
  readonly details: Readonly<Record<string, JsonValue>>;
}

export const appendAuditEventInputSchema = z.object({
  tenantId: z.uuid().nullable(),
  actor: z.object({
    type: z.enum(AUDIT_ACTOR_TYPES),
    id: z.string().min(1).max(255).nullable().default(null),
  }),
  subject: z
    .object({ type: z.string().min(1).max(64), id: z.string().min(1).max(255) })
    .nullable()
    .default(null),
  action: auditActionSchema,
  outcome: z.enum(AUDIT_OUTCOMES).default("success"),
  details: z.record(z.string(), jsonValueSchema).default({}),
});
export type AppendAuditEventInput = z.input<typeof appendAuditEventInputSchema>;

export const auditFilterSchema = z.object({
  actions: z.array(auditActionSchema).max(50).optional(),
  /** Matches the action itself and everything below it: `login` matches `login.success`. */
  actionPrefix: z
    .string()
    .regex(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/)
    .optional(),
  actorId: z.string().min(1).max(255).optional(),
  subjectId: z.string().min(1).max(255).optional(),
  outcome: z.enum(AUDIT_OUTCOMES).optional(),
  from: z.date().optional(),
  to: z.date().optional(),
});
export type AuditFilter = z.input<typeof auditFilterSchema>;

/** Largest Postgres bigint; `seq` never exceeds it. */
const MAX_BIGINT = 9_223_372_036_854_775_807n;

export const auditPageSchema = z.object({
  limit: z.number().int().min(1).max(200).default(50),
  /** Opaque cursor from a previous page's `nextCursor`. */
  cursor: z
    .string()
    .regex(/^\d{1,19}$/, "must be a cursor returned by a previous page")
    .refine((value) => BigInt(value) <= MAX_BIGINT, "must be a cursor returned by a previous page")
    .optional(),
});
export type AuditPage = z.input<typeof auditPageSchema>;

export interface AuditEventPage {
  readonly events: readonly AuditEvent[];
  /** Pass as `cursor` to get the next (older) page; `null` when there is none. */
  readonly nextCursor: string | null;
}
