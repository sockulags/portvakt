import type { BlindIndexPurpose } from "../crypto/blind-index.js";
import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import { PIN_INDEX_SUBJECT_PREFIX } from "../domain/person.js";
import { rewrapApplicationSecrets } from "./applications.js";
import { rewrapLoginMethodSecrets } from "./login-methods.js";
import { identityPinContext } from "./persons.js";
import { grantAgentContext, partyIdentifierContext } from "./representation.js";
import { rewrapSpKeys } from "./saml.js";
import { rewrapSigningKeys } from "./signing-keys.js";

export interface RewrapResult {
  readonly applicationSecrets: number;
  readonly loginMethodSecrets: number;
  readonly samlSpKeys: number;
  readonly signingKeys: number;
  readonly identityPins: number;
  readonly partyIdentifiers: number;
  readonly grantAgentIdentifiers: number;
}

interface IndexedColumn {
  readonly table: string;
  readonly idColumn: string;
  readonly encrypted: string;
  readonly index: string;
  readonly indexKey: string;
  readonly purpose: (row: Record<string, unknown>) => BlindIndexPurpose;
  readonly extraColumns: string;
  readonly context: (id: string) => string;
  /** Rows whose subject is the blind index (`pin-index:<index>`) get the new index there too. */
  readonly indexedSubject?: boolean;
}

const INDEXED_COLUMNS: readonly IndexedColumn[] = [
  {
    table: "identities",
    idColumn: "id",
    encrypted: "pin_encrypted",
    index: "pin_index",
    indexKey: "pin_index_key",
    purpose: () => "pin",
    extraColumns: "",
    context: identityPinContext,
    indexedSubject: true,
  },
  {
    table: "parties",
    idColumn: "id",
    encrypted: "identifier_encrypted",
    index: "identifier_index",
    indexKey: "identifier_index_key",
    purpose: (row) => (row.type === "person" ? "pin" : "orgnr"),
    extraColumns: ", type",
    context: partyIdentifierContext,
  },
  {
    table: "representation_grants",
    idColumn: "id",
    encrypted: "agent_identifier_encrypted",
    index: "agent_identifier_index",
    indexKey: "agent_identifier_index_key",
    purpose: () => "pin",
    extraColumns: "",
    context: grantAgentContext,
  },
];

/**
 * Re-encrypts and re-indexes encrypted personal identifiers whose envelope or blind index was
 * made with an older master key. Table and column names are constants above, never input.
 */
async function rewrapIndexed(db: Db, keys: KeyRing, column: IndexedColumn): Promise<number> {
  const rows = await db.query<Record<string, unknown> & { id: string; value: string }>(
    `SELECT ${column.idColumn} AS id, ${column.encrypted} AS value ${column.extraColumns}
       FROM ${column.table}
      WHERE ${column.encrypted} IS NOT NULL
        AND (${column.indexKey} <> $1 OR split_part(${column.encrypted}, '.', 2) <> $2)`,
    [keys.index.currentKeyId, keys.secrets.currentKeyId],
  );
  for (const row of rows) {
    const context = column.context(row.id);
    const plaintext = keys.secrets.decryptString(row.value, context);
    const index = keys.index.compute(column.purpose(row), plaintext);
    // An identity keyed by its pin (SAML subject source personalIdentityNumber) is re-keyed too.
    const subject =
      column.indexedSubject === true
        ? // Only identities of SAML methods whose subject source is the pin (never by prefix).
          `, subject = CASE WHEN EXISTS (
                 SELECT 1 FROM login_method_saml s
                  WHERE s.tenant_id = identities.tenant_id
                    AND s.login_method_id = identities.login_method_id
                    AND s.subject_source = 'personalIdentityNumber')
                    AND subject LIKE '${PIN_INDEX_SUBJECT_PREFIX}%'
               THEN '${PIN_INDEX_SUBJECT_PREFIX}' || $3 ELSE subject END`
        : "";
    await db.query(
      `UPDATE ${column.table}
          SET ${column.encrypted} = $2, ${column.index} = $3, ${column.indexKey} = $4${subject}
        WHERE ${column.idColumn} = $1 AND ${column.encrypted} = $5`,
      [row.id, keys.secrets.rewrap(row.value, context), index.index, index.keyId, row.value],
    );
  }
  return rows.length;
}

/**
 * Master key rotation: re-wraps every stored secret and re-computes every blind index that is not
 * under the current MASTER_KEY (the old key must still be listed in MASTER_KEY_PREVIOUS). Runs in
 * one transaction; safe to run repeatedly.
 */
export async function rewrapAllSecrets(db: Db, keys: KeyRing): Promise<RewrapResult> {
  return db.transaction(async (tx) => {
    const [identityPins, partyIdentifiers, grantAgentIdentifiers] = [
      await rewrapIndexed(tx, keys, INDEXED_COLUMNS[0] as IndexedColumn),
      await rewrapIndexed(tx, keys, INDEXED_COLUMNS[1] as IndexedColumn),
      await rewrapIndexed(tx, keys, INDEXED_COLUMNS[2] as IndexedColumn),
    ];
    return {
      applicationSecrets: await rewrapApplicationSecrets(tx, keys.secrets),
      loginMethodSecrets: await rewrapLoginMethodSecrets(tx, keys.secrets),
      samlSpKeys: await rewrapSpKeys(tx, keys.secrets),
      signingKeys: await rewrapSigningKeys(tx, keys.secrets),
      identityPins,
      partyIdentifiers,
      grantAgentIdentifiers,
    };
  });
}
