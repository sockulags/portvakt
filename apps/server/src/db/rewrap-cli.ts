import { ConfigError, loadConfig } from "../config/index.js";
import { createKeyRing } from "../crypto/keyring.js";
import { rewrapAllSecrets } from "../repositories/index.js";
import { createDb, createPool } from "./database.js";

/**
 * `npm run rewrap-secrets -w apps/server`: after moving the old MASTER_KEY to MASTER_KEY_PREVIOUS
 * and setting a new MASTER_KEY, re-wraps every stored secret under the new key. Once it reports
 * zero remaining, the old key can be dropped from MASTER_KEY_PREVIOUS.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const keys = createKeyRing(config.masterKeys);
  const pool = createPool({
    url: config.database.url,
    poolMax: 1,
    applicationName: "portvakt-rewrap",
  });
  try {
    const result = await rewrapAllSecrets(createDb(pool), keys);
    const summary = Object.entries(result)
      .map(([kind, count]) => `${kind}=${count}`)
      .join(", ");
    console.log(`re-wrapped under master key ${keys.secrets.currentKeyId}: ${summary}`);
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  console.error(
    error instanceof ConfigError
      ? error.message
      : `re-wrap failed: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
