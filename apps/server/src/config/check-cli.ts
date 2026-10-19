import { report } from "./report.js";

/**
 * `npm run config:check -w apps/server`: prints the problems and warnings of the configuration in
 * the environment (names only, never values) and exits with 1 when the server would refuse it.
 * `-- --job` checks it as the owner-role jobs see it (migrate, audit:prune, rewrap-secrets: they
 * also need MIGRATION_DATABASE_URL in production).
 */
const outcome = report(process.env, { ownerJob: process.argv.includes("--job") });
console.log(outcome.text);
process.exitCode = outcome.ok ? 0 : 1;
