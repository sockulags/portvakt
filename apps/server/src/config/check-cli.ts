import { report } from "./report.js";

/**
 * `npm run config:check -w apps/server`: prints the problems and warnings of the configuration in
 * the environment (names only, never values) and exits with 1 when the server would refuse it.
 */
const outcome = report(process.env);
console.log(outcome.text);
process.exitCode = outcome.ok ? 0 : 1;
