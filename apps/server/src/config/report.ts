import { existsSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_LOGIN_UI_DIR } from "../login/ui-shell.js";
import { checkConfig, type ConfigReport } from "./index.js";

/**
 * The report of `npm run config:check -w apps/server` (`check-cli.ts`): validates the
 * environment the way the server does at start (every production refusal: development defaults,
 * http URLs, one database role for migrations and runtime, unprotected metrics, private upstream
 * hosts, short or reused secrets), plus what start-up checks beyond the variables (the login UI
 * build in production), and lists the problems and warnings by variable name. Values are never
 * printed. `ok` is false when the server would refuse to start.
 */
export function report(env: NodeJS.ProcessEnv): { readonly text: string; readonly ok: boolean } {
  const result: ConfigReport = checkConfig(env);
  const issues = [...result.issues];
  if (result.nodeEnv === "production") {
    const dir = env.LOGIN_UI_DIR?.trim() ? env.LOGIN_UI_DIR.trim() : DEFAULT_LOGIN_UI_DIR;
    if (!existsSync(join(dir, "index.html"))) {
      issues.push(
        "LOGIN_UI_DIR: the login UI build (index.html) is missing; production refuses to start",
      );
    }
  }
  const lines = [`Portvakt configuration check (NODE_ENV=${result.nodeEnv})`];
  if (issues.length === 0)
    lines.push("No problems: the server would start with this configuration.");
  else {
    lines.push(`${issues.length} problem(s); the server refuses to start:`);
    for (const issue of issues) lines.push(`  - ${issue}`);
  }
  if (result.warnings.length > 0) {
    lines.push(`${result.warnings.length} warning(s):`);
    for (const warning of result.warnings) lines.push(`  - ${warning}`);
  }
  return { text: lines.join("\n"), ok: issues.length === 0 };
}
