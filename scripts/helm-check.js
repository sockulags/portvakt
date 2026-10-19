#!/usr/bin/env node
// @ts-check
/**
 * `npm run helm:check`: lints the Helm chart (deploy/helm/portvakt) with `helm lint --strict`,
 * renders it with `helm template` and validates the manifests with kubeconform, for each values
 * set below: the defaults, the production-like ci/production-values.yaml, and every optional
 * part switched on. Helm and kubeconform run in their containers, pinned by digest in
 * deploy/images.Dockerfile (no local helm needed); kubeconform fetches the Kubernetes schemas.
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { image } from "./images.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const charts = join(root, "deploy", "helm");
const HELM = image("helm");
const KUBECONFORM = image("kubeconform");
/** The chart's kubeVersion is >=1.27; validate against a current release. */
const KUBERNETES_VERSION = "1.30.0";

/** @type {{ name: string; args: string[] }[]} */
const VALUE_SETS = [
  { name: "default values", args: [] },
  { name: "production-like values", args: ["-f", "portvakt/ci/production-values.yaml"] },
  {
    name: "every optional part on",
    args: [
      "--set",
      "networkPolicy.enabled=true",
      "--set",
      "server.autoscaling.enabled=true",
      "--set",
      "metrics.serviceMonitor.enabled=true",
      "--set",
      "metrics.serviceMonitor.tokenSecretKey=METRICS_TOKEN",
      "--set",
      "networkPolicy.database.podSelector.matchLabels.app=postgres",
      "--set",
      "database.maxConnections=197",
    ],
  },
];

/**
 * @param {string[]} args
 * @param {string} [input]
 */
function docker(args, input) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    input,
    maxBuffer: 64 * 1024 * 1024,
    // Git Bash on Windows would rewrite the container paths.
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
  });
  if (result.error) throw result.error;
  return result;
}

/** @param {string[]} args */
function helm(args) {
  return docker(["run", "--rm", "-v", `${charts}:/charts`, "-w", "/charts", HELM, ...args]);
}

let failed = false;
for (const set of VALUE_SETS) {
  const lint = helm(["lint", "--strict", "portvakt", ...set.args]);
  const rendered = helm(["template", "portvakt-check", "portvakt", ...set.args]);
  /** @type {{ status: number | null; stdout: string; stderr: string }} */
  let validation = { status: 1, stdout: "", stderr: "not run" };
  if (rendered.status === 0) {
    validation = docker(
      [
        "run",
        "--rm",
        "-i",
        KUBECONFORM,
        "-strict",
        "-summary",
        "-ignore-missing-schemas",
        "-kubernetes-version",
        KUBERNETES_VERSION,
        "-",
      ],
      rendered.stdout,
    );
  }
  const ok = lint.status === 0 && rendered.status === 0 && validation.status === 0;
  console.log(`${ok ? "ok  " : "FAIL"} ${set.name}`);
  console.log(`     helm lint: ${lint.stdout.trim().split("\n").at(-1) ?? ""}`);
  console.log(`     kubeconform: ${validation.stdout.trim().split("\n").at(-1) ?? ""}`);
  if (!ok) {
    failed = true;
    for (const output of [lint.stdout, lint.stderr, rendered.stderr, validation.stdout]) {
      if (output.trim() !== "") console.error(output.trim());
    }
  }
}
if (failed) process.exit(1);
console.log("helm:check: the chart lints, renders and validates");
