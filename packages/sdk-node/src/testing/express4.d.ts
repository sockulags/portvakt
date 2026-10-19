/** Express 4 (devDependency alias `express4`), for the compatibility test. */
declare module "express4" {
  import type { Express } from "express";
  const express: () => Express;
  export default express;
}
