import { createDemoApp } from "./app.js";
import { DemoConfigError, loadDemoConfig } from "./config.js";

/**
 * Entry point. One codebase, run twice: Service A and Service B differ in APP_NAME, PORT,
 * CLIENT_ID, CLIENT_SECRET and COOKIE_NAME (cookies on localhost are shared across ports).
 * `npm run dev:stack` starts both with the seeded `demo` tenant.
 */
function main(): void {
  let config;
  try {
    config = loadDemoConfig();
  } catch (error) {
    if (error instanceof DemoConfigError) {
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }
  const server = createDemoApp(config).listen(config.port, () => {
    console.log(`${config.appName} (${config.clientId}) listening on ${config.publicUrl}`);
  });
  const stop = (): void => {
    server.close(() => process.exit(0));
    server.closeAllConnections();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main();
