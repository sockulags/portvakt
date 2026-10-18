import { createApp } from "./app.js";
import { type Config, ConfigError, loadConfig } from "./config/index.js";

function loadConfigOrExit(): Config {
  try {
    return loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }
}

const config = loadConfigOrExit();

createApp().listen(config.port, () => {
  console.log(`portvakt server listening on port ${config.port}`);
});
