import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 3100);

createApp().listen(port, () => {
  console.log(`mock-idp listening on port ${port}`);
});
