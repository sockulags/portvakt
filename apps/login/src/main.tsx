import "@portvakt/design-system/tokens.css";
import "@portvakt/fonts/fonts.css";
import "./login.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { readBootstrap } from "./api";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <App bootstrap={readBootstrap(document)} />
  </StrictMode>,
);
