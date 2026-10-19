// @ts-check
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

const reactWorkspaces = [
  "apps/login/**",
  "apps/admin/**",
  "packages/design-system/**",
  "examples/demo-service/web/**",
];

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/coverage/**",
      "e2e/test-results/**",
      "e2e/playwright-report/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/*.js"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { globals: globals.node },
  },
  {
    files: reactWorkspaces.map((glob) => `${glob}/*.{ts,tsx}`),
    ...reactHooks.configs.flat.recommended,
    languageOptions: { globals: globals.browser },
  },
  {
    // Delivered design system: `AddedContracts {}` is an intentional, empty extension point.
    files: ["packages/design-system/src/**/contracts.ts"],
    rules: { "@typescript-eslint/no-empty-object-type": "off" },
  },
);
