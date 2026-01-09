import js from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";
import unusedImports from "eslint-plugin-unused-imports";

export default [
  js.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parser: tsparser,
      parserOptions: {
        project: "./tsconfig.json"
      },
      globals: {
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        performance: "readonly",
        atob: "readonly",
        btoa: "readonly",
        NodeJS: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
      "unused-imports": unusedImports
    },
    rules: {
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "unused-imports/no-unused-imports": "warn",
      "unused-imports/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-console": "off",
      "no-useless-escape": "warn",
      "no-control-regex": "off",
      "no-misleading-character-class": "off",
    },
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        performance: "readonly",
        atob: "readonly",
        btoa: "readonly",
      },
    },
    plugins: {
      "unused-imports": unusedImports
    },
    rules: {
      "no-unused-vars": "off",
      "unused-imports/no-unused-imports": "warn",
      "unused-imports/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-console": "off",
      "no-useless-escape": "warn",
      "no-control-regex": "off",
      "no-misleading-character-class": "off",
    },
  },
  {
    ignores: ["node_modules/", "coverage/", "logs/", "test/", "dist/", "*.d.ts"],
  },
];
