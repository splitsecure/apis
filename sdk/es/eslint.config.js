// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**"] },
  js.configs.recommended,
  // Type-aware, because the rules worth having here need types: an unawaited
  // lookup on the callback path is the class of bug this catches.
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  // The config file itself is outside the tsconfig project.
  { files: ["eslint.config.js"], ...tseslint.configs.disableTypeChecked },
  {
    // Tests reach into malformed and hand-built wire shapes on purpose, and
    // node:test's test() returns a promise nobody is meant to await.
    files: ["test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-floating-promises": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-call": "off",
    },
  },
);
