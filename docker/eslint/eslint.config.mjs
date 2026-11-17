// LabSecurity's own ESLint flat config. It is the ONLY config used: `bin/scan` runs ESLint with `--config` on a disposable
// copy of the project and `--no-inline-config`, so neither the project's eslint config nor its `eslint-disable` comments apply.
//
// Rule routing (see labsec/reports.py and docs/RULES.md):
//   * security rules (`security/*`, `no-unsanitized/*`) -> DefectDojo (ESLint Scan parser) and SonarQube external issues;
//   * every other rule (ESLint recommended, typescript-eslint strict, @angular-eslint) is quality -> SonarQube only.
// Type-aware typescript-eslint rules are NOT enabled: they need the project's tsconfig and a full type check of the repository.
import { defineConfig } from 'eslint/config';
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import angular from 'angular-eslint';
import security from 'eslint-plugin-security';
import noUnsanitized from 'eslint-plugin-no-unsanitized';

const SCRIPT_FILES = ['**/*.{js,mjs,cjs,jsx}'];
const TS_FILES = ['**/*.{ts,tsx,mts,cts}'];

export default defineConfig([
  {
    ignores: ['**/node_modules/**', '**/dist/**', '**/.angular/**', '**/coverage/**', '**/bin/**', '**/obj/**', '**/*.min.js', '**/*.d.ts'],
  },
  {
    linterOptions: { reportUnusedDisableDirectives: 'off' },
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },

  // --- Quality: ESLint recommended + typescript-eslint strict (non type-aware) -> SonarQube only
  { files: SCRIPT_FILES, extends: [js.configs.recommended] },
  { files: TS_FILES, extends: [js.configs.recommended, tseslint.configs.strict] },

  // --- Quality: Angular (TypeScript and templates, including inline templates) -> SonarQube only
  {
    files: TS_FILES,
    extends: [angular.configs.tsRecommended],
    processor: angular.processInlineTemplates,
  },
  {
    files: ['**/*.html'],
    extends: [angular.configs.templateRecommended, angular.configs.templateAccessibility],
  },

  // --- Security -> DefectDojo
  {
    files: [...SCRIPT_FILES, ...TS_FILES],
    extends: [security.configs.recommended, noUnsanitized.configs.recommended],
    rules: {
      // Flags every `obj[key]` access: thousands of false positives on ordinary code and no way to tell the real ones.
      'security/detect-object-injection': 'off',
    },
  },
]);
