# Contributing

This document is the style guide for the project. The instructions follow ASD-STE100 Simplified Technical English.
Terms that are not in the STE dictionary (for example "lint", "commit") are technical names.

## Before you commit

1. Install the dependencies: `npm ci --ignore-scripts`
2. Do the style check: `npm run lint`
3. If the check shows layout errors, correct them automatically: `npm run lint:fix`
4. Do the tests: `npm test`

The GitLab CI job `test` does steps 2 and 4.

Node.js 22.13 or later is necessary (`engines` in `package.json`).

## Code style

ESLint enforces the rules in this section. The configuration is `eslint.config.js`.

| Topic | Rule |
|---|---|
| Modules | CommonJS: `require` and `module.exports`. |
| Indentation | 4 spaces. No tabs. One more level for each `case` in a `switch`. |
| Semicolons | Always. |
| Strings | Single quotes. Use double quotes only if the string contains a single quote. Template literals are permitted. |
| Trailing commas | Always in a list or an object that has more than one line. |
| Braces | The opening brace is on the same line (`1tbs`). `if (x) return y;` on one line is permitted. A body with more than one line must have braces. |
| Variables | `const` by default, `let` if the value changes. Not `var`. |
| Comparison | `===` and `!==` only. |
| Unused code | No unused variables and no unused `require`. Start the name of a parameter that must stay with `_`. |
| Dependencies | `require` only a package that `package.json` lists. Do not rely on a package that comes with a different package. |
| Empty lines | One at most. One newline at the end of the file. No spaces at the end of a line. |

ESLint does not enforce the spacing in `{ a }`, the parentheses of arrow functions or the line length.
Use the style of the adjacent code.

## Comments

The default is no comment. Write a comment only if the code cannot show the fact.

Write a comment for:

- a constraint that is not obvious, a unit or a permitted range
- a workaround, together with its cause
- unusual behavior of a protocol or a library, with the specification section or the file and function
- a condition that a later change must not break

Do not write a comment that:

- says again what the code does
- divides the file into sections
- tells the history of a change (the commit message has that)

Write one idea in each sentence, with 20 words at most. Do not use contractions.

## Configuration

- Read each setting from the environment in `app.js`, and give it to the routes with `app.set()`.
- Read each numeric setting with `parseIntEnv()`. It has limits, and it stops the start if the value is bad.
- A bad or missing value must stop the process with a `FATAL:` line. Do not continue with a default that is less safe.
- Add each new setting to the table in `README.md`.

## Tests

- Write the test first, and make sure that it fails for the correct cause.
- A change to behavior needs a test. A bug fix needs a test that fails without the fix.
- `test/integration/helpers/buildApp.js` builds a simpler app without helmet, rate limits and secure cookies. Use it for route logic only.
- For headers, cookies, limits and startup checks, load the real `app.js` (see `appStartup.test.js`, `signInFlow.test.js`).
- Use `example.com`, `example.org` or `.test` names for hosts that are not real.

## Commits

- Use Conventional Commits: `type(scope): subject`, for example `fix(saml): ...`.
  The types in use are `feat`, `fix`, `chore`, `docs`, `test`, `ci`, `build` and `style`.
- Write the subject in the imperative mood, in lower case, without a period.
- In the body, give the cause of the change and its effect. The diff shows the rest.
- Make one branch and one pull request for each topic.
- Do not put a layout-only change and a behavior change in the same commit.
