const js = require('@eslint/js');
const globals = require('globals');
const stylistic = require('@stylistic/eslint-plugin');
const n = require('eslint-plugin-n');

module.exports = [
    { ignores: ['node_modules/', 'coverage/', 'dist/', 'docs/', 'e2e/'] },

    js.configs.recommended,
    n.configs['flat/recommended-script'],

    {
        files: ['**/*.js', 'bin/www'],
        languageOptions: {
            ecmaVersion: 2023,
            sourceType: 'commonjs',
            globals: globals.node,
        },
        plugins: { '@stylistic': stylistic },
        rules: {
            // correctness
            'eqeqeq': 'error',
            'no-var': 'error',
            'prefer-const': 'error',
            'curly': ['error', 'multi-line'],
            'radix': 'error',
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-new-func': 'error',
            'no-throw-literal': 'error',
            'no-unused-vars': ['error', {
                args: 'after-used',
                // Express finds an error handler by its four parameters, so `next` stays in the list.
                argsIgnorePattern: '^_|^next$',
                caughtErrors: 'none',
            }],

            // A bad setting must stop the process at startup (app.js, bin/www).
            'n/no-process-exit': 'off',

            // layout
            '@stylistic/indent': ['error', 4, { SwitchCase: 1 }],
            '@stylistic/semi': ['error', 'always'],
            '@stylistic/quotes': ['error', 'single', { avoidEscape: true, allowTemplateLiterals: 'always' }],
            '@stylistic/comma-dangle': ['error', 'always-multiline'],
            '@stylistic/brace-style': ['error', '1tbs', { allowSingleLine: true }],
            '@stylistic/keyword-spacing': 'error',
            '@stylistic/space-before-blocks': 'error',
            '@stylistic/space-infix-ops': 'error',
            '@stylistic/comma-spacing': 'error',
            '@stylistic/no-trailing-spaces': 'error',
            '@stylistic/eol-last': 'error',
            '@stylistic/no-multiple-empty-lines': ['error', { max: 1, maxBOF: 0, maxEOF: 0 }],
        },
    },

    {
        // Started as `node ./bin/www`, and the file is executable. It is not a package.json "bin" entry.
        files: ['bin/www'],
        rules: { 'n/hashbang': 'off' },
    },

    {
        files: ['test/**/*.js'],
        languageOptions: {
            globals: { ...globals.node, ...globals.jest },
        },
        rules: {
            // jest and supertest are devDependencies
            'n/no-unpublished-require': 'off',
        },
    },
];
