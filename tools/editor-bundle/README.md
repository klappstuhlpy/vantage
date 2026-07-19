# Editor bundle

Pre-builds the CodeMirror 6 bundle for the database console's SQL editor.

## Regenerating

```bash
cd tools/editor-bundle
npm ci
npm run build
```

This produces `static/vendor/codemirror.bundle.js` (ESM). Commit the output —
it is the vendored artifact the app loads at runtime.

## Updating

1. Bump versions in `package.json`
2. `npm ci && npm run build`
3. Test the database page (syntax highlighting, autocomplete, keybindings)
4. Commit both `package-lock.json` and the rebuilt bundle
