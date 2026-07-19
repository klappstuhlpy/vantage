/* CodeMirror 6 wrapper for the database console (DB Studio P3).
 *
 * Mounts an editor in place of the old textarea, with SQL syntax highlighting,
 * schema-fed autocomplete, and the Ctrl+Enter run binding. The dialect and
 * schema switch dynamically (via Compartments) when the source changes —
 * without recreating the editor instance, so undo history survives.
 */

import {
  EditorView,
  keymap,
  placeholder,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  drawSelection,
  highlightSpecialChars,
} from '/static/vendor/codemirror.bundle.js';

import {
  EditorState,
  Compartment,
} from '/static/vendor/codemirror.bundle.js';

import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
} from '/static/vendor/codemirror.bundle.js';

import {
  sql,
  PostgreSQL,
  SQLite,
} from '/static/vendor/codemirror.bundle.js';

import {
  syntaxHighlighting,
  HighlightStyle,
  bracketMatching,
  foldGutter,
  indentOnInput,
  syntaxTree,
} from '/static/vendor/codemirror.bundle.js';

import { tags } from '/static/vendor/codemirror.bundle.js';

import {
  autocompletion,
  closeBrackets,
  closeBracketsKeymap,
  completionKeymap,
} from '/static/vendor/codemirror.bundle.js';

import {
  searchKeymap,
  highlightSelectionMatches,
} from '/static/vendor/codemirror.bundle.js';

import {
  linter,
  lintGutter,
} from '/static/vendor/codemirror.bundle.js';

/* =======================================================================
   Theme
   ======================================================================= */

const vantageHighlight = HighlightStyle.define([
  { tag: tags.keyword, color: 'var(--syn-keyword)', fontWeight: '600' },
  { tag: tags.string, color: 'var(--syn-string)' },
  { tag: tags.number, color: 'var(--syn-number)' },
  { tag: tags.comment, color: 'var(--syn-comment)', fontStyle: 'italic' },
  { tag: tags.operator, color: 'var(--syn-operator)' },
  { tag: tags.typeName, color: 'var(--syn-type)' },
  { tag: tags.function(tags.variableName), color: 'var(--syn-func)' },
  { tag: tags.bool, color: 'var(--syn-bool)' },
  { tag: tags.null, color: 'var(--syn-comment)', fontStyle: 'italic' },
  { tag: tags.punctuation, color: 'var(--ink-2)' },
  { tag: tags.variableName, color: 'var(--ink-1)' },
  { tag: tags.standard(tags.name), color: 'var(--syn-func)' },
]);

const vantageTheme = EditorView.theme({
  '&': {
    fontSize: 'var(--fs-sm)',
    fontFamily: 'var(--font-mono)',
    backgroundColor: 'var(--bg-0)',
  },
  '.cm-content': {
    caretColor: 'var(--ink-1)',
    padding: 'var(--sp-2) 0',
  },
  '.cm-cursor, .cm-dropCursor': {
    borderLeftColor: 'var(--ink-1)',
  },
  '.cm-selectionBackground, ::selection': {
    backgroundColor: 'color-mix(in srgb, var(--acc) 18%, transparent)',
  },
  '&.cm-focused .cm-selectionBackground': {
    backgroundColor: 'color-mix(in srgb, var(--acc) 22%, transparent)',
  },
  '.cm-activeLine': {
    backgroundColor: 'var(--bg-hover)',
  },
  '.cm-gutters': {
    backgroundColor: 'var(--bg-1)',
    color: 'var(--ink-3)',
    border: 'none',
    borderRight: '1px solid var(--line-1)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'var(--bg-hover)',
  },
  '.cm-foldPlaceholder': {
    backgroundColor: 'var(--bg-2)',
    border: '1px solid var(--line-1)',
    color: 'var(--ink-3)',
  },
  '.cm-tooltip': {
    backgroundColor: 'var(--bg-2)',
    border: '1px solid var(--line-1)',
    boxShadow: 'var(--shadow-2, 0 4px 12px rgb(0 0 0 / 0.2))',
  },
  '.cm-tooltip-autocomplete ul li[aria-selected]': {
    backgroundColor: 'var(--bg-hover)',
    color: 'var(--ink-1)',
  },
});

/* =======================================================================
   SQL Linter — walks the parse tree for Error nodes
   ======================================================================= */

const sqlLinter = linter((view) => {
  const diagnostics = [];
  const tree = syntaxTree(view.state);

  tree.cursor().iterate((node) => {
    if (node.type.isError) {
      diagnostics.push({
        from: node.from,
        to: Math.max(node.to, node.from + 1),
        severity: 'error',
        message: 'Syntax error',
      });
    }
  });

  return diagnostics;
}, { delay: 300 });

/* =======================================================================
   Editor factory
   ======================================================================= */

/**
 * @param {HTMLElement} container
 * @param {{ onRun: (opts: {sql: string}) => void }} opts
 */
export function createEditor(container, { onRun }) {
  const langConf = new Compartment();

  const runKeymap = keymap.of([
    {
      key: 'Ctrl-Enter',
      mac: 'Cmd-Enter',
      run(view) {
        const sel = view.state.sliceDoc(
          view.state.selection.main.from,
          view.state.selection.main.to
        );
        onRun({ sql: sel || view.state.doc.toString() });
        return true;
      },
    },
    {
      key: 'Ctrl-Shift-Enter',
      mac: 'Cmd-Shift-Enter',
      run(view) {
        onRun({ sql: view.state.doc.toString() });
        return true;
      },
    },
  ]);

  const state = EditorState.create({
    doc: '',
    extensions: [
      lineNumbers(),
      highlightActiveLineGutter(),
      highlightSpecialChars(),
      history(),
      foldGutter(),
      drawSelection(),
      indentOnInput(),
      bracketMatching(),
      closeBrackets(),
      autocompletion(),
      highlightActiveLine(),
      highlightSelectionMatches(),
      vantageTheme,
      syntaxHighlighting(vantageHighlight),
      langConf.of(sql({ dialect: SQLite })),
      keymap.of([
        ...closeBracketsKeymap,
        ...defaultKeymap,
        ...searchKeymap,
        ...historyKeymap,
        ...completionKeymap,
        indentWithTab,
      ]),
      runKeymap,
      sqlLinter,
      lintGutter(),
      placeholder('Write SQL here…'),
      EditorView.lineWrapping,
    ],
  });

  const view = new EditorView({ state, parent: container });

  return {
    getText() {
      return view.state.doc.toString();
    },

    setText(text) {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: text },
      });
    },

    getSelection() {
      const { from, to } = view.state.selection.main;
      if (from === to) return null;
      return view.state.sliceDoc(from, to);
    },

    focus() {
      view.focus();
    },

    setDialect(kind, schema) {
      const dialect = kind === 'postgres' ? PostgreSQL : SQLite;
      const opts = { dialect };
      if (schema) opts.schema = schema;
      view.dispatch({ effects: langConf.reconfigure(sql(opts)) });
    },

    destroy() {
      view.destroy();
    },
  };
}
