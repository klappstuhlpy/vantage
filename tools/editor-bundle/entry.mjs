// The single facade that selects which CM6 symbols the editor wrapper needs.
// Only what is re-exported here ends up in the bundle.

export {
  EditorView,
  keymap,
  placeholder,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
  drawSelection,
  rectangularSelection,
  highlightSpecialChars,
} from '@codemirror/view';

export { EditorState, Compartment } from '@codemirror/state';

export {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
} from '@codemirror/commands';

export { sql, PostgreSQL, SQLite } from '@codemirror/lang-sql';

export {
  syntaxHighlighting,
  HighlightStyle,
  bracketMatching,
  foldGutter,
  indentOnInput,
  syntaxTree,
} from '@codemirror/language';

export { tags } from '@lezer/highlight';

export {
  autocompletion,
  closeBrackets,
  closeBracketsKeymap,
  completionKeymap,
  acceptCompletion,
} from '@codemirror/autocomplete';

export { searchKeymap, highlightSelectionMatches } from '@codemirror/search';

export { linter, lintGutter } from '@codemirror/lint';
