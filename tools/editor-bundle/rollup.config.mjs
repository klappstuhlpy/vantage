import resolve from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';

export default {
  input: 'entry.mjs',
  output: {
    file: '../../static/vendor/codemirror.bundle.js',
    format: 'es',
    sourcemap: false,
  },
  plugins: [resolve(), terser()],
};
