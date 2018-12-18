import commonjs from 'rollup-plugin-commonjs';
import node from 'rollup-plugin-node-resolve';
import { uglify } from 'rollup-plugin-uglify';
import replace from 'rollup-plugin-replace';
import { plugin as analyze } from 'rollup-plugin-analyzer'

function onwarn(message) {
  const suppressed = ['UNRESOLVED_IMPORT', 'THIS_IS_UNDEFINED'];

  if (!suppressed.find(code => message.code === code)) {
    return console.warn(message.message);
  }
}

export default [
  // for browser
  {
    input: 'lib/browser.js',
    output: {
      file: 'lib/aws-signatures.browser.umd.js',
      format: 'umd',
      name: 'aws-signatures',
      sourcemap: true,
      exports: 'named',
    },
    onwarn,
  },
  // for server
  {
    input: 'lib/index.js',
    output: {
      file: 'lib/aws-signatures.umd.js',
      format: 'umd',
      name: 'aws-signatures',
      sourcemap: false,
      exports: 'named',
    },
    onwarn,
  },
  // for filesize
  {
    input: 'lib/aws-signatures.browser.umd.js',
    output: {
      file: 'dist/bundlesize.js',
      format: 'cjs',
      exports: 'named',
    },
    plugins: [
      node(),
      commonjs({
        ignore: [
          'react',
          'react-dom/server',
          'aws-amplify'
        ],
      }),
      replace({
        'process.env.NODE_ENV': JSON.stringify('production'),
      }),
      uglify(),
      analyze(),
    ],
    onwarn,
  },
];