// Bundles and minifies the CLI into one file so the published package carries no readable source tree.
import { build } from 'esbuild';
import { chmodSync, rmSync, statSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
await build({
  entryPoints: ['src/cli.ts'],
  outfile: 'dist/cli.js',
  bundle: true,
  minify: true,
  legalComments: 'none',
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: false,
  // CommonJS dependencies inside the bundle call require() for node builtins.
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  logLevel: 'warning',
});
chmodSync('dist/cli.js', 0o755);
console.log(`dist/cli.js ${(statSync('dist/cli.js').size / 1024).toFixed(0)} KiB`);
