#!/usr/bin/env node
import { main } from './cli.js';

// Set process.exitCode rather than calling process.exit(): calling exit() while
// a large report is still draining to stdout can truncate the output. Letting
// the event loop empty on its own flushes it first.
main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`fatal: ${err.message}\n`);
    process.exitCode = 2;
  });
