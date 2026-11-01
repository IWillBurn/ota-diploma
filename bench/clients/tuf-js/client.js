#!/usr/bin/env node
// tuf-js client-under-test adapter for otabench.
// Implements the tuf-conformance CLI protocol (see third_party/tuf-conformance/CLIENT-CLI.md):
//   client --metadata-dir D init ROOT
//   client --metadata-dir D --metadata-url U refresh
//   client --metadata-dir D --metadata-url U --target-name N... --target-base-url T --target-dir TD download
// Exit code 0 = success, 1 = any failure.
'use strict';

const fs = require('fs');
const path = require('path');
const { Updater } = require('tuf-js');

function parseArgs(argv) {
  const opts = { targetNames: [], positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--metadata-dir': opts.metadataDir = argv[++i]; break;
      case '--metadata-url': opts.metadataUrl = argv[++i]; break;
      case '--target-name': opts.targetNames.push(argv[++i]); break;
      case '--target-base-url': opts.targetBaseUrl = argv[++i]; break;
      case '--target-dir': opts.targetDir = argv[++i]; break;
      case '-v': case '--verbose': break;
      default:
        if (!opts.command) opts.command = a; else opts.positional.push(a);
    }
  }
  return opts;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.command === 'init') {
    fs.copyFileSync(o.positional[0], path.join(o.metadataDir, 'root.json'));
    return;
  }
  const updater = new Updater({
    metadataDir: o.metadataDir,
    metadataBaseUrl: o.metadataUrl.replace(/\/$/, ''),
    targetDir: o.targetDir,
    targetBaseUrl: o.targetBaseUrl ? o.targetBaseUrl.replace(/\/$/, '') : undefined,
  });
  if (o.command === 'refresh') {
    await updater.refresh();
    return;
  }
  if (o.command === 'download') {
    await updater.refresh();
    for (const name of o.targetNames) {
      const info = await updater.getTargetInfo(name);
      if (!info) throw new Error(`${name} not found in repository`);
      const cached = await updater.findCachedTarget(info);
      if (!cached) await updater.downloadTarget(info);
    }
    return;
  }
  throw new Error(`unknown command ${o.command}`);
}

// Set exitCode instead of calling process.exit(): on Windows, exiting while
// undici sockets are still closing trips a libuv assertion. But a response the
// library stopped reading (e.g. after "Max length reached") can keep a keep-alive
// socket and thus the event loop alive: exit anyway once the work is done and the
// sockets had 2 s to close. The verdict (exit code) is the library's, not ours.
const finish = (code) => {
  process.exitCode = code;
  setTimeout(() => process.exit(code), 2000).unref();
};
main().then(
  () => finish(0),
  (err) => { console.error(`tuf-js client: ${err && err.message ? err.message : err}`); finish(1); },
);
