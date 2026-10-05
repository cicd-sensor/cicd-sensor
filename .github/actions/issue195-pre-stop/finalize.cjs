const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
if (!['post', 'pre-post'].includes(process.env.ISSUE195_MODE)) {
  console.log('issue195 finalizer not enabled for this comparison mode');
} else if (!fs.existsSync('/run/issue195/context.env')) {
  console.log('issue195 initialization did not finish; no agent ownership established');
} else {
  const r = spawnSync('sudo', ['/usr/bin/bash', '/usr/local/bin/issue195-finalize', 'action-post'], { stdio: 'inherit' });
  process.exitCode = r.status ?? 1;
}
