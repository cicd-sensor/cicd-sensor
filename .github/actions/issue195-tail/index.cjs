const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
if (process.env.STATE_registered !== 'true') {
  fs.appendFileSync(process.env.GITHUB_STATE, 'registered=true\n');
} else {
  const marker = `issue195-tail-${process.env.GITHUB_RUN_ID}-${process.env.ISSUE195_MODE}-${process.env.PROBE_REP}`;
  const result = spawnSync('/usr/bin/touch', [`/tmp/${marker}`], { stdio: 'inherit' });
  console.log(marker);
  if (result.status !== 0) process.exitCode = 1;
  if (process.env.ISSUE195_SCENARIO === 'manager-503') {
    const fault = spawnSync('sudo', ['touch', '/run/issue195/manager-503'], { stdio: 'inherit' });
    if (fault.status !== 0) process.exitCode = 1;
  }
  const probe = spawnSync('/usr/local/bin/issue195-shutdown-probe', ['tail_post'], {
    env: { ...process.env, PROBE_TRACKING_ID: process.env.RUNNER_TRACKING_ID }, stdio: 'inherit',
  });
  if (probe.status !== 0) process.exitCode = 1;
  if (process.env.ISSUE195_SCENARIO === 'post-failure') process.exitCode = 17;
}
