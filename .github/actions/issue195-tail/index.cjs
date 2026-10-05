const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
if (process.env.STATE_registered !== 'true') {
  fs.appendFileSync(process.env.GITHUB_STATE, 'registered=true\n');
} else {
  if (process.env.ISSUE195_MODE === 'checkpoint') {
    const report = JSON.parse(fs.readFileSync(`${process.env.RUNNER_TEMP}/cicd-sensor-output/cicd-sensor-result-log.json`, 'utf8'));
    // Observe a nonterminal snapshot in the durable job log; do not mislabel it
    // as a final Summary or inject a new schema into the Manager output sink.
    console.log(JSON.stringify({kind: 'issue195_checkpoint', terminal: false,
      events_total: report.events_total, events_dropped: report.events_dropped,
      finalize_reason: report.finalize_reason, end_time: report.end_time}));
  }
  const marker = `issue195-tail-${process.env.GITHUB_RUN_ID}-${process.env.ISSUE195_MODE}-${process.env.PROBE_REP}-${process.env.ISSUE195_TAIL_KIND || 'main'}`;
  const result = spawnSync('/usr/bin/touch', [`/tmp/${marker}`], { stdio: 'inherit' });
  console.log(marker);
  if (result.status !== 0) process.exitCode = 1;
  if (process.env.ISSUE195_SCENARIO === 'manager-503') {
    const fault = spawnSync('sudo', ['touch', '/run/issue195/manager-503'], { stdio: 'inherit' });
    if (fault.status !== 0) process.exitCode = 1;
  }
  if (process.env.ISSUE195_SCENARIO === 'slow-manager') {
    const fault = spawnSync('sudo', ['touch', '/run/issue195/manager-slow'], { stdio: 'inherit' });
    if (fault.status !== 0) process.exitCode = 1;
  }
  const probe = spawnSync('/usr/local/bin/issue195-shutdown-probe', [`tail_post_${process.env.ISSUE195_TAIL_KIND || 'main'}`], {
    env: { ...process.env, PROBE_TRACKING_ID: process.env.RUNNER_TRACKING_ID }, stdio: 'inherit',
  });
  if (probe.status !== 0) process.exitCode = 1;
  if (process.env.ISSUE195_SCENARIO === 'post-failure') process.exitCode = 17;
}
