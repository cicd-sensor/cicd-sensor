require('node:fs').appendFileSync(process.env.GITHUB_STATE, 'registered=true\n');
console.log('issue195 other action pre registered its tail post');
