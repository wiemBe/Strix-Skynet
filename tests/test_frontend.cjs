/* Async rendering regressions, using the actual browser code with controlled response ordering. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../skynet/static/app.js'), 'utf8');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise, resolve}; };

async function testStalePageResponse() {
  const reply = deferred();
  const context = vm.createContext({location: {hash: '#/targets/1'}, fetch: () => reply.promise});
  const code = source.slice(source.indexOf('class NavigationChanged'), source.indexOf('\nfunction toast('));
  vm.runInContext(code + '\nthis.api = api; this.NavigationChanged = NavigationChanged;', context);
  const pending = context.api('/api/targets/1');
  context.location.hash = '#/campaigns/1';
  reply.resolve({status: 200, ok: true, json: async () => ({name: 'old target'})});
  await assert.rejects(pending, context.NavigationChanged);
}

async function testTabResponseOrdering() {
  const findings = deferred(), coverage = deferred();
  const rendered = [];
  const context = vm.createContext({guard: f => f, id: 1, scan: {}, location: {hash: '#/scans/1'}, log: {},
    live: {generation: 0}, body: {replaceChildren: node => rendered.push(node)},
    findingsView: () => findings.promise, skyCoverageTab: () => coverage.promise});
  const start = source.indexOf('  const renderBody = guard(async () => {');
  const end = source.indexOf('\n  async function findingsView()', start);
  assert(start > 0 && end > start);
  vm.runInContext('let tab = "findings"; let bodyGeneration = 0;\n' + source.slice(start, end) +
    '\nthis.render = renderBody; this.setTab = value => { tab = value; };', context);
  const oldRequest = context.render();
  context.setTab('coverage');
  const newRequest = context.render();
  coverage.resolve('coverage');
  await newRequest;
  findings.resolve('stale findings');
  await oldRequest;
  assert.deepEqual(rendered, ['coverage']);
}

(async () => {
  await testStalePageResponse();
  await testTabResponseOrdering();
  console.log('2 frontend async regression tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
