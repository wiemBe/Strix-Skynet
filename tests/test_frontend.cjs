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

function catalogueHarness() {
  const context = vm.createContext({});
  const start = source.indexOf('function modelCatalogue(');
  const end = source.indexOf('\nfunction llmDialog(', start);
  assert(start > 0 && end > start);
  vm.runInContext(source.slice(start, end) + '\nthis.create = modelCatalogue; this.modelID = llmModelID;', context);
  return context;
}

async function testCatalogueIgnoresOldProviderResponsesAndErrors() {
  const {create} = catalogueHarness();
  const first = deferred(), second = deferred(), states = [];
  const c = create(p => p.provider === 'old' ? first.promise : second.promise, s => states.push(s), () => {}, () => 'saved');
  const old = c.load({provider: 'old'});
  c.invalidate('provider changed');
  const current = c.load({provider: 'new'});
  second.resolve({ok: true, models: ['new-model'], message: 'new catalogue'});
  await current;
  first.resolve({ok: true, models: ['old-model'], message: 'stale catalogue'});
  await old;
  assert.deepEqual(Array.from(states.at(-1).models), ['new-model']);
  const failure = deferred();
  const errors = create(() => failure.promise, s => states.push(s), () => {}, () => 'saved');
  const pending = errors.load({});
  errors.invalidate('address changed');
  failure.resolve(Promise.reject(new Error('stale failure')));
  await pending;
  assert.equal(states.at(-1).message, 'address changed');
}

async function testCatalogueOnlyChoosesAnUnambiguousEmptyModel() {
  const {create} = catalogueHarness();
  const chosen = [], states = [];
  let current = '';
  const c = create(async () => ({ok: true, models: ['single', 'single', null, 12], message: 'ready'}),
    s => states.push(s), m => { chosen.push(m); current = m; }, () => current);
  await c.load({});
  assert.deepEqual(chosen, ['single']);
  assert.deepEqual(Array.from(states.at(-1).models), ['single']);
  current = 'custom-unlisted';
  await c.load({});
  assert.equal(current, 'custom-unlisted');
  const multiple = create(async () => ({ok: true, models: ['b', 'a']}), () => {}, m => chosen.push(m), () => '');
  await multiple.load({});
  assert.deepEqual(chosen, ['single']);
}

async function testClosedCatalogueDoesNotRenderOrChoose() {
  const {create} = catalogueHarness();
  const response = deferred(), states = [], chosen = [];
  let calls = 0;
  const c = create(() => {calls++; return response.promise;}, s => states.push(s), m => chosen.push(m), () => '');
  const pending = c.load({});
  c.dispose();
  response.resolve({ok: true, models: ['single']});
  await pending;
  await c.load({});
  assert.equal(calls, 1);
  assert.equal(states.length, 1);
  assert.deepEqual(chosen, []);
}

async function testCatalogueFailureAndModelEditedDuringLookup() {
  const {create} = catalogueHarness();
  const response = deferred(), states = [], chosen = [];
  let current = '';
  const c = create(() => response.promise, s => states.push(s), m => chosen.push(m), () => current);
  const pending = c.load({});
  current = 'manually-entered';
  response.resolve({ok: true, models: ['single']});
  await pending;
  assert.deepEqual(chosen, []);
  const failed = create(async () => {throw new Error('connection lost');}, s => states.push(s), () => {}, () => '');
  await failed.load({});
  assert.equal(states.at(-1).failed, true);
  assert.equal(states.at(-1).loading, false);
  assert.equal(states.at(-1).message, 'connection lost');
}

function testProviderSpecificModelPrefixes() {
  const {modelID} = catalogueHarness();
  assert.equal(modelID('openrouter', 'openai/gpt-5'), 'openai/gpt-5');
  assert.equal(modelID('openrouter', 'openrouter/openai/gpt-5'), 'openai/gpt-5');
  assert.equal(modelID('litellm', 'openai/gateway-model'), 'gateway-model');
  assert.equal(modelID('opencode_go', 'opencode-go/go-model'), 'go-model');
}

(async () => {
  await testStalePageResponse();
  await testTabResponseOrdering();
  await testCatalogueIgnoresOldProviderResponsesAndErrors();
  await testCatalogueOnlyChoosesAnUnambiguousEmptyModel();
  await testClosedCatalogueDoesNotRenderOrChoose();
  await testCatalogueFailureAndModelEditedDuringLookup();
  testProviderSpecificModelPrefixes();
  console.log('7 frontend regression tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
