// =============================================================================
// Compiler Tests — Rego + Registry + Pluggability
// Run: node tests/compilers.test.js
// =============================================================================

const { getCompiler, listCompilers, registerCompiler } = require('../compilers');
const { RegoCompiler } = require('../compilers/rego');
const { PolicyCompiler } = require('../compilers/base');

let passed = 0, failed = 0;
const failures = [];
function assert(c, n) { if (c) { passed++; console.log(`  ✔ ${n}`); } else { failed++; failures.push(n); console.log(`  ✗ ${n}`); } }

const pol = { id:1, name:'Test Policy', description:'A test', severity:'high',
  conditions: [
    { field:'environment', operator:'equals', value:'production' },
    { field:'security_score', operator:'lt', value:'50' },
    { field:'verified', operator:'is_false' },
  ],
  actions: [{ type:'flag', message:'Low score unattested prod' }],
};

// ═══ REGISTRY ═══
console.log('\n═══ REGISTRY ═══');
const all = listCompilers();
assert(all.includes('rego'), 'Has rego');
assert(getCompiler('rego') instanceof RegoCompiler, 'rego → RegoCompiler');
try { getCompiler('fake'); assert(false, 'Should throw'); } catch(e) { assert(e.message.includes('Unknown'), 'Unknown throws'); }

// ═══ PLUGGABLE REGISTRATION ═══
console.log('\n═══ PLUGGABLE REGISTRATION ═══');
class MockCompiler extends PolicyCompiler {
  constructor() { super('mock'); }
  get extension() { return '.mock'; }
  compile(policy) { return `mock:${policy.name}`; }
  compileCondition(c) { return `mock:${c.field}`; }
}
registerCompiler('mock', new MockCompiler());
assert(listCompilers().includes('mock'), 'Mock registered');
assert(getCompiler('mock').compile({ name:'test' }) === 'mock:test', 'Mock compiles');
assert(getCompiler('mock').extension === '.mock', 'Mock extension');

// ═══ REGO ═══
console.log('\n═══ REGO ═══');
const rego = getCompiler('rego');
assert(rego.name === 'rego', 'Name');
assert(rego.extension === '.rego', 'Extension');
const ro = rego.compile(pol);
assert(ro.includes('package policy_1'), 'Package');
assert(ro.includes('default violation := false'), 'Default');
assert(ro.includes('input.environment == "production"'), 'Equals');
assert(ro.includes('to_number(input.security_score) < 50'), 'Lt');
assert(ro.includes('input.verified != true'), 'Is_false');
assert(ro.includes('severity := "high"'), 'Severity');
assert(ro.includes('Low score unattested prod'), 'Message');

const ops = [
  { op:'equals', f:'env', v:'prod', e:'input.env == "prod"' },
  { op:'not_equals', f:'env', v:'prod', e:'input.env != "prod"' },
  { op:'contains', f:'n', v:'admin', e:'contains(input.n, "admin")' },
  { op:'starts_with', f:'n', v:'svc', e:'startswith(input.n, "svc")' },
  { op:'ends_with', f:'n', v:'bot', e:'endswith(input.n, "bot")' },
  { op:'in', f:'t', v:'low,none', e:'input.t in {"low", "none"}' },
  { op:'not_in', f:'t', v:'low', e:'not input.t in {"low"}' },
  { op:'matches', f:'n', v:'(admin|root)', e:'regex.match("(admin|root)", input.n)' },
  { op:'gt', f:'s', v:'80', e:'to_number(input.s) > 80' },
  { op:'gte', f:'s', v:'50', e:'to_number(input.s) >= 50' },
  { op:'lt', f:'s', v:'40', e:'to_number(input.s) < 40' },
  { op:'lte', f:'s', v:'100', e:'to_number(input.s) <= 100' },
  { op:'is_true', f:'v', v:'', e:'input.v == true' },
  { op:'is_false', f:'v', v:'', e:'input.v != true' },
  { op:'exists', f:'o', v:'', e:'input.o' },
  { op:'not_exists', f:'o', v:'', e:'not input.o' },
];
ops.forEach(t => assert(rego.compileCondition({field:t.f,operator:t.op,value:t.v}).includes(t.e), `Rego ${t.op}`));

console.log(`\n${'═'.repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failures.length) failures.forEach(f => console.log(`    ✗ ${f}`));
console.log(`${'═'.repeat(50)}\n`);
process.exit(failed>0?1:0);
