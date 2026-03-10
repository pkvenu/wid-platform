// =============================================================================
// Policy Evaluator Tests
// Run: node tests/policy-engine.test.js
// =============================================================================

const { PolicyEvaluator, OPERATORS, OPERATORS_BY_TYPE, CONDITION_FIELDS, ACTION_TYPES } = require('../engine/evaluator');
const { POLICY_TEMPLATES } = require('../engine/templates');

const evaluator = new PolicyEvaluator();
let passed = 0, failed = 0;
const failures = [];
function assert(c, n) { if (c) { passed++; console.log(`  ✔ ${n}`); } else { failed++; failures.push(n); console.log(`  ✗ ${n}`); } }
function w(o = {}) { return { id:1, name:'test', type:'lambda', cloud_provider:'aws', environment:'staging', trust_level:'high', security_score:75, verified:true, is_shadow:false, owner:'dev@co.com', team:'backend', spiffe_id:'spiffe://co/test', category:'Service Account', last_seen:new Date().toISOString(), created_at:new Date(Date.now()-30*86400000).toISOString(), labels:{}, metadata:{}, ...o }; }

console.log('\n═══ OPERATORS ═══');
assert(OPERATORS.equals('hello','Hello'), 'equals ci');
assert(!OPERATORS.equals('a','b'), 'equals miss');
assert(OPERATORS.not_equals('a','b'), 'not_equals');
assert(OPERATORS.contains('hello world','world'), 'contains');
assert(OPERATORS.not_contains('hello','world'), 'not_contains');
assert(OPERATORS.starts_with('hello','hel'), 'starts_with');
assert(OPERATORS.ends_with('hello','llo'), 'ends_with');
assert(OPERATORS.in('prod','prod,staging'), 'in CSV');
assert(OPERATORS.in('a',['a','b']), 'in array');
assert(OPERATORS.not_in('dev','prod,staging'), 'not_in');
assert(OPERATORS.matches('admin-role','(admin|root)'), 'matches');
assert(!OPERATORS.matches('reader','(admin|root)'), 'matches miss');
assert(OPERATORS.gt(80,50), 'gt');
assert(OPERATORS.gte(50,50), 'gte');
assert(OPERATORS.lt(30,50), 'lt');
assert(OPERATORS.lte(50,50), 'lte');
assert(OPERATORS.between(50,[30,70]), 'between');
assert(!OPERATORS.between(80,[30,70]), 'between out');
assert(OPERATORS.between(50,'30,70'), 'between CSV');
assert(OPERATORS.is_true(true), 'is_true');
assert(OPERATORS.is_true('true'), 'is_true str');
assert(OPERATORS.is_false(false), 'is_false');
assert(OPERATORS.is_false(null), 'is_false null');
assert(OPERATORS.is_false(''), 'is_false empty');
assert(OPERATORS.exists('val'), 'exists');
assert(!OPERATORS.exists(null), 'exists null');
assert(!OPERATORS.exists(''), 'exists empty');
assert(OPERATORS.not_exists(null), 'not_exists null');
assert(OPERATORS.not_exists(''), 'not_exists empty');
const old = new Date(Date.now()-100*86400000).toISOString();
const fresh = new Date(Date.now()-5*86400000).toISOString();
assert(OPERATORS.older_than_days(old,90), 'older 100>90');
assert(!OPERATORS.older_than_days(fresh,90), 'older 5!>90');
assert(OPERATORS.newer_than_days(fresh,90), 'newer 5<90');
assert(!OPERATORS.newer_than_days(old,90), 'newer 100!<90');
assert(OPERATORS.older_than_days(null,90), 'older null→stale');

console.log('\n═══ CONDITION EVAL ═══');
const pw = w({ environment:'production', security_score:35, verified:false });
assert(evaluator.evaluateCondition({field:'environment',operator:'equals',value:'production'},pw).passed, 'env=prod');
assert(evaluator.evaluateCondition({field:'security_score',operator:'lt',value:'40'},pw).passed, 'score<40');
assert(evaluator.evaluateCondition({field:'verified',operator:'is_false'},pw).passed, 'verified=false');
assert(evaluator.evaluateCondition({field:'owner',operator:'exists'},pw).passed, 'owner exists');
assert(!evaluator.evaluateCondition({field:'environment',operator:'equals',value:'staging'},pw).passed, 'env!=staging');
assert(!evaluator.evaluateCondition({field:'name',operator:'fake_op',value:'x'},pw).passed, 'unknown op → error');

console.log('\n═══ POLICY EVAL ═══');
const pol = {id:1,name:'Test',severity:'critical',conditions:[{field:'environment',operator:'equals',value:'production'},{field:'verified',operator:'is_false'}],actions:[{type:'flag',message:'Unattested prod'}],enabled:true,enforcement_mode:'audit'};
assert(evaluator.evaluatePolicy(pol, w({environment:'production',verified:false})).violated, 'Prod unattested → violated');
assert(evaluator.evaluatePolicy(pol, w({environment:'production',verified:false})).message === 'Unattested prod', 'Message correct');
assert(!evaluator.evaluatePolicy(pol, w({environment:'production',verified:true})).violated, 'Prod attested → ok');
assert(evaluator.evaluatePolicy({...pol,scope_environment:'production'}, w({environment:'staging',verified:false})).skipped, 'Staging → skipped');

console.log('\n═══ BULK EVAL ═══');
const opol = {id:2,name:'Owner',severity:'high',conditions:[{field:'owner',operator:'not_exists'}],actions:[{type:'flag',message:'No owner'}],enabled:true,enforcement_mode:'audit'};
const ws = [w({id:1,owner:'x'}),w({id:2,owner:null}),w({id:3,owner:''}),w({id:4,owner:'y'}),w({id:5,owner:null})];
const bulk = evaluator.evaluateAgainstAll(opol,ws);
assert(bulk.total===5, 'Total 5');
assert(bulk.evaluated===5, 'Eval 5');
assert(bulk.violations===3, `3 orphans (got ${bulk.violations})`);

console.log('\n═══ SCOPE ═══');
const spol = {id:3,name:'Scope',severity:'medium',conditions:[{field:'security_score',operator:'lt',value:'50'}],actions:[],scope_environment:'production',enabled:true,enforcement_mode:'audit'};
const sws = [w({id:1,environment:'production',security_score:30}),w({id:2,environment:'staging',security_score:30}),w({id:3,environment:'production',security_score:80})];
const sr = evaluator.evaluateAgainstAll(spol,sws);
assert(sr.evaluated===2, 'Only prod evaluated');
assert(sr.violations===1, '1 prod violation');
const tpol = {...spol,scope_environment:null,scope_types:['iam-role']};
assert(evaluator.evaluateAgainstAll(tpol,[w({id:1,type:'iam-role',security_score:30}),w({id:2,type:'lambda',security_score:30})]).evaluated===1, 'Type scope');

console.log('\n═══ TEMPLATES ═══');
const tids = Object.keys(POLICY_TEMPLATES);
assert(tids.length>=9, `${tids.length} templates`);
tids.forEach(id => { const t = POLICY_TEMPLATES[id]; assert(t.name && t.conditions?.length, `tpl "${id}"`); });
const pt = {...POLICY_TEMPLATES['prod-attestation-required'],id:'t',enabled:true,enforcement_mode:'audit'};
assert(evaluator.evaluatePolicy(pt,w({environment:'production',verified:false})).violated, 'Prod tpl: violated');
assert(!evaluator.evaluatePolicy(pt,w({environment:'production',verified:true})).violated, 'Prod tpl: ok');
const st = {...POLICY_TEMPLATES['stale-credential-lifecycle'],id:'t',enabled:true,enforcement_mode:'audit'};
assert(evaluator.evaluatePolicy(st,w({last_seen:new Date(Date.now()-120*86400000).toISOString()})).violated, 'Stale tpl: violated');
assert(!evaluator.evaluatePolicy(st,w({last_seen:new Date().toISOString()})).violated, 'Stale tpl: ok');
const at = {...POLICY_TEMPLATES['admin-requires-crypto'],id:'t',enabled:true,enforcement_mode:'audit'};
assert(evaluator.evaluatePolicy(at,w({name:'admin-role',trust_level:'high'})).violated, 'Admin tpl: high → violated');
assert(!evaluator.evaluatePolicy(at,w({name:'admin-role',trust_level:'cryptographic'})).violated, 'Admin tpl: crypto → ok');
assert(!evaluator.evaluatePolicy(at,w({name:'reader',trust_level:'low'})).violated, 'Admin tpl: non-admin → ok');
const lt = {...POLICY_TEMPLATES['low-score-quarantine'],id:'t',enabled:true,enforcement_mode:'audit'};
assert(evaluator.evaluatePolicy(lt,w({security_score:30})).violated, 'Low-score: 30 → violated');
assert(!evaluator.evaluatePolicy(lt,w({security_score:80})).violated, 'Low-score: 80 → ok');

console.log('\n═══ SCHEMA ═══');
assert(CONDITION_FIELDS.length>=14, `${CONDITION_FIELDS.length} fields`);
assert(ACTION_TYPES.length>=7, `${ACTION_TYPES.length} actions`);
CONDITION_FIELDS.forEach(f => assert((OPERATORS_BY_TYPE[f.type]||[]).length>0, `${f.key} has ops`));
Object.entries(OPERATORS_BY_TYPE).forEach(([t,ops]) => ops.forEach(op => assert(typeof OPERATORS[op]==='function', `op ${op} exists`)));

console.log('\n═══ EDGE CASES ═══');
assert(evaluator.evaluatePolicy({id:0,name:'E',conditions:[],actions:[],severity:'low',enabled:true,enforcement_mode:'audit'},w()).violated, 'Empty → vacuous');
assert(evaluator.evaluateCondition({field:'owner',operator:'not_exists'},w({owner:null})).passed, 'null → not_exists');
assert(!evaluator.evaluateCondition({field:'owner',operator:'exists'},w({owner:null})).passed, 'null → !exists');
assert(evaluator.evaluateAll([{id:0,name:'Off',conditions:[{field:'verified',operator:'is_false'}],actions:[],severity:'low',enabled:false,enforcement_mode:'audit'}],w({verified:false})).length===0, 'Disabled → skip');
assert(evaluator.evaluateAll([{id:0,name:'DM',conditions:[{field:'verified',operator:'is_false'}],actions:[],severity:'low',enabled:true,enforcement_mode:'disabled'}],w({verified:false})).length===0, 'Mode disabled → skip');

console.log(`\n${'═'.repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failures.length) failures.forEach(f => console.log(`    ✗ ${f}`));
console.log(`${'═'.repeat(50)}\n`);
process.exit(failed>0?1:0);
