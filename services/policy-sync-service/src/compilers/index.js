// =============================================================================
// Compiler Registry — Pluggable Policy Compilation
// =============================================================================
// Usage:
//   const compiler = getCompiler('rego');
//   const output = compiler.compile(policy);
//
// To add a new compiler (e.g. Cedar, OpenFGA):
//   1. Create compilers/yourformat.js extending PolicyCompiler from base.js
//   2. Register it in COMPILERS below
//   3. Set POLICY_COMPILER=yourformat in env
// =============================================================================

const { RegoCompiler } = require('./rego');

const COMPILERS = {
  rego: new RegoCompiler(),
};

function getCompiler(name = 'rego') {
  const compiler = COMPILERS[name];
  if (!compiler) throw new Error(`Unknown compiler: "${name}". Available: ${Object.keys(COMPILERS).join(', ')}`);
  return compiler;
}

function listCompilers() {
  return Object.keys(COMPILERS);
}

function registerCompiler(name, instance) {
  COMPILERS[name] = instance;
}

module.exports = { getCompiler, listCompilers, registerCompiler };