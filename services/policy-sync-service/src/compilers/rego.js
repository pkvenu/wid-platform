// =============================================================================
// Rego Compiler — OPA Policy Compilation
// =============================================================================

const { PolicyCompiler } = require('./base');

class RegoCompiler extends PolicyCompiler {
  constructor() {
    super('rego');
  }

  get extension() { return '.rego'; }
  get contentType() { return 'text/plain'; }

  compile(policy) {
    const pkg = policy.opa_package || `policy_${(policy.id || 'custom')}`;
    const conditions = Array.isArray(policy.conditions) ? policy.conditions : [];

    let rego = `package ${pkg}\n\ndefault violation := false\n\n`;
    rego += `# Policy: ${policy.name}\n`;
    if (policy.description) rego += `# ${policy.description}\n`;
    rego += `\n`;

    rego += `violation if {\n`;
    for (const cond of conditions) {
      rego += `    ${this.compileCondition(cond)}\n`;
    }
    rego += `}\n\n`;

    const msg = policy.actions?.[0]?.message || `Violation of policy: ${policy.name}`;
    rego += `message := "${msg}" if {\n    violation\n}\n\n`;
    rego += `severity := "${policy.severity || 'medium'}"\n`;

    return rego;
  }

  compileCondition(cond) {
    const { field, operator, value } = cond;
    const f = `input.${field}`;

    switch (operator) {
      case 'equals':       return `${f} == "${value}"`;
      case 'not_equals':   return `${f} != "${value}"`;
      case 'contains':     return `contains(${f}, "${value}")`;
      case 'not_contains': return `not contains(${f}, "${value}")`;
      case 'starts_with':  return `startswith(${f}, "${value}")`;
      case 'ends_with':    return `endswith(${f}, "${value}")`;
      case 'in':           return `${f} in {${value.split(',').map(v => `"${v.trim()}"`).join(', ')}}`;
      case 'not_in':       return `not ${f} in {${value.split(',').map(v => `"${v.trim()}"`).join(', ')}}`;
      case 'matches':      return `regex.match("${value}", ${f})`;
      case 'gt':           return `to_number(${f}) > ${value}`;
      case 'gte':          return `to_number(${f}) >= ${value}`;
      case 'lt':           return `to_number(${f}) < ${value}`;
      case 'lte':          return `to_number(${f}) <= ${value}`;
      case 'is_true':      return `${f} == true`;
      case 'is_false':     return `${f} != true`;
      case 'exists':       return `${f}`;
      case 'not_exists':   return `not ${f}`;
      case 'between': {
        const [lo, hi] = value.split(',').map(v => v.trim());
        return `to_number(${f}) >= ${lo}\n    to_number(${f}) <= ${hi}`;
      }
      case 'older_than_days':
        return `# ${field} older than ${value} days\n    time.now_ns() - time.parse_rfc3339_ns(${f}) > ${Number(value) * 86400} * 1000000000`;
      case 'newer_than_days':
        return `# ${field} newer than ${value} days\n    time.now_ns() - time.parse_rfc3339_ns(${f}) < ${Number(value) * 86400} * 1000000000`;
      default:
        return `# Unknown operator: ${operator}`;
    }
  }
}

module.exports = { RegoCompiler };
