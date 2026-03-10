// =============================================================================
// Policy Compiler — Abstract Interface
// =============================================================================
// Every policy runtime (OPA, Cedar, OpenFGA) implements this interface.
// The evaluator and routes never touch runtime-specific code directly.
// =============================================================================

class PolicyCompiler {
  /**
   * @param {string} name - Compiler identifier ('rego', 'cedar', 'json')
   */
  constructor(name) {
    this.name = name;
  }

  /**
   * Compile a policy into the target runtime format.
   * @param {Object} policy - { name, description, conditions[], actions[], severity, id }
   * @returns {string} - Compiled policy in target format
   */
  compile(policy) {
    throw new Error(`compile() not implemented by ${this.name}`);
  }

  /**
   * Compile a single condition into the target format (for previews).
   * @param {Object} condition - { field, operator, value }
   * @returns {string}
   */
  compileCondition(condition) {
    throw new Error(`compileCondition() not implemented by ${this.name}`);
  }

  /**
   * Return file extension for the compiled output.
   * @returns {string} - e.g. '.rego', '.cedar', '.json'
   */
  get extension() {
    throw new Error(`extension not implemented by ${this.name}`);
  }

  /**
   * Return content type for HTTP responses.
   * @returns {string}
   */
  get contentType() {
    return 'text/plain';
  }
}

module.exports = { PolicyCompiler };
