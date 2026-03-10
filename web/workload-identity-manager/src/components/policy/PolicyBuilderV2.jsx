import React, { useState, useEffect } from 'react';
import {
  ArrowRight, ArrowLeft, Save, TestTube, Plus, Trash2,
  Check, X, AlertCircle, Shield, Loader,
} from 'lucide-react';
import toast from 'react-hot-toast';

const PolicyBuilderV2 = () => {
  const [step, setStep] = useState(1);
  const [policy, setPolicy] = useState({
    name: '',
    description: '',
    allowRules: [{
      id: '1',
      conditions: [
        { id: 'c1', field: 'subject', operator: 'equals', value: '' },
        { id: 'c2', field: 'audience', operator: 'equals', value: '' }
      ]
    }],
    denyRules: []
  });

  const [testInput, setTestInput] = useState({ subject: '', audience: '' });
  const [testResult, setTestResult] = useState(null);
  const [showRegoPreview, setShowRegoPreview] = useState(false);
  const [workloadOptions, setWorkloadOptions] = useState([]);
  const [targetOptions, setTargetOptions] = useState([]);
  const [loading, setLoading] = useState(true);

  const fieldOptions = [
    { value: 'subject', label: 'Subject (Who)', type: 'string' },
    { value: 'audience', label: 'Audience (What)', type: 'string' },
    { value: 'time', label: 'Time of Day', type: 'time' },
    { value: 'securityScore', label: 'Security Score', type: 'number' },
    { value: 'location', label: 'Geographic Location', type: 'string' },
    { value: 'environment', label: 'Environment', type: 'string' }
  ];

  const operatorOptions = {
    string: [
      { value: 'equals', label: 'equals', symbol: '==' },
      { value: 'notEquals', label: 'does not equal', symbol: '!=' },
      { value: 'contains', label: 'contains', symbol: '∋' },
      { value: 'startsWith', label: 'starts with', symbol: '^' },
      { value: 'in', label: 'is in list', symbol: '∈' }
    ],
    number: [
      { value: 'greaterThan', label: 'greater than', symbol: '>' },
      { value: 'lessThan', label: 'less than', symbol: '<' },
      { value: 'equals', label: 'equals', symbol: '==' },
      { value: 'greaterOrEqual', label: '≥', symbol: '>=' },
      { value: 'lessOrEqual', label: '≤', symbol: '<=' }
    ],
    time: [
      { value: 'between', label: 'between', symbol: '⟺' },
      { value: 'after', label: 'after', symbol: '>' },
      { value: 'before', label: 'before', symbol: '<' }
    ]
  };

  const environmentOptions = ['production', 'staging', 'development'];

  useEffect(() => {
    const fetchOptions = async () => {
      try {
        const workloadsRes = await fetch('/api/v1/workloads/options');
        const workloadsData = await workloadsRes.json();
        setWorkloadOptions(workloadsData.options.map(opt => opt.label));

        const targetsRes = await fetch('/api/v1/targets/options');
        const targetsData = await targetsRes.json();
        setTargetOptions(targetsData.options.map(t => t.label));
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch options:', error);
        toast.error('Failed to load workloads and targets');
        setLoading(false);
      }
    };
    fetchOptions();
  }, []);

  const addCondition = (ruleType, ruleId) => {
    const newCondition = {
      id: `c${Date.now()}`,
      field: 'subject',
      operator: 'equals',
      value: ''
    };
    setPolicy(prev => ({
      ...prev,
      [ruleType]: prev[ruleType].map(rule =>
        rule.id === ruleId
          ? { ...rule, conditions: [...rule.conditions, newCondition] }
          : rule
      )
    }));
  };

  const updateCondition = (ruleType, ruleId, conditionId, updates) => {
    setPolicy(prev => ({
      ...prev,
      [ruleType]: prev[ruleType].map(rule =>
        rule.id === ruleId
          ? { ...rule, conditions: rule.conditions.map(cond => cond.id === conditionId ? { ...cond, ...updates } : cond) }
          : rule
      )
    }));
  };

  const removeCondition = (ruleType, ruleId, conditionId) => {
    const rule = policy[ruleType].find(r => r.id === ruleId);
    if (rule && rule.conditions.length <= 1) {
      toast.error('Cannot remove the last condition');
      return;
    }
    setPolicy(prev => ({
      ...prev,
      [ruleType]: prev[ruleType].map(rule =>
        rule.id === ruleId
          ? { ...rule, conditions: rule.conditions.filter(c => c.id !== conditionId) }
          : rule
      )
    }));
  };

  const addDenyRule = () => {
    setPolicy(prev => ({
      ...prev,
      denyRules: [...prev.denyRules, {
        id: `deny${Date.now()}`,
        conditions: [{ id: `c${Date.now()}`, field: 'subject', operator: 'equals', value: '' }]
      }]
    }));
  };

  const generateRego = () => {
    let rego = 'package workload\n\ndefault allow := false\n\n';
    policy.allowRules.forEach((rule, idx) => {
      rego += `# Allow Rule ${idx + 1}\n`;
      rego += 'allow if {\n';
      rule.conditions.forEach(cond => {
        const opMap = { equals: '==', notEquals: '!=', greaterThan: '>', lessThan: '<', greaterOrEqual: '>=', lessOrEqual: '<=', contains: 'contains', startsWith: 'startswith', in: 'in' };
        const op = opMap[cond.operator] || '==';
        if (cond.operator === 'contains' || cond.operator === 'startsWith') {
          rego += `    ${cond.operator}(input.${cond.field}, "${cond.value}")\n`;
        } else {
          rego += `    input.${cond.field} ${op} "${cond.value}"\n`;
        }
      });
      rego += '}\n\n';
    });
    policy.denyRules.forEach((rule, idx) => {
      rego += `# Deny Rule ${idx + 1}\ndeny if {\n`;
      rule.conditions.forEach(cond => {
        const op = cond.operator === 'equals' ? '==' : '!=';
        rego += `    input.${cond.field} ${op} "${cond.value}"\n`;
      });
      rego += '}\n\nallow if {\n    not deny\n}\n\n';
    });
    return rego;
  };

  const handleTest = async () => {
    if (!testInput.subject || !testInput.audience) {
      toast.error('Please enter both subject and audience for testing');
      return;
    }
    try {
      const response = await fetch('/api/opa/v1/data/workload/allow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: testInput })
      });
      const data = await response.json();
      setTestResult({
        allowed: data.result === true,
        message: data.result ? 'Access allowed ✓' : 'Access denied ✗'
      });
      toast.success('Test completed');
    } catch (error) {
      toast.error('Test failed - check OPA connection');
    }
  };

  const handleSave = async () => {
    if (!policy.name) { toast.error('Please enter a policy name'); setStep(1); return; }
    const hasValidCondition = policy.allowRules.some(rule => rule.conditions.some(c => c.value));
    if (!hasValidCondition) { toast.error('Please fill in at least one condition'); setStep(2); return; }
    const regoPolicy = generateRego();
    try {
      const response = await fetch('/api/opa/v1/policies/workload-policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: regoPolicy
      });
      if (response.ok) {
        toast.success('Policy saved successfully!');
        setPolicy({
          name: '', description: '',
          allowRules: [{ id: '1', conditions: [{ id: 'c1', field: 'subject', operator: 'equals', value: '' }, { id: 'c2', field: 'audience', operator: 'equals', value: '' }] }],
          denyRules: []
        });
        setStep(1);
      } else { toast.error('Failed to save policy'); }
    } catch { toast.error('Error saving policy - check OPA connection'); }
  };

  const getFieldType = (fieldValue) => fieldOptions.find(f => f.value === fieldValue)?.type || 'string';
  const getOperatorsForField = (fieldValue) => operatorOptions[getFieldType(fieldValue)] || operatorOptions.string;

  /* ── Condition Block ── */
  const ConditionBlock = ({ ruleType, ruleId, condition, isLast, index }) => {
    const operators = getOperatorsForField(condition.field);

    const renderValueInput = () => {
      if (condition.field === 'subject') {
        return (
          <select value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} className="nhi-select">
            <option value="">Select workload...</option>
            {workloadOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
          </select>
        );
      }
      if (condition.field === 'audience') {
        return (
          <select value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} className="nhi-select">
            <option value="">Select target...</option>
            {targetOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
          </select>
        );
      }
      if (condition.field === 'environment') {
        return (
          <select value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} className="nhi-select">
            <option value="">Select environment...</option>
            {environmentOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
          </select>
        );
      }
      if (condition.field === 'time' && condition.operator === 'between') {
        return (
          <div className="flex items-center gap-2">
            <input type="time" value={condition.value?.split(' - ')[0] || ''} onChange={(e) => { const end = condition.value?.split(' - ')[1] || ''; updateCondition(ruleType, ruleId, condition.id, { value: end ? `${e.target.value} - ${end}` : e.target.value }); }} className="nhi-input" />
            <span className="text-nhi-faint text-xs font-medium">to</span>
            <input type="time" value={condition.value?.split(' - ')[1] || ''} onChange={(e) => { const start = condition.value?.split(' - ')[0] || ''; updateCondition(ruleType, ruleId, condition.id, { value: start ? `${start} - ${e.target.value}` : e.target.value }); }} className="nhi-input" />
          </div>
        );
      }
      if (condition.field === 'time') {
        return <input type="time" value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} className="nhi-input" />;
      }
      if (getFieldType(condition.field) === 'number') {
        return <input type="number" value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} placeholder="Enter number..." className="nhi-input" />;
      }
      return <input type="text" value={condition.value} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { value: e.target.value })} placeholder="Enter value..." className="nhi-input" />;
    };

    return (
      <div className="space-y-3">
        <div className="flex items-start gap-3">
          <div className="w-7 h-7 rounded-full bg-white/[0.06] flex items-center justify-center text-xs font-semibold text-nhi-dim mt-1 shrink-0">
            {index + 1}
          </div>
          <div className="flex-1 grid grid-cols-3 gap-3">
            <select
              value={condition.field}
              onChange={(e) => {
                const newField = e.target.value;
                const newOps = getOperatorsForField(newField);
                updateCondition(ruleType, ruleId, condition.id, { field: newField, operator: newOps[0].value, value: '' });
              }}
              className="nhi-select"
            >
              {fieldOptions.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
            </select>
            <select value={condition.operator} onChange={(e) => updateCondition(ruleType, ruleId, condition.id, { operator: e.target.value })} className="nhi-select">
              {operators.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
            </select>
            {renderValueInput()}
          </div>
          <button onClick={() => removeCondition(ruleType, ruleId, condition.id)} className="p-2 text-nhi-faint hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors mt-1">
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
        {!isLast && (
          <div className="flex items-center gap-3 ml-10">
            <div className="w-0.5 h-5 bg-white/[0.06]" />
            <span className="px-2.5 py-0.5 bg-white/[0.04] text-nhi-faint text-[10px] font-bold rounded-full uppercase tracking-wider">AND</span>
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 gap-3">
        <Loader className="w-5 h-5 text-accent animate-spin" />
        <span className="text-sm text-nhi-dim">Loading policy options...</span>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* ── Progress Steps ── */}
      <div className="mb-8 flex items-center justify-center gap-3">
        {[
          { num: 1, label: 'Basic Info' },
          { num: 2, label: 'Define Rules' },
          { num: 3, label: 'Test & Save' }
        ].map((s, idx) => (
          <React.Fragment key={s.num}>
            <button
              onClick={() => setStep(s.num)}
              className={`flex items-center gap-2.5 px-4 py-2.5 rounded-lg transition-all text-sm font-medium ${
                step === s.num
                  ? 'bg-accent text-white shadow-glow-sm'
                  : step > s.num
                  ? 'bg-emerald-500/[0.15] text-emerald-400'
                  : 'bg-white/[0.04] text-nhi-dim hover:bg-white/[0.06]'
              }`}
            >
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                step > s.num ? 'bg-emerald-400/20' : step === s.num ? 'bg-white/20' : 'bg-white/[0.06]'
              }`}>
                {step > s.num ? <Check className="w-3.5 h-3.5" /> : s.num}
              </div>
              {s.label}
            </button>
            {idx < 2 && <ArrowRight className="w-4 h-4 text-nhi-ghost" />}
          </React.Fragment>
        ))}
      </div>

      {/* ── Step 1: Basic Info ── */}
      {step === 1 && (
        <div className="nhi-card p-7 space-y-6 animate-fadeIn">
          <div>
            <h2 className="text-xl font-bold text-nhi-text mb-1">Policy Information</h2>
            <p className="text-sm text-nhi-dim">Start by giving your policy a name and description</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-nhi-muted mb-2">
              Policy Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={policy.name}
              onChange={(e) => setPolicy({ ...policy, name: e.target.value })}
              placeholder="e.g., Payment Service to Stripe Access"
              className="nhi-input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-nhi-muted mb-2">Description (Optional)</label>
            <textarea
              value={policy.description}
              onChange={(e) => setPolicy({ ...policy, description: e.target.value })}
              placeholder="Describe the purpose of this policy..."
              rows={4}
              className="nhi-input resize-none"
            />
          </div>
          <div className="flex justify-end pt-2">
            <button onClick={() => setStep(2)} disabled={!policy.name} className="nhi-btn-primary disabled:opacity-40 disabled:cursor-not-allowed">
              Next: Define Rules <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Step 2: Rules ── */}
      {step === 2 && (
        <div className="space-y-5 animate-fadeIn">
          {/* Allow Rules */}
          <div className="nhi-card p-7">
            <div className="flex items-start gap-4 mb-6">
              <div className="w-10 h-10 bg-emerald-400/10 rounded-lg flex items-center justify-center shrink-0">
                <Check className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-nhi-text mb-0.5">ALLOW when</h3>
                <p className="text-sm text-nhi-dim">Define conditions that grant access</p>
              </div>
            </div>
            {policy.allowRules.map(rule => (
              <div key={rule.id} className="space-y-4">
                {rule.conditions.map((cond, idx) => (
                  <ConditionBlock key={cond.id} ruleType="allowRules" ruleId={rule.id} condition={cond} isLast={idx === rule.conditions.length - 1} index={idx} />
                ))}
                <button onClick={() => addCondition('allowRules', rule.id)} className="ml-10 nhi-btn-ghost text-accent-light hover:bg-accent/[0.08]">
                  <Plus className="w-4 h-4" /> Add Another Condition
                </button>
              </div>
            ))}
          </div>

          {/* Deny Rules */}
          <div className="nhi-card p-7">
            <div className="flex items-start gap-4 mb-6">
              <div className="w-10 h-10 bg-red-400/10 rounded-lg flex items-center justify-center shrink-0">
                <X className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-nhi-text mb-0.5">DENY when (Optional)</h3>
                <p className="text-sm text-nhi-dim">Add conditions that explicitly block access</p>
              </div>
            </div>
            {policy.denyRules.length === 0 ? (
              <button onClick={addDenyRule} className="ml-10 nhi-btn-ghost border-2 border-dashed border-white/[0.08] text-nhi-dim">
                <Plus className="w-4 h-4" /> Add Deny Rule
              </button>
            ) : (
              policy.denyRules.map(rule => (
                <div key={rule.id} className="space-y-4">
                  {rule.conditions.map((cond, idx) => (
                    <ConditionBlock key={cond.id} ruleType="denyRules" ruleId={rule.id} condition={cond} isLast={idx === rule.conditions.length - 1} index={idx} />
                  ))}
                  <button onClick={() => addCondition('denyRules', rule.id)} className="ml-10 nhi-btn-ghost text-accent-light hover:bg-accent/[0.08]">
                    <Plus className="w-4 h-4" /> Add Another Condition
                  </button>
                </div>
              ))
            )}
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(1)} className="nhi-btn-secondary">
              <ArrowLeft className="w-4 h-4" /> Back
            </button>
            <button onClick={() => setStep(3)} className="nhi-btn-primary">
              Next: Test Policy <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Step 3: Test & Save ── */}
      {step === 3 && (
        <div className="space-y-5 animate-fadeIn">
          {/* Rego Preview */}
          <div className="nhi-card p-7">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-nhi-text mb-0.5">Generated Policy</h3>
                <p className="text-sm text-nhi-dim">Rego code deployed to OPA</p>
              </div>
              <button onClick={() => setShowRegoPreview(!showRegoPreview)} className="text-sm font-medium text-accent-light hover:text-accent transition-colors">
                {showRegoPreview ? 'Hide' : 'Show'} Code
              </button>
            </div>
            {showRegoPreview && (
              <pre className="bg-surface-0 text-emerald-300 p-5 rounded-lg overflow-x-auto text-xs leading-relaxed border border-white/[0.04] font-mono">
                {generateRego()}
              </pre>
            )}
          </div>

          {/* Test */}
          <div className="nhi-card p-7">
            <div className="mb-5">
              <h3 className="text-lg font-bold text-nhi-text mb-0.5">Test Your Policy</h3>
              <p className="text-sm text-nhi-dim">Verify before saving</p>
            </div>
            <div className="grid grid-cols-2 gap-4 mb-5">
              <div>
                <label className="block text-sm font-medium text-nhi-muted mb-2">Test Subject (Who)</label>
                <select value={testInput.subject} onChange={(e) => setTestInput({ ...testInput, subject: e.target.value })} className="nhi-select">
                  <option value="">Select workload to test...</option>
                  {workloadOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-nhi-muted mb-2">Test Audience (What)</label>
                <select value={testInput.audience} onChange={(e) => setTestInput({ ...testInput, audience: e.target.value })} className="nhi-select">
                  <option value="">Select target to test...</option>
                  {targetOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                </select>
              </div>
            </div>

            {testResult && (
              <div className={`p-4 rounded-lg mb-5 border ${
                testResult.allowed
                  ? 'bg-emerald-400/[0.08] border-emerald-400/20'
                  : 'bg-red-400/[0.08] border-red-400/20'
              }`}>
                <div className="flex items-center gap-3">
                  {testResult.allowed ? <Check className="w-5 h-5 text-emerald-400" /> : <X className="w-5 h-5 text-red-400" />}
                  <span className="font-bold text-nhi-text">{testResult.message}</span>
                </div>
              </div>
            )}

            <button onClick={handleTest} disabled={!testInput.subject || !testInput.audience} className="nhi-btn-secondary disabled:opacity-40 disabled:cursor-not-allowed">
              <TestTube className="w-4 h-4" /> Run Test
            </button>
          </div>

          {/* Summary callout */}
          <div className="nhi-card p-5 border-l-2 border-l-accent">
            <div className="flex gap-3">
              <AlertCircle className="w-5 h-5 text-accent-light shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-nhi-text text-sm mb-0.5">Ready to save?</h4>
                <p className="text-sm text-nhi-dim">
                  Policy "<span className="text-accent-light font-semibold">{policy.name}</span>" will be deployed to OPA and take effect immediately.
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-between">
            <button onClick={() => setStep(2)} className="nhi-btn-secondary">
              <ArrowLeft className="w-4 h-4" /> Back to Rules
            </button>
            <button onClick={handleSave} className="nhi-btn-primary shadow-glow">
              <Save className="w-4 h-4" /> Save Policy
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PolicyBuilderV2;