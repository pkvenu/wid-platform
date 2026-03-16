import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  Eye, EyeOff, Sun, Moon, Shield, Search, GitBranch, BarChart3,
  ChevronRight, Globe, Building2,
} from 'lucide-react';

const FEATURES = [
  { icon: Search, title: 'Discover Every Identity', desc: 'Auto-discover workloads, service accounts, and NHIs across AWS, GCP, Azure, and Kubernetes.' },
  { icon: GitBranch, title: 'Map Attack Paths', desc: 'Visualize credential chains, blast radius, and lateral movement risks in real time.' },
  { icon: Shield, title: 'Enforce Zero Trust', desc: 'Policy-driven enforcement with Simulate, Audit, and Enforce modes. No blind rollouts.' },
  { icon: BarChart3, title: 'Prove Compliance', desc: 'Audit-ready evidence for SOC 2, ISO 27001, NIST 800-53, CIS, and EU AI Act.' },
];

const DATA_REGIONS = [
  { value: 'us', label: 'United States' },
  { value: 'eu', label: 'European Union' },
  { value: 'ap', label: 'Asia Pacific' },
];

export default function Login() {
  const { user, login, register, hasUsers } = useAuth();
  const { isDark, toggle } = useTheme();
  const navigate = useNavigate();

  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organization, setOrganization] = useState('');
  const [dataRegion, setDataRegion] = useState('us');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // If no users exist, default to register mode
  useEffect(() => {
    if (!hasUsers) setMode('register');
  }, [hasUsers]);

  // If already logged in, redirect
  useEffect(() => {
    if (user) navigate('/', { replace: true });
  }, [user, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (mode === 'register') {
        await register(name, email, password, organization, dataRegion);
        navigate('/onboarding', { replace: true });
      } else {
        await login(email, password);
        navigate('/', { replace: true });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inputClass = 'w-full h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all';

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col lg:flex-row">
      {/* Theme toggle */}
      <button
        onClick={toggle}
        className="absolute top-4 right-4 z-10 p-2 rounded-lg text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-colors"
      >
        {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </button>

      {/* ─── Left: Hero ──────────────────────────────────────────────── */}
      <div className="hidden lg:flex lg:w-[60%] flex-col justify-center px-16 xl:px-24 py-16 bg-gradient-to-br from-surface-0 via-surface-0 to-accent/[0.06] relative overflow-hidden">
        {/* Decorative grid */}
        <div className="absolute inset-0 opacity-[0.03]" style={{ backgroundImage: 'radial-gradient(circle, currentColor 1px, transparent 1px)', backgroundSize: '24px 24px' }} />

        <div className="relative z-10 max-w-xl">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-10">
            <div className="w-10 h-10 rounded-xl bg-accent flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 16 16" fill="none">
                <path d="M4 5.5a2 2 0 012-2h4a2 2 0 010 4H8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
                <path d="M12 10.5a2 2 0 01-2 2H6a2 2 0 010-4h2" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
                <circle cx="8" cy="8" r="1.2" fill="#fff"/>
              </svg>
            </div>
            <span className="text-lg font-bold text-nhi-text tracking-tight">Workload Identity Defense</span>
          </div>

          <h1 className="text-3xl xl:text-4xl font-bold text-nhi-text leading-tight mb-4">
            See every identity.<br />
            Close every gap.
          </h1>
          <p className="text-base text-nhi-dim mb-10 leading-relaxed max-w-md">
            The enterprise platform for discovering, attesting, and securing non-human identities across your entire infrastructure.
          </p>

          {/* Features */}
          <div className="space-y-5">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="flex gap-4">
                <div className="w-9 h-9 rounded-lg bg-accent/[0.08] border border-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon className="w-4.5 h-4.5 text-accent-light" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-nhi-text mb-0.5">{title}</h3>
                  <p className="text-xs text-nhi-dim leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Social proof */}
          <div className="mt-12 pt-8 border-t border-brd/50">
            <p className="text-xs text-nhi-ghost mb-3 uppercase tracking-wider font-medium">Trusted by security teams at</p>
            <div className="flex items-center gap-6">
              {['Enterprise', 'FinTech', 'HealthTech', 'GovCloud'].map((v) => (
                <span key={v} className="text-xs text-nhi-dim/60 font-semibold tracking-wide">{v}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ─── Right: Form ─────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col items-center justify-center px-6 py-12 lg:px-12">
        <div className="w-full max-w-[420px]">
          {/* Mobile logo */}
          <div className="flex flex-col items-center mb-8 lg:hidden">
            <div className="w-12 h-12 rounded-xl bg-accent flex items-center justify-center mb-4">
              <svg width="24" height="24" viewBox="0 0 16 16" fill="none">
                <path d="M4 5.5a2 2 0 012-2h4a2 2 0 010 4H8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
                <path d="M12 10.5a2 2 0 01-2 2H6a2 2 0 010-4h2" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
                <circle cx="8" cy="8" r="1.2" fill="#fff"/>
              </svg>
            </div>
            <h1 className="text-xl font-bold text-nhi-text">Workload Identity Defense</h1>
          </div>

          {/* Tab switcher */}
          <div className="flex bg-surface-1 border border-brd rounded-xl p-1 mb-6">
            <button
              onClick={() => { setMode('login'); setError(''); }}
              className={`flex-1 h-9 rounded-lg text-sm font-medium transition-all ${
                mode === 'login'
                  ? 'bg-accent text-white shadow-sm'
                  : 'text-nhi-dim hover:text-nhi-text'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setMode('register'); setError(''); }}
              className={`flex-1 h-9 rounded-lg text-sm font-medium transition-all ${
                mode === 'register'
                  ? 'bg-accent text-white shadow-sm'
                  : 'text-nhi-dim hover:text-nhi-text'
              }`}
            >
              Start Free Trial
            </button>
          </div>

          {/* Form Card */}
          <div className="bg-surface-1 border border-brd rounded-xl p-6 shadow-sm">
            {!hasUsers && mode === 'register' && (
              <div className="mb-4 p-3 rounded-lg bg-accent/[0.08] border border-accent/20">
                <p className="text-xs text-accent-light font-medium">
                  Welcome! Create the first admin account to get started.
                </p>
              </div>
            )}

            {error && (
              <div className="mb-4 p-3 rounded-lg bg-red-500/[0.08] border border-red-500/20">
                <p className="text-xs text-red-400 font-medium">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              {mode === 'register' && (
                <div>
                  <label className="block text-xs font-medium text-nhi-dim mb-1.5">Full Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Smith"
                    required
                    autoComplete="name"
                    className={inputClass}
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-nhi-dim mb-1.5">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  required
                  autoComplete="email"
                  className={inputClass}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-nhi-dim mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={mode === 'register' ? 'Min 8 characters' : 'Enter password'}
                    required
                    minLength={mode === 'register' ? 8 : undefined}
                    autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                    className={`${inputClass} pr-10`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nhi-ghost hover:text-nhi-dim transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {mode === 'register' && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-nhi-dim mb-1.5">
                      <Building2 className="w-3.5 h-3.5 inline mr-1 -mt-0.5" />
                      Organization Name
                    </label>
                    <input
                      type="text"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      placeholder="Acme Corp"
                      required
                      className={inputClass}
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-nhi-dim mb-1.5">
                      <Globe className="w-3.5 h-3.5 inline mr-1 -mt-0.5" />
                      Data Region
                    </label>
                    <select
                      value={dataRegion}
                      onChange={(e) => setDataRegion(e.target.value)}
                      className={`${inputClass} appearance-none cursor-pointer`}
                    >
                      {DATA_REGIONS.map((r) => (
                        <option key={r.value} value={r.value}>{r.label}</option>
                      ))}
                    </select>
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={loading}
                className="h-10 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all mt-1 flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    {mode === 'register' ? 'Creating organization...' : 'Signing in...'}
                  </>
                ) : (
                  <>
                    {mode === 'register' ? 'Create Organization' : 'Sign In'}
                    <ChevronRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Footer */}
          <div className="mt-6 text-center">
            <p className="text-xs text-nhi-ghost">
              Enterprise deployment?{' '}
              <a href="mailto:sales@wid.dev" className="text-accent-light hover:underline font-medium">
                Contact Sales
              </a>
            </p>
          </div>

          <p className="text-center text-[11px] text-nhi-ghost mt-4">
            Workload Identity Defense
          </p>
        </div>
      </div>
    </div>
  );
}
