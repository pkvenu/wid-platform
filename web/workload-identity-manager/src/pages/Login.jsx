import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { Eye, EyeOff, Sun, Moon } from 'lucide-react';

export default function Login() {
  const { user, login, register, hasUsers } = useAuth();
  const { isDark, toggle } = useTheme();
  const navigate = useNavigate();

  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // If no users exist, show register mode
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
        await register(name, email, password);
      } else {
        await login(email, password);
      }
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col items-center justify-center px-4">
      {/* Theme toggle */}
      <button
        onClick={toggle}
        className="absolute top-4 right-4 p-2 rounded-lg text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-colors"
      >
        {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </button>

      <div className="w-full max-w-[400px]">
        {/* Logo + Brand */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-accent flex items-center justify-center mb-4">
            <svg width="24" height="24" viewBox="0 0 16 16" fill="none">
              <path d="M4 5.5a2 2 0 012-2h4a2 2 0 010 4H8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
              <path d="M12 10.5a2 2 0 01-2 2H6a2 2 0 010-4h2" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
              <circle cx="8" cy="8" r="1.2" fill="#fff"/>
            </svg>
          </div>
          <h1 className="text-xl font-bold text-nhi-text">Workload Identity</h1>
          <p className="text-sm text-nhi-dim mt-1">
            {mode === 'register' ? 'Create your admin account' : 'Sign in to your account'}
          </p>
        </div>

        {/* Form Card */}
        <div className="bg-surface-1 border border-brd rounded-xl p-6 shadow-sm">
          {!hasUsers && (
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
                <label className="block text-xs font-medium text-nhi-dim mb-1.5">Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your name"
                  required
                  autoComplete="name"
                  className="w-full h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all"
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
                className="w-full h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all"
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
                  className="w-full h-10 px-3 pr-10 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all"
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

            <button
              type="submit"
              disabled={loading}
              className="h-10 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all mt-1"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  {mode === 'register' ? 'Creating account...' : 'Signing in...'}
                </span>
              ) : (
                mode === 'register' ? 'Create Account' : 'Sign In'
              )}
            </button>
          </form>

          {/* Toggle mode — only show if users exist (can't register if users exist) */}
          {hasUsers && (
            <div className="mt-4 pt-4 border-t border-brd text-center">
              <p className="text-xs text-nhi-ghost">
                {mode === 'login' ? (
                  <>Don't have an account? Contact your admin.</>
                ) : (
                  <>
                    Already have an account?{' '}
                    <button
                      onClick={() => { setMode('login'); setError(''); }}
                      className="text-accent-light hover:underline font-medium"
                    >
                      Sign in
                    </button>
                  </>
                )}
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-nhi-ghost mt-6">
          Workload Identity Director
        </p>
      </div>
    </div>
  );
}
