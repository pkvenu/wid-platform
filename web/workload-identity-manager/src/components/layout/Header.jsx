import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Search, Bell, WifiOff, Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

const ROUTE_META = {
  '/': { title: 'Workloads' },
  '/workloads': { title: 'Workloads' },
  '/graph': { title: 'Identity Graph' },
  '/policies': { title: 'Policies' },
  '/access': { title: 'Access Events' },
  '/dashboard': { title: 'Dashboard' },
  '/templates': { title: 'Templates' },
  '/operations': { title: 'Operations' },
  '/demo': { title: 'Demo' },
  '/connectors': { title: 'Connectors' },
};

const Header = () => {
  const location = useLocation();
  const meta = ROUTE_META[location.pathname] || { title: 'Workload Identity' };
  const [serviceStatus, setServiceStatus] = useState({ count: 0, online: false, scanners: [] });
  const [showScanners, setShowScanners] = useState(false);
  const { theme, toggle, isDark } = useTheme();

  useEffect(() => {
    const checkServices = async () => {
      try {
        const res = await fetch('/api/v1/scanners', { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          const scannerCount = data.scanners?.length || 0;
          setServiceStatus({ count: scannerCount, online: true, scanners: data.scanners || [] });
        } else {
          // API reachable but endpoint missing — still online
          setServiceStatus({ count: 0, online: true });
        }
      } catch {
        try {
          const ping = await fetch('/api/v1/stats', { credentials: 'include' });
          setServiceStatus({ count: 0, online: ping.ok });
        } catch {
          setServiceStatus({ count: 0, online: false });
        }
      }
    };

    checkServices();
    const interval = setInterval(checkServices, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-surface-1 flex items-center justify-between px-7" style={{ borderBottom: '1px solid var(--border)' }}>
      <div className="flex items-center gap-4">
        <h1 className="text-base font-bold text-nhi-text tracking-tight">
          {meta.title}
        </h1>
        <span className="text-[11px] font-medium text-nhi-faint px-2.5 py-1 rounded-full font-mono" style={{ background: 'var(--bg-accent-soft)' }}>
          v0.2.0
        </span>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-nhi-faint" />
          <input
            type="text"
            placeholder="Search identities..."
            className="nhi-input pl-9 pr-3 py-1.5 w-52 text-xs"
          />
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="p-2 rounded-lg text-nhi-dim transition-colors"
          style={{ background: 'var(--bg-subtle)' }}
          title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        <button className="relative p-2 rounded-lg text-nhi-dim transition-colors" style={{ background: 'var(--bg-subtle)' }}>
          <Bell className="w-4 h-4" />
          <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-risk-critical" />
        </button>

        {serviceStatus.online ? (
          <div className="relative"
            onMouseEnter={() => setShowScanners(true)}
            onMouseLeave={() => setShowScanners(false)}>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/[0.08] border border-emerald-500/[0.12] cursor-pointer">
              <div className="w-[7px] h-[7px] rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.4)]" />
              <span className="text-[11px] font-semibold text-emerald-500 dark:text-emerald-400 font-mono">
                {serviceStatus.count > 0
                  ? `${serviceStatus.count} Scanner${serviceStatus.count !== 1 ? 's' : ''}`
                  : 'API Online'}
              </span>
            </div>
            {showScanners && serviceStatus.scanners.length > 0 && (
              <div className="absolute right-0 top-full mt-1.5 z-50 min-w-[220px] rounded-lg shadow-lg border"
                style={{ background: 'var(--surface-3)', borderColor: 'var(--border)' }}>
                <div className="px-3 py-2 text-[10px] font-bold text-nhi-dim uppercase" style={{ borderBottom: '1px solid var(--border)', letterSpacing: '0.05em' }}>
                  Active Scanners
                </div>
                {serviceStatus.scanners.map((s, i) => {
                  const provIcons = { aws: '\u2601', docker: '\ud83d\udc33', vault: '\ud83d\udd10', internal: '\ud83d\udd11', gcp: '\u2601', azure: '\u2601' };
                  return (
                    <div key={i} className="px-3 py-1.5 flex items-center gap-2" style={{ borderBottom: i < serviceStatus.scanners.length - 1 ? '1px solid var(--border)' : 'none' }}>
                      <span className="text-[12px]">{provIcons[s.provider] || '\ud83d\udd0d'}</span>
                      <span className="text-[10px] font-semibold text-nhi-text flex-1">{s.name}</span>
                      <span className="text-[8px] font-mono text-nhi-faint px-1.5 py-0.5 rounded" style={{ background: 'var(--bg-accent-soft)' }}>{s.provider}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/[0.08] border border-red-500/[0.12]">
            <WifiOff className="w-3 h-3 text-red-400" />
            <span className="text-[11px] font-semibold text-red-400 font-mono">Offline</span>
          </div>
        )}

        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent to-accent-dim flex items-center justify-center text-xs font-bold text-white cursor-pointer">
          WI
        </div>
      </div>
    </header>
  );
};

export default Header;