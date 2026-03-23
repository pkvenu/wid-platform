import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  Server,
  GitBranch,
  ScrollText,
  ScanSearch,
  LogOut,
  Plug,
  PanelLeftClose,
  PanelLeftOpen,
  ClipboardCheck,
  Settings,
  BrainCircuit,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useOnboarding } from '../../context/OnboardingContext';

const ALL_NAV_ITEMS = [
  { icon: Server, label: 'Workloads', path: '/workloads', badge: true },
  { icon: GitBranch, label: 'Identity Graph', path: '/graph' },
  { icon: BrainCircuit, label: 'AI Inventory', path: '/ai-inventory' },
  { icon: Plug, label: 'Connectors', path: '/connectors' },
  { icon: Shield, label: 'Policies', path: '/policies' },
  { icon: ScrollText, label: 'Access Events', path: '/access' },
  { icon: ClipboardCheck, label: 'Compliance', path: '/compliance' },
  { icon: Settings, label: 'Settings', path: '/settings' },
];

const ONBOARDING_NAV_ITEMS = [
  { icon: Plug, label: 'Connectors', path: '/connectors' },
  { icon: Settings, label: 'Settings', path: '/settings' },
];

const Sidebar = ({ isCollapsed, onToggleCollapse }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, tenant, tenantSlug, logout } = useAuth();
  const { hasConnectors } = useOnboarding();

  // Prefix nav paths with tenant slug
  const prefixedItems = (hasConnectors ? ALL_NAV_ITEMS : ONBOARDING_NAV_ITEMS).map(item => ({
    ...item,
    path: `/${tenantSlug}${item.path}`,
    basePath: item.path, // keep original for active matching
  }));
  const NAV_ITEMS = prefixedItems;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const initials = user?.name
    ? user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
    : '?';

  const isActive = (path) => {
    // Match against both tenant-prefixed path and the base path
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const tenantPrefix = `/${tenantSlug}`;

  return (
    <aside
      className={`fixed left-0 top-0 bottom-0 z-50 flex flex-col bg-surface-0 border-r transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] ${
        isCollapsed ? 'w-[56px]' : 'w-[240px]'
      }`}
      style={{ borderColor: 'var(--border)' }}
    >
      {/* ── Brand ── */}
      <div
        className="h-14 flex items-center gap-3 px-3.5 border-b border-brd cursor-pointer shrink-0 group"
        onClick={() => onToggleCollapse(!isCollapsed)}
      >
        {/* Logo mark */}
        <div className="w-7 h-7 rounded-lg bg-accent flex items-center justify-center shrink-0">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M4 5.5a2 2 0 012-2h4a2 2 0 010 4H8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
            <path d="M12 10.5a2 2 0 01-2 2H6a2 2 0 010-4h2" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
            <circle cx="8" cy="8" r="1.2" fill="#fff"/>
          </svg>
        </div>

        <div
          className={`overflow-hidden whitespace-nowrap transition-all duration-200 ${
            isCollapsed ? 'w-0 opacity-0' : 'w-auto opacity-100'
          }`}
        >
          <div className="text-[13px] font-bold text-nhi-text tracking-tight leading-tight">
            Workload Identity
          </div>
          <div className="text-[10px] font-medium text-nhi-faint uppercase tracking-[0.06em]">
            Defense
          </div>
        </div>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 py-3 px-2 flex flex-col gap-0.5">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.path);

          return (
            <Link
              key={item.path}
              to={item.path}
              className={`relative flex items-center gap-3 h-10 rounded-lg transition-all duration-150 group/item ${
                isCollapsed ? 'justify-center px-0' : 'px-2.5'
              } ${
                active
                  ? 'bg-accent/[0.12] text-accent-light'
                  : 'text-nhi-dim hover:text-nhi-muted hover:bg-surface-3/50'
              }`}
            >
              {/* Active bar */}
              {active && (
                <div className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full bg-accent" />
              )}

              <Icon className="w-5 h-5 shrink-0" strokeWidth={active ? 2 : 1.5} />

              {!isCollapsed && (
                <>
                  <span className={`text-[13px] flex-1 ${active ? 'font-semibold' : 'font-medium'}`}>
                    {item.label}
                  </span>

                  {/* Badge placeholder for dynamic count */}
                  {item.badge && (
                    <span className="text-[10px] font-bold font-mono bg-accent/[0.15] text-accent-light px-1.5 py-0.5 rounded-md">
                      —
                    </span>
                  )}
                </>
              )}

              {/* Collapsed badge dot */}
              {item.badge && isCollapsed && (
                <div className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-accent" />
              )}

              {/* Tooltip on collapsed */}
              {isCollapsed && (
                <div className="absolute left-full ml-2 px-2.5 py-1.5 bg-surface-3 text-nhi-text text-xs font-medium rounded-md whitespace-nowrap opacity-0 pointer-events-none group-hover/item:opacity-100 transition-opacity duration-150 shadow-lg border border-brd z-50">
                  {item.label}
                </div>
              )}
            </Link>
          );
        })}

        {/* Scan button - separated section (only when connectors exist) */}
        {hasConnectors && (
          <div className={`mt-3 pt-3 border-t border-brd ${isCollapsed ? 'px-1.5' : 'px-2'}`}>
            <Link
              to={`${tenantPrefix}/workloads`}
              className={`flex items-center gap-2.5 h-10 rounded-lg bg-accent/[0.08] text-accent border border-accent/20 transition-all duration-150 hover:bg-accent/[0.15] hover:border-accent/35 hover:shadow-[0_0_12px_rgba(124,111,240,0.15)] ${
                isCollapsed ? 'justify-center px-0' : 'px-3'
              }`}
            >
              <ScanSearch className="w-[18px] h-[18px] shrink-0" strokeWidth={1.5} />
              {!isCollapsed && (
                <span className="text-[13px] font-semibold">Run Scan</span>
              )}
            </Link>
            {isCollapsed && (
              <div className="absolute left-full ml-2 px-2.5 py-1.5 bg-surface-3 text-nhi-text text-xs font-medium rounded-md whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-150 shadow-lg border border-brd z-50">
                Run Scan
              </div>
            )}
          </div>
        )}
      </nav>

      {/* ── Bottom — User + Logout ── */}
      <div className="border-t border-brd p-2 shrink-0">
        {user && (
          <div
            className={`flex items-center gap-2.5 h-10 rounded-lg text-nhi-dim ${
              isCollapsed ? 'justify-center px-0' : 'px-2.5'
            }`}
          >
            {/* Avatar circle */}
            <div className="w-7 h-7 rounded-full bg-accent/[0.15] text-accent-light flex items-center justify-center shrink-0">
              <span className="text-[10px] font-bold">{initials}</span>
            </div>
            {!isCollapsed && (
              <div className="flex-1 min-w-0">
                <div className="text-[12px] font-medium text-nhi-text truncate">{user.name}</div>
                <div className="text-[10px] text-nhi-ghost truncate">{tenant?.name || user.email}</div>
              </div>
            )}
            {!isCollapsed && (
              <button
                onClick={handleLogout}
                className="p-1.5 rounded-md text-nhi-ghost hover:text-red-400 hover:bg-red-500/[0.08] transition-colors shrink-0"
                title="Sign out"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        )}

        {/* Logout tooltip for collapsed sidebar */}
        {isCollapsed && user && (
          <button
            onClick={handleLogout}
            className="flex items-center justify-center w-full h-8 rounded-md text-nhi-ghost hover:text-red-400 hover:bg-red-500/[0.08] transition-colors mt-1"
            title="Sign out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        )}

        <button
          onClick={() => onToggleCollapse(!isCollapsed)}
          className={`flex items-center h-8 w-full rounded-md text-nhi-ghost hover:text-nhi-dim hover:bg-surface-3/50 transition-all duration-150 ${
            isCollapsed ? 'justify-center' : 'justify-end px-2.5'
          }`}
        >
          {isCollapsed ? (
            <PanelLeftOpen className="w-4 h-4" />
          ) : (
            <PanelLeftClose className="w-4 h-4" />
          )}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;