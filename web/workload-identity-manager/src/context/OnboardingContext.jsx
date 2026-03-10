import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useAuth } from './AuthContext';

const OnboardingContext = createContext();

export function OnboardingProvider({ children }) {
  const { user } = useAuth();
  const [hasConnectors, setHasConnectors] = useState(null); // null = unknown
  const [loading, setLoading] = useState(true);

  const fetchConnectorStatus = useCallback(async () => {
    if (!user) { setLoading(false); return; }
    try {
      const res = await fetch('/api/v1/connectors', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        const total = data.total ?? data.connectors?.length ?? 0;
        setHasConnectors(total > 0);
      } else {
        // Endpoint failed — assume connectors exist so we don't block navigation
        setHasConnectors(true);
      }
    } catch {
      setHasConnectors(true);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchConnectorStatus();
  }, [fetchConnectorStatus]);

  const refresh = useCallback(async () => {
    setLoading(true);
    await fetchConnectorStatus();
  }, [fetchConnectorStatus]);

  return (
    <OnboardingContext.Provider value={{ hasConnectors, loading, refresh }}>
      {children}
    </OnboardingContext.Provider>
  );
}

export function useOnboarding() {
  const ctx = useContext(OnboardingContext);
  if (!ctx) throw new Error('useOnboarding must be used within OnboardingProvider');
  return ctx;
}
