import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useOnboarding } from '../../context/OnboardingContext';

export default function OnboardingGuard() {
  const { hasConnectors, loading } = useOnboarding();
  const { pathname } = useLocation();

  // Still loading — render nothing (parent Layout already visible, avoids flash)
  if (loading) return null;

  // No connectors and not already on /connectors → redirect
  if (hasConnectors === false && pathname !== '/connectors') {
    return <Navigate to="/connectors" replace />;
  }

  return <Outlet />;
}
