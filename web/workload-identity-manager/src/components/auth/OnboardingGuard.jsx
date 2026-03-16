import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useOnboarding } from '../../context/OnboardingContext';

export default function OnboardingGuard() {
  const { hasConnectors, loading } = useOnboarding();
  const { pathname } = useLocation();
  const onboardingComplete = localStorage.getItem('wid_onboarding_complete') === 'true';

  // Still loading — render nothing (parent Layout already visible, avoids flash)
  if (loading) return null;

  // User has never completed onboarding and has no connectors → redirect to wizard
  if (!onboardingComplete && hasConnectors === false && pathname !== '/onboarding') {
    return <Navigate to="/onboarding" replace />;
  }

  // Onboarding done but no connectors → send to connectors page
  if (hasConnectors === false && pathname !== '/connectors') {
    return <Navigate to="/connectors" replace />;
  }

  return <Outlet />;
}
