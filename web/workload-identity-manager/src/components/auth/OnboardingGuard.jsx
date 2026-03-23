import React from 'react';
import { Navigate, Outlet, useLocation, useParams } from 'react-router-dom';
import { useOnboarding } from '../../context/OnboardingContext';

export default function OnboardingGuard() {
  const { hasConnectors, loading } = useOnboarding();
  const { pathname } = useLocation();
  const { tenantSlug } = useParams();
  const onboardingComplete = localStorage.getItem('wid_onboarding_complete') === 'true';
  const prefix = tenantSlug ? `/${tenantSlug}` : '';

  // Still loading — render nothing (parent Layout already visible, avoids flash)
  if (loading) return null;

  // User has never completed onboarding and has no connectors → redirect to wizard
  if (!onboardingComplete && hasConnectors === false && pathname !== '/onboarding') {
    return <Navigate to="/onboarding" replace />;
  }

  // Onboarding done but no connectors → send to connectors page
  const connectorsPath = `${prefix}/connectors`;
  if (hasConnectors === false && pathname !== connectorsPath && pathname !== '/connectors') {
    return <Navigate to={connectorsPath} replace />;
  }

  return <Outlet />;
}
