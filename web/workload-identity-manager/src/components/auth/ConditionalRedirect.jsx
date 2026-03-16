import React from 'react';
import { Navigate } from 'react-router-dom';
import { useOnboarding } from '../../context/OnboardingContext';

export default function ConditionalRedirect() {
  const { hasConnectors, loading } = useOnboarding();
  const onboardingComplete = localStorage.getItem('wid_onboarding_complete') === 'true';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // Not onboarded yet → wizard
  if (!onboardingComplete && !hasConnectors) {
    return <Navigate to="/onboarding" replace />;
  }

  // Onboarded but no connectors → connectors page
  if (!hasConnectors) {
    return <Navigate to="/connectors" replace />;
  }

  // All good → workloads
  return <Navigate to="/workloads" replace />;
}
