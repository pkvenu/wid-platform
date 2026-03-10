import React from 'react';
import { Navigate } from 'react-router-dom';
import { useOnboarding } from '../../context/OnboardingContext';

export default function ConditionalRedirect() {
  const { hasConnectors, loading } = useOnboarding();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return <Navigate to={hasConnectors ? '/workloads' : '/connectors'} replace />;
}
