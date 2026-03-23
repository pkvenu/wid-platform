import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

/**
 * Redirects to the tenant-scoped URL.
 * Used at `/` to redirect to `/:tenantSlug/` and for legacy non-tenant routes.
 * Falls back to 'default' slug if tenant info is not yet available.
 */
export default function TenantRedirect({ path }) {
  const { tenant } = useAuth();
  const slug = tenant?.slug || 'default';
  const target = path ? `/${slug}/${path}` : `/${slug}/`;
  return <Navigate to={target} replace />;
}
