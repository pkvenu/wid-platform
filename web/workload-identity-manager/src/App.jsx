import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Layout from './components/layout/Layout';
import ProtectedRoute from './components/auth/ProtectedRoute';
import OnboardingGuard from './components/auth/OnboardingGuard';
import ConditionalRedirect from './components/auth/ConditionalRedirect';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Policies from './pages/Policies';
import Workloads from './pages/Workloads';
import AccessEvents from './pages/AccessEvents';
import GraphPage from './pages/GraphPage';
import Templates from './pages/Templates';
import Operations from './pages/Operations';
import DemoFlow from './pages/DemoFlow';
import Connectors from './pages/Connectors';
import Compliance from './pages/Compliance';

function App() {
  return (
    <Router>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'var(--surface-3)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border)',
            fontSize: '13px',
            fontFamily: 'DM Sans, sans-serif',
          },
        }}
      />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            {/* Connectors is always accessible (onboarding landing page) */}
            <Route path="connectors" element={<Connectors />} />
            {/* All other routes require at least one connector */}
            <Route element={<OnboardingGuard />}>
              <Route index element={<ConditionalRedirect />} />
              <Route path="workloads" element={<Workloads />} />
              <Route path="policies" element={<Policies />} />
              <Route path="access" element={<AccessEvents />} />
              <Route path="graph" element={<GraphPage />} />
              {/* Hidden from nav but still routable for direct links */}
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="compliance" element={<Compliance />} />
              <Route path="templates" element={<Templates />} />
              <Route path="operations" element={<Operations />} />
              <Route path="demo" element={<DemoFlow />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
