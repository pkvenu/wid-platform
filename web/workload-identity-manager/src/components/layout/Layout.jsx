import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

const Layout = () => {
  const [isCollapsed, setIsCollapsed] = useState(true); // collapsed by default

  return (
    <div className="min-h-screen bg-surface-1">
      <Sidebar isCollapsed={isCollapsed} onToggleCollapse={setIsCollapsed} />

      <div
        className="transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]"
        style={{ marginLeft: isCollapsed ? 56 : 240 }}
      >
        <div
          className="fixed top-0 right-0 z-40 transition-all duration-300"
          style={{ left: isCollapsed ? 56 : 240 }}
        >
          <Header />
        </div>

        <main className="pt-14">
          <div className="p-7">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

export default Layout;