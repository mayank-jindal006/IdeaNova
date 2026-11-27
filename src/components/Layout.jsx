import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export const Layout = () => {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  return (
    <div className={`app-shell ${collapsed ? 'shell-collapsed' : ''}`}>
      <Sidebar mobileOpen={navigationOpen} collapsed={collapsed} onClose={() => setNavigationOpen(false)} onToggle={() => setCollapsed((value) => !value)} />
      <div className="app-main">
        <div className="mobile-topbar">
          <button type="button" className="icon-button" aria-label="Open navigation" onClick={() => setNavigationOpen(true)}>☰</button>
          <span className="mobile-brand">RepoGuard</span>
        </div>
        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
