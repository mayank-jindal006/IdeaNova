import React from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldIcon, DashboardIcon, RepoIcon, RefreshCwIcon, PackageIcon, ClockIcon } from './icons';
import { useRepoGuard } from '../context/useRepoGuard';

export const Sidebar = ({ mobileOpen, collapsed, onClose, onToggle }) => {
  const { metrics, resetAllData, user, logout } = useRepoGuard();

  const handleReset = (e) => {
    e.preventDefault();
    if (window.confirm("Refresh repositories, findings, and scan history from the security service?")) {
      resetAllData();
    }
  };

  return (
    <>
    {mobileOpen && <button type="button" aria-label="Close navigation" className="sidebar-scrim" onClick={onClose} />}
    <aside className={`app-sidebar ${mobileOpen ? 'sidebar-open' : ''} ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <div className="sidebar-brand">
        <div className="brand-logo-box">
          <ShieldIcon size={20} className="brand-logo-icon" />
        </div>
        <div className="brand-text-block">
          <span className="brand-name">RepoGuard</span>
          <span className="brand-badge">SecOps Console</span>
        </div>
        <button type="button" className="sidebar-collapse" aria-label="Toggle sidebar" onClick={onToggle}>‹</button>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-group-label">Core Operations</div>
        
        <NavLink
          to="/" onClick={onClose}
          end
          className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
        >
          <DashboardIcon size={16} />
          <span>Dashboard</span>
        </NavLink>

        <div className="nav-group-label">Commerce</div>
        <NavLink to="/catalog" onClick={onClose} className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}>
          <PackageIcon size={16} />
          <span>Catalog</span>
        </NavLink>

        <NavLink
          to="/repositories" onClick={onClose}
          className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
        >
          <RepoIcon size={16} />
          <span>Repositories</span>
          <span className="nav-counter">{metrics.totalRepos}</span>
        </NavLink>
        <NavLink to="/activity" onClick={onClose} className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}>
          <ClockIcon size={16} />
          <span>Security Activity</span>
        </NavLink>
      </nav>

      <div className="sidebar-footer">
        <div className="text-xs text-secondary" title={user?.email}>{user?.email}</div>
        <div className="sidebar-telemetry">
          <div className="telemetry-item">
            <span className="telemetry-label">Active Exposures</span>
            <span className={`telemetry-val ${metrics.activeFindingsCount > 0 ? 'text-danger' : 'text-success'}`}>
              {metrics.activeFindingsCount}
            </span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">Avg Compliance</span>
            <span className="telemetry-val text-mono">{metrics.avgCompliance}%</span>
          </div>
        </div>

        <button 
          className="sidebar-reset-btn" 
          onClick={handleReset}
          title="Refresh persistent security data"
        >
          <RefreshCwIcon size={12} />
          <span>Refresh Security Data</span>
        </button>
        <button className="sidebar-reset-btn" onClick={logout} title="Sign out of RepoGuard">
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
