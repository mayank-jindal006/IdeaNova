import React from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldIcon, DashboardIcon, RepoIcon, RefreshCwIcon } from './icons';
import { useRepoGuard } from '../context/RepoGuardContext';

export const Sidebar = () => {
  const { metrics, resetAllData } = useRepoGuard();

  const handleReset = (e) => {
    e.preventDefault();
    if (window.confirm("Reset all repositories, findings, and scan histories to clean initial defaults?")) {
      resetAllData();
    }
  };

  return (
    <aside className="app-sidebar">
      <div className="sidebar-brand">
        <div className="brand-logo-box">
          <ShieldIcon size={20} className="brand-logo-icon" />
        </div>
        <div className="brand-text-block">
          <span className="brand-name">RepoGuard</span>
          <span className="brand-badge">SecOps Console</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-group-label">Core Operations</div>
        
        <NavLink
          to="/"
          end
          className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
        >
          <DashboardIcon size={16} />
          <span>Dashboard</span>
        </NavLink>

        <NavLink
          to="/repositories"
          className={({ isActive }) => `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
        >
          <RepoIcon size={16} />
          <span>Repositories</span>
          <span className="nav-counter">{metrics.totalRepos}</span>
        </NavLink>
      </nav>

      <div className="sidebar-footer">
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
          title="Reset demo data to initial state"
        >
          <RefreshCwIcon size={12} />
          <span>Reset Demo Data</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
