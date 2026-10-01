import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldIcon, DashboardIcon, RepoIcon, RefreshCwIcon } from './icons';
import api from '../api/client';

export const Sidebar = () => {
  const [stats, setStats] = useState({
    totalRepos: null,
    activeFindings: null,
    avgCompliance: null
  });

  const loadStats = async () => {
    try {
      const summary = await api.getDashboardSummary();
      if (summary) {
        const totalRepos = summary.totals?.repos ?? 0;
        const totalFindings = summary.totals?.findings ?? 0;
        const scores = summary.repo_scores || [];
        const avgComp = scores.length > 0
          ? Math.round(scores.reduce((a, b) => a + (b.compliance_score || 0), 0) / scores.length)
          : null;

        setStats({
          totalRepos,
          activeFindings: totalFindings,
          avgCompliance: avgComp
        });
      }
    } catch {
      // API unreachable
    }
  };

  useEffect(() => {
    loadStats();
    const timer = setInterval(loadStats, 10000);
    return () => clearInterval(timer);
  }, []);

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
          {stats.totalRepos != null && (
            <span className="nav-counter">{stats.totalRepos}</span>
          )}
        </NavLink>
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-telemetry">
          <div className="telemetry-item">
            <span className="telemetry-label">Active Exposures</span>
            <span className={`telemetry-val ${stats.activeFindings > 0 ? 'text-danger' : stats.activeFindings === 0 ? 'text-success' : 'text-muted'}`}>
              {stats.activeFindings != null ? stats.activeFindings : '—'}
            </span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">Avg Compliance</span>
            <span className="telemetry-val text-mono">
              {stats.avgCompliance != null ? `${stats.avgCompliance}%` : '—'}
            </span>
          </div>
        </div>

        <button 
          className="sidebar-reset-btn" 
          onClick={loadStats}
          title="Refresh security telemetry"
        >
          <RefreshCwIcon size={12} />
          <span>Refresh Telemetry</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
