import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// Simple embedded custom SVG components to avoid imports issues and keep look premium
const DashboardIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>
);

const RepositoriesIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
);

const ScaIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
);

const ComplianceIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
);

const SettingsIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
);

const ShieldIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
);

const LogoutIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
);

export const Sidebar = () => {
  const { user, logout } = useAuth();

  return (
    <aside className="app-sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">
          <ShieldIcon />
        </div>
        <h1 className="logo-text">Idea<span>Nova</span></h1>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Operations</div>
        <div className="nav-links">
          <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} end>
            <div className="nav-icon"><DashboardIcon /></div>
            <span>Dashboard</span>
          </NavLink>
          <NavLink to="/repositories" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <div className="nav-icon"><RepositoriesIcon /></div>
            <span>Repositories</span>
          </NavLink>
          <NavLink to="/sca" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <div className="nav-icon"><ScaIcon /></div>
            <span>SCA Scan</span>
          </NavLink>
        </div>

        <div className="nav-section-title">Compliance & Config</div>
        <div className="nav-links">
          <NavLink to="/compliance" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <div className="nav-icon"><ComplianceIcon /></div>
            <span>Compliance Hub</span>
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
            <div className="nav-icon"><SettingsIcon /></div>
            <span>Key Rotation</span>
          </NavLink>
        </div>
      </nav>

      {user && (
        <div className="sidebar-footer">
          <div className="user-badge">
            <div className="user-avatar">
              {user.avatarLetter}
            </div>
            <div className="user-info">
              <div className="user-name">{user.username}</div>
              <div className="user-role-badge">{user.role}</div>
            </div>
            <button className="logout-btn-icon" onClick={logout} title="Log Out">
              <LogoutIcon />
            </button>
          </div>
        </div>
      )}
    </aside>
  );
};

export default Sidebar;
