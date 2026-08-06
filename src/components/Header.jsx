import React from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSystemData } from '../context/SystemDataContext';

export const Header = () => {
  const location = useLocation();
  const { user, switchRole } = useAuth();
  const { repositories } = useSystemData();

  // Find if any repository is currently scanning
  const isAnyScanning = repositories.some(r => r.scanningStatus === 'scanning');

  // Convert pathname to readable page title
  const getPageTitle = () => {
    const path = location.pathname;
    if (path === '/') return 'Team Risk Dashboard';
    if (path.startsWith('/repositories')) return 'Repository Security Audits';
    if (path === '/sca') return 'Software Composition Analysis (SCA)';
    if (path === '/compliance') return 'OWASP & ASVS Compliance Center';
    if (path === '/settings') return 'Vault & Key Rotation Settings';
    return 'IdeaNova Security Copilot';
  };

  const handleRoleChange = (role) => {
    switchRole(role);
  };

  return (
    <header className="app-header">
      <div className="header-title-area">
        <h2 className="page-title">{getPageTitle()}</h2>
      </div>

      <div className="header-actions">
        {isAnyScanning ? (
          <div className="system-status-indicator">
            <span className="status-dot scanning"></span>
            <span>Running security scanner...</span>
          </div>
        ) : (
          <div className="system-status-indicator">
            <span className="status-dot"></span>
            <span>System Secure (Static Analysis Idle)</span>
          </div>
        )}

        {user && (
          <div className="role-quick-switcher">
            <button 
              className={`role-switcher-btn ${user.role === 'Developer' ? 'active' : ''}`}
              onClick={() => handleRoleChange('Developer')}
            >
              Developer
            </button>
            <button 
              className={`role-switcher-btn ${user.role === 'Security Engineer' ? 'active' : ''}`}
              onClick={() => handleRoleChange('Security Engineer')}
            >
              SecOps
            </button>
            <button 
              className={`role-switcher-btn ${user.role === 'CISO' ? 'active' : ''}`}
              onClick={() => handleRoleChange('CISO')}
            >
              CISO
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default Header;
