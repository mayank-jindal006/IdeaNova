import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSystemData } from '../context/SystemDataContext';

export const Header = () => {
  const location = useLocation();
  const { user, switchRole } = useAuth();
  const { repositories } = useSystemData();

  // Theme logic
  const [theme, setTheme] = useState(localStorage.getItem('ideanova_theme') || 'dark');

  useEffect(() => {
    if (theme === 'light') {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
    localStorage.setItem('ideanova_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

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

        {/* Theme Switcher Button */}
        <button 
          onClick={toggleTheme}
          style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid var(--border-color)',
            color: 'var(--text-primary)',
            fontSize: '15px',
            cursor: 'pointer',
            padding: '5px 12px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'var(--transition-fast)',
          }}
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>

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
