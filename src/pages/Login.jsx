import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ShieldIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
);

export const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [selectedRole, setSelectedRole] = useState('Developer');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    const res = login(username, password, selectedRole);
    if (res.success) {
      navigate('/');
    } else {
      setError(res.message);
    }
  };

  const loadPreset = (name, role) => {
    setUsername(name);
    setPassword('••••••••');
    setSelectedRole(role);
  };

  return (
    <div className="auth-container">
      <div className="auth-background-effects">
        <div className="auth-glow-circle-1"></div>
        <div className="auth-glow-circle-2"></div>
      </div>

      <div className="auth-card">
        <div className="auth-logo-section">
          <div className="auth-logo">
            <ShieldIcon />
          </div>
          <h2 className="auth-title">IdeaNova DevOps Copilot</h2>
          <p className="auth-subtitle">AI-Driven Secure Code Ingestion & Remediation</p>
        </div>

        {error && (
          <div className="risk-alert-box" style={{ marginTop: '0', marginBottom: '20px' }}>
            <div className="risk-alert-title">Authentication Failed</div>
            <p style={{ fontSize: '12px' }}>{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="auth-form-group">
            <label className="auth-label">Username</label>
            <input 
              type="text" 
              className="auth-input" 
              placeholder="e.g. alex_secops" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="auth-form-group">
            <label className="auth-label">Password</label>
            <input 
              type="password" 
              className="auth-input" 
              placeholder="••••••••" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <div className="auth-form-group">
            <label className="auth-label">System Role Access</label>
            <div className="role-selector-grid">
              <div 
                className={`role-option ${selectedRole === 'Developer' ? 'active' : ''}`}
                onClick={() => setSelectedRole('Developer')}
              >
                <span className="role-name">Developer</span>
                <span className="role-desc">Fix & PRs</span>
              </div>
              <div 
                className={`role-option ${selectedRole === 'Security Engineer' ? 'active' : ''}`}
                onClick={() => setSelectedRole('Security Engineer')}
              >
                <span className="role-name">SecOps</span>
                <span className="role-desc">Full Admin</span>
              </div>
              <div 
                className={`role-option ${selectedRole === 'CISO' ? 'active' : ''}`}
                onClick={() => setSelectedRole('CISO')}
              >
                <span className="role-name">CISO</span>
                <span className="role-desc">Analytics</span>
              </div>
            </div>
          </div>

          <button type="submit" className="auth-btn">
            Authenticate Device
          </button>
        </form>

        <div className="auth-preset-hints">
          <p className="preset-title">Or auto-fill demonstration profile:</p>
          <div className="preset-buttons">
            <button 
              className="preset-btn"
              onClick={() => loadPreset('dev_alice', 'Developer')}
            >
              Developer Alice
            </button>
            <button 
              className="preset-btn"
              onClick={() => loadPreset('sam_secops', 'Security Engineer')}
            >
              SecOps Sam
            </button>
            <button 
              className="preset-btn"
              onClick={() => loadPreset('ciso_clara', 'CISO')}
            >
              CISO Clara
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
