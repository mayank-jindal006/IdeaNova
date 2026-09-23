import React from 'react';
import { useSystemData } from '../context/SystemDataContext';
import { useAuth } from '../context/AuthContext';

// Simple Icons
const RotateIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
);

export const Settings = () => {
  const { user } = useAuth();
  const { integrations, rotateIntegrationKey } = useSystemData();

  const handleRotate = (id) => {
    rotateIntegrationKey(id);
  };

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '25px' }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Connect third-party API providers and Secret Managers. RepoGuard triggers automated revocation and key-rotation API requests to secure leaked credentials at the root provider.
        </p>
      </div>

      <div className="content-grid-2col" style={{ gridTemplateColumns: '3fr 2fr' }}>
        {/* Left Column: Integrations List */}
        <div className="glass-panel">
          <div className="glass-panel-header">
            <h4 className="panel-title">Active Rotation Integrations</h4>
            <span className="status-badge safe" style={{ fontSize: '10px' }}>
              Webhooks Configured
            </span>
          </div>

          <div className="credentials-grid">
            {integrations.map(integ => {
              const isPending = integ.status === 'pending';

              return (
                <div key={integ.id} className="credential-card">
                  <div className="cred-header">
                    <div className="cred-provider-logo">
                      {integ.type.toUpperCase()}
                    </div>
                    <div className="cred-name-area">
                      <span className="cred-title">{integ.name}</span>
                      <span className="cred-status-indicator">
                        <span className={`status-dot ${isPending ? 'scanning' : ''}`} style={{ background: integ.status === 'configured' ? 'var(--color-success)' : integ.status === 'pending' ? 'var(--color-primary)' : 'var(--text-muted)' }}></span>
                        {integ.status === 'configured' ? 'Connected' : integ.status === 'pending' ? 'Rotating Keys...' : 'Setup Pending'}
                      </span>
                    </div>
                  </div>

                  <p className="cred-body">
                    {integ.description}
                  </p>

                  <div style={{ fontSize: '12px' }}>
                    <div className="cred-meta-row">
                      <span className="cred-meta-label">Managed Keys</span>
                      <span className="cred-meta-value">{integ.activeKeysCount} tokens</span>
                    </div>
                    <div className="cred-meta-row" style={{ border: 'none', marginBottom: '0' }}>
                      <span className="cred-meta-label">Last Rotation Request</span>
                      <span className="cred-meta-value">{integ.lastRotation}</span>
                    </div>
                  </div>

                  <div className="cred-actions">
                    {user?.role === 'Security Engineer' ? (
                      <button 
                        className="btn-primary" 
                        style={{ padding: '6px 12px', fontSize: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                        onClick={() => handleRotate(integ.id)}
                        disabled={isPending}
                      >
                        <RotateIcon /> {isPending ? 'Rotating API...' : 'Rotate Key Now'}
                      </button>
                    ) : (
                      <button className="btn-secondary" disabled style={{ fontSize: '12px', width: '100%' }}>
                        Requires SecOps Role to Rotate
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Information panel & settings */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '25px' }}>
          <div className="glass-panel">
            <h4 className="panel-title" style={{ marginBottom: '12px' }}>Rotation-Aware Security Loop</h4>
            <p className="ai-explanation-text" style={{ fontSize: '13px', lineHeight: '1.6' }}>
              Sealing a secret in a Git commit history is only 50% of the job. Once a secret is exposed, it must be considered compromised. 
              <br/><br/>
              RepoGuard automatically hooks into cloud provider endpoints (e.g. AWS IAM API or Stripe Revoke Keys API) to:
            </p>
            <ol style={{ paddingLeft: '20px', fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <li>Generate a replacement token in the provider dashboard.</li>
              <li>Inject the new token as an environment variable in target server instances (Vercel, AWS ECS, Heroku).</li>
              <li>Revoke the exposed key.</li>
              <li>Scan the repository to ensure no other code references the revoked credentials.</li>
            </ol>
          </div>

          <div className="glass-panel">
            <h4 className="panel-title" style={{ marginBottom: '12px' }}>API Configurations</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              <div>
                <label className="auth-label" style={{ fontSize: '11px' }}>Global Webhook Endpoint</label>
                <input 
                  type="text" 
                  className="auth-input" 
                  value="https://api.ideanova.secops.io/v1/webhooks/github" 
                  readOnly 
                  style={{ background: 'rgba(0,0,0,0.4)', fontSize: '12px' }}
                />
              </div>

              <div>
                <label className="auth-label" style={{ fontSize: '11px' }}>LLM Fix Automation Context</label>
                <select className="auth-input" disabled style={{ background: 'rgba(0,0,0,0.4)', fontSize: '12px' }}>
                  <option>Claude-3.5-Sonnet (Production-Grade Fixes)</option>
                  <option>Gemini-1.5-Pro (Long-context repository fix)</option>
                </select>
              </div>

              <div>
                <label className="auth-label" style={{ fontSize: '11px' }}>Scan Frequency Profiles</label>
                <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
                  <span className="repo-lang-badge" style={{ color: 'var(--color-primary)', borderColor: 'var(--color-primary)' }}>On push & PR (Default)</span>
                  <span className="repo-lang-badge">Hourly cron</span>
                  <span className="repo-lang-badge">Daily clean</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
