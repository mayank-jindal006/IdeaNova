import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useSystemData } from '../context/SystemDataContext';
import { useAuth } from '../context/AuthContext';

// Simple SVGs
const BackIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
);
const TerminalIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
);
const GitMergeIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 15V9a4 4 0 0 0-4-4H9"/><line x1="6" y1="9" x2="6" y2="15"/></svg>
);
const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
);

export const RepositoryDetail = ({ repoId }) => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const { 
    repositories, 
    secrets, 
    prs, 
    scanLogs,
    runSecurityScan, 
    triggerAiFix, 
    mergePr, 
    markAsFalsePositive 
  } = useSystemData();

  // Find target repository
  const repo = repositories.find(r => r.id === repoId);
  const repoSecrets = secrets.filter(s => s.repoId === repoId);
  
  // States
  const [selectedSecretId, setSelectedSecretId] = useState('');
  const consoleEndRef = useRef(null);

  // Auto-select first secret if none is selected
  useEffect(() => {
    if (repoSecrets.length > 0 && !selectedSecretId) {
      // Find first exposed or fixing secret, otherwise first resolved
      const active = repoSecrets.find(s => s.status === 'exposed' || s.status === 'fixing');
      if (active) {
        setSelectedSecretId(active.id);
      } else {
        setSelectedSecretId(repoSecrets[0].id);
      }
    }
  }, [repoSecrets, selectedSecretId]);

  // Handle URL query parameters for PR reviews (from dashboard click)
  useEffect(() => {
    const queryPrId = searchParams.get('prId');
    if (queryPrId) {
      const targetPr = prs.find(p => p.id === queryPrId);
      if (targetPr && targetPr.repoId === repoId) {
        setSelectedSecretId(targetPr.issueId);
      }
    }
  }, [searchParams, prs, repoId]);

  // Scroll terminal logs to bottom
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs, repo?.scanningStatus]);

  if (!repo) {
    return <div style={{ color: 'var(--color-danger)' }}>Repository not found.</div>;
  }

  const selectedSecret = repoSecrets.find(s => s.id === selectedSecretId);
  const logs = scanLogs[repoId] || [];
  
  // Find linked open PR if state is fixing
  const linkedPr = prs.find(p => p.issueId === selectedSecretId && p.status === 'open');

  const handleScanTrigger = () => {
    runSecurityScan(repoId);
  };

  const handleCreatePr = () => {
    if (selectedSecret) {
      triggerAiFix(selectedSecret.id);
    }
  };

  const handleMergePr = () => {
    if (linkedPr) {
      mergePr(linkedPr.id);
    }
  };

  const handleIgnore = () => {
    if (selectedSecret) {
      markAsFalsePositive(selectedSecret.id);
    }
  };

  return (
    <div className="animate-fade-in">
      {/* Detail Header */}
      <div className="repo-header">
        <div className="repo-title-wrapper">
          <button 
            className="btn-secondary" 
            style={{ alignSelf: 'flex-start', padding: '5px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '10px' }}
            onClick={() => navigate('/repositories')}
          >
            <BackIcon /> Back to Repositories
          </button>
          <h3 style={{ fontSize: '24px', fontWeight: '800' }}>{repo.name}</h3>
          <div className="repo-meta-list">
            <span className="repo-meta-item">
              Language: <strong style={{ color: 'var(--text-primary)' }}>{repo.language}</strong>
            </span>
            <span className="repo-meta-item">
              Branch: <code style={{ background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px' }}>{repo.branch}</code>
            </span>
            <span className="repo-meta-item">
              Risk: <span className={`status-badge ${repo.riskLevel}`} style={{ padding: '2px 8px' }}>{repo.riskLevel.toUpperCase()}</span>
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div className="repo-score-badge">
            <span className="score-number">{repo.complianceScore}%</span>
            <span className="score-label">Compliance<br/>Rating</span>
          </div>
          {user?.role !== 'CISO' && (
            <button 
              className="btn-primary" 
              onClick={handleScanTrigger}
              disabled={repo.scanningStatus === 'scanning'}
            >
              {repo.scanningStatus === 'scanning' ? 'Scanning...' : 'Trigger Scan'}
            </button>
          )}
        </div>
      </div>

      {/* If scanning, show terminal simulator */}
      {repo.scanningStatus === 'scanning' && (
        <div className="glass-panel animate-fade-in" style={{ marginBottom: '25px' }}>
          <div className="glass-panel-header" style={{ marginBottom: '10px' }}>
            <span className="panel-title" style={{ color: 'var(--color-primary)' }}>
              <TerminalIcon /> Static Analysis Execution Console
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px', flex: '1', justifyContent: 'flex-end', paddingRight: '15px' }}>
              <div className="progress-bar-container" style={{ margin: 0 }}>
                <div className="progress-bar-fill" style={{ width: `${repo.scanProgress}%` }}></div>
              </div>
              <span style={{ fontSize: '12px', fontWeight: 'bold' }}>{repo.scanProgress}%</span>
            </div>
          </div>
          <div className="console-view">
            {logs.map((line, idx) => {
              let lineClass = 'info';
              if (line.includes('[WARN]')) lineClass = 'warn';
              if (line.includes('[SUCCESS]')) lineClass = 'success';
              return (
                <div key={idx} className={`console-line ${lineClass}`}>
                  {line}
                </div>
              );
            })}
            <div ref={consoleEndRef} />
          </div>
        </div>
      )}

      {/* Master Detail Split layout */}
      <div className="detail-layout-grid">
        {/* Left Column: Secrets exposed list */}
        <div>
          <h4 className="section-sub-title" style={{ marginTop: '0', marginBottom: '12px' }}>Secrets Scanning Findings</h4>
          {repoSecrets.length === 0 ? (
            <div className="glass-panel" style={{ padding: '30px', textAlign: 'center' }}>
              <span className="status-badge safe" style={{ padding: '8px 16px', fontSize: '13px', marginBottom: '15px' }}>
                No Leaked Credentials Found
              </span>
              <p style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                Run security scans to ingestion code histories and audit signatures.
              </p>
            </div>
          ) : (
            repoSecrets.map(sec => (
              <div 
                key={sec.id}
                className={`finding-item-row ${selectedSecretId === sec.id ? 'selected' : ''}`}
                onClick={() => setSelectedSecretId(sec.id)}
              >
                <div className="finding-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={`status-badge ${sec.severity}`}>
                      {sec.severity.toUpperCase()}
                    </span>
                    <span className="finding-title">{sec.type}</span>
                  </div>
                  <span className="finding-file-path">{sec.filePath}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px' }}>
                  <span className={`status-badge ${sec.status === 'exposed' ? 'critical' : sec.status === 'fixing' ? 'pending' : sec.status === 'resolved' ? 'resolved' : 'pending'}`} style={{ fontSize: '10px' }}>
                    {sec.status === 'exposed' ? 'EXPOSED' : sec.status === 'fixing' ? 'FIX PENDING' : sec.status === 'resolved' ? 'SECURED' : 'FALSE POSITIVE'}
                  </span>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{sec.dateFound}</span>
                </div>
              </div>
            ))
          )}

          {/* Past Scan console dump summary */}
          {logs.length > 0 && repo.scanningStatus === 'idle' && (
            <div className="glass-panel" style={{ marginTop: '25px' }}>
              <div className="glass-panel-header" style={{ marginBottom: '10px' }}>
                <span className="panel-title" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                  <TerminalIcon /> Last Audit Execution Logs
                </span>
                <button 
                  className="preset-btn" 
                  style={{ fontSize: '10px', padding: '3px 8px' }}
                  onClick={() => navigate(`/repositories`)}
                >
                  Clear Logs
                </button>
              </div>
              <div className="console-view" style={{ height: '140px', fontSize: '10px', padding: '10px' }}>
                {logs.slice(-5).map((line, idx) => (
                  <div key={idx} className="console-line info" style={{ color: 'var(--text-secondary)' }}>
                    {line}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: AI Remediation Wizard */}
        <div>
          <h4 className="section-sub-title" style={{ marginTop: '0', marginBottom: '12px' }}>AI Explain & Fix Wizard</h4>
          {selectedSecret ? (
            <div className="explain-fix-panel">
              <div className="explain-fix-header">
                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: '700' }}>{selectedSecret.type}</h3>
                  <code style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>ID: {selectedSecret.id} | Hash: {selectedSecret.commitHash}</code>
                </div>
                <span className={`status-badge ${selectedSecret.severity}`}>
                  {selectedSecret.severity.toUpperCase()}
                </span>
              </div>

              {selectedSecret.status === 'exposed' && (
                <div className="risk-alert-box animate-fade-in">
                  <div className="risk-alert-title">CRITICAL RISK FACTOR</div>
                  <p style={{ fontSize: '12px', lineHeight: '1.4' }}>
                    Credential committed in plaintext. Bots will scrape and compromise access within minutes.
                  </p>
                </div>
              )}

              {selectedSecret.status === 'fixing' && (
                <div className="risk-alert-box animate-fade-in" style={{ background: 'rgba(0, 240, 255, 0.05)', borderColor: 'rgba(0,240,255,0.2)' }}>
                  <div className="risk-alert-title" style={{ color: 'var(--color-primary)' }}>AUTO-FIX BRANCH GENERATED</div>
                  <p style={{ fontSize: '12px', lineHeight: '1.4', color: 'var(--text-primary)' }}>
                    Copilot has opened a pull request to move credentials to environment variables. Merge the PR below to secure the codebase.
                  </p>
                </div>
              )}

              {selectedSecret.status === 'resolved' && (
                <div className="risk-alert-box animate-fade-in" style={{ background: 'rgba(57, 211, 83, 0.05)', borderColor: 'rgba(57,211,83,0.2)' }}>
                  <div className="risk-alert-title" style={{ color: 'var(--color-success)' }}>VULNERABILITY RESOLVED</div>
                  <p style={{ fontSize: '12px', lineHeight: '1.4', color: 'var(--text-primary)' }}>
                    Hardcoded secret was scrubbed and configuration refactored to consume secret manager environment flags.
                  </p>
                </div>
              )}

              <h4 className="section-sub-title">AI Exposure Analysis</h4>
              <p className="ai-explanation-text">
                {selectedSecret.explanation}
              </p>

              <h4 className="section-sub-title">Proposed Remediated Patch ({selectedSecret.filePath})</h4>
              <div className="diff-viewer">
                {selectedSecret.diff.map((line, idx) => (
                  <div key={idx} className={`diff-line ${line.type}`}>
                    <span className="diff-line-num">{line.line}</span>
                    <span>{line.content}</span>
                  </div>
                ))}
              </div>

              {/* Action Buttons depending on status */}
              <div className="panel-action-footer">
                {selectedSecret.status === 'exposed' && (
                  <>
                    {user?.role !== 'CISO' && (
                      <button className="btn-primary" onClick={handleCreatePr}>
                        AI Auto-Fix: Create PR
                      </button>
                    )}
                    {user?.role === 'Security Engineer' && (
                      <button className="btn-secondary" onClick={handleIgnore}>
                        Ignore
                      </button>
                    )}
                    <button className="btn-secondary" onClick={() => navigate('/settings')}>
                      Rotate Credentials
                    </button>
                  </>
                )}

                {selectedSecret.status === 'fixing' && (
                  <>
                    {user?.role !== 'CISO' && linkedPr && (
                      <button className="btn-primary" onClick={handleMergePr} style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'linear-gradient(135deg, #2ea44f 0%, #22863a 100%)', color: '#fff', boxShadow: 'none' }}>
                        <GitMergeIcon /> Merge Auto-Fix PR
                      </button>
                    )}
                    <button className="btn-secondary" onClick={() => navigate('/settings')}>
                      Configure Vault Rotation
                    </button>
                  </>
                )}

                {selectedSecret.status === 'resolved' && (
                  <span style={{ color: 'var(--color-success)', fontWeight: '700', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckIcon /> Patched applied. Repository compliance score improved.
                  </span>
                )}
                
                {selectedSecret.status === 'false_positive' && (
                  <span style={{ color: 'var(--text-secondary)', fontWeight: '600', fontSize: '13px' }}>
                    Marked as Safe (Ignored). Scan exception active.
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div className="glass-panel" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-secondary)' }}>
              Select a vulnerability finding to inspect the Exposure Analysis and run remediation scripts.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RepositoryDetail;
