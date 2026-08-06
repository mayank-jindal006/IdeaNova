import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSystemData } from '../context/SystemDataContext';
import { useAuth } from '../context/AuthContext';
import RepositoryDetail from './RepositoryDetail';

// Simple Icons
const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
);
const TerminalIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
);

export const Repositories = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const repoId = searchParams.get('id');

  const { user } = useAuth();
  const { repositories, secrets, vulnerabilities, runSecurityScan, scanLogs } = useSystemData();

  // If a repository id is present in url, show details screen
  if (repoId) {
    return <RepositoryDetail repoId={repoId} />;
  }

  const handleScanTrigger = (id, e) => {
    e.stopPropagation(); // Avoid triggering card navigation
    runSecurityScan(id);
  };

  const selectRepository = (id) => {
    setSearchParams({ id });
  };

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '25px' }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Integrate, scan, and manage compliance pipelines across repositories. Propose LLM patches to seal exposed keys.
        </p>
      </div>

      {/* Grid of Repositories */}
      <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        {repositories.map(repo => {
          // Count active secrets findings
          const repoSecretsCount = secrets.filter(s => s.repoId === repo.id && (s.status === 'exposed' || s.status === 'fixing')).length;
          // Count active CVE vulnerabilities
          const repoCVEsCount = vulnerabilities.filter(v => v.repoId === repo.id).length;

          const isScanning = repo.scanningStatus === 'scanning';

          return (
            <div 
              key={repo.id}
              className="glass-panel"
              style={{ 
                cursor: 'pointer',
                borderColor: isScanning ? 'var(--color-primary)' : 'var(--border-color)',
                transition: 'var(--transition-smooth)'
              }}
              onClick={() => selectRepository(repo.id)}
            >
              {/* Card Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '15px' }}>
                <div>
                  <h4 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)' }}>{repo.name}</h4>
                  <div style={{ display: 'flex', gap: '6px', marginTop: '6px', alignItems: 'center' }}>
                    <span className="repo-lang-badge">{repo.language}</span>
                    <span className={`status-badge ${repo.riskLevel}`} style={{ fontSize: '9px', padding: '1px 6px' }}>
                      {repo.riskLevel.toUpperCase()} RISK
                    </span>
                  </div>
                </div>

                <div className="score-circle-wrapper" style={{ border: '2px solid rgba(255,255,255,0.05)', borderRadius: '50%', padding: '6px' }}>
                  <span className="score-text" style={{ fontSize: '11px', color: repo.complianceScore > 75 ? 'var(--color-success)' : repo.complianceScore > 50 ? 'var(--color-warning)' : 'var(--color-danger)' }}>
                    {repo.complianceScore}%
                  </span>
                </div>
              </div>

              {/* Scan status overlay if active */}
              {isScanning ? (
                <div className="animate-fade-in" style={{ marginBottom: '15px', background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '8px', border: '1px dashed var(--border-color-glow)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '5px' }}>
                    <span style={{ color: 'var(--color-primary)', fontWeight: 'bold' }}>Executing static scan...</span>
                    <span>{repo.scanProgress}%</span>
                  </div>
                  <div className="progress-bar-container" style={{ margin: 0, height: '6px', maxWidth: '100%' }}>
                    <div className="progress-bar-fill" style={{ width: `${repo.scanProgress}%` }}></div>
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '15px', borderBottom: '1px dashed rgba(255,255,255,0.05)', paddingBottom: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span>Active exposed credentials:</span>
                    <strong style={{ color: repoSecretsCount > 0 ? 'var(--color-danger)' : 'var(--color-success)' }}>{repoSecretsCount}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Outdated package CVEs:</span>
                    <strong style={{ color: repoCVEsCount > 0 ? 'var(--color-warning)' : 'var(--color-success)' }}>{repoCVEsCount}</strong>
                  </div>
                </div>
              )}

              {/* Commit info */}
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '20px', wordBreak: 'break-all' }}>
                <strong>Last Commit:</strong> {repo.lastCommit}
                <div style={{ marginTop: '2px' }}>{repo.commitDate}</div>
              </div>

              {/* Actions Footer */}
              <div style={{ display: 'flex', gap: '10px' }}>
                <button 
                  className="btn-secondary"
                  style={{ flex: 1, padding: '7px 0', fontSize: '12px' }}
                  onClick={() => selectRepository(repo.id)}
                >
                  Audit Code & PRs
                </button>
                {user?.role !== 'CISO' && (
                  <button 
                    className="btn-primary"
                    style={{ flex: 1, padding: '7px 0', fontSize: '12px' }}
                    onClick={(e) => handleScanTrigger(repo.id, e)}
                    disabled={isScanning}
                  >
                    {isScanning ? 'Running...' : 'Trigger Scan'}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* General Terminal Console simulation (shows if any scanning occurs) */}
      {repositories.some(r => r.scanningStatus === 'scanning') && (
        <div className="glass-panel animate-fade-in" style={{ marginTop: '30px' }}>
          <div className="glass-panel-header">
            <span className="panel-title" style={{ color: 'var(--color-primary)' }}>
              <TerminalIcon /> Running Scopes Global Engine Monitor
            </span>
          </div>
          <div className="console-view" style={{ height: '150px' }}>
            {repositories.filter(r => r.scanningStatus === 'scanning').map(repo => {
              const logs = scanLogs[repo.id] || [];
              return (
                <div key={repo.id}>
                  <div style={{ color: 'var(--color-primary)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '3px', marginBottom: '5px' }}>
                    --- Ingestion Stream: {repo.name} ({repo.scanProgress}%) ---
                  </div>
                  {logs.slice(-3).map((line, idx) => (
                    <div key={idx} className="console-line">
                      {line}
                    </div>
                  ))}
                  <div style={{ height: '10px' }} />
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default Repositories;
