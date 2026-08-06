import React, { useState } from 'react';
import { useSystemData } from '../context/SystemDataContext';
import { useAuth } from '../context/AuthContext';

// Simple Icons
const InfoIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
);
const TerminalIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
);

export const ScaScan = () => {
  const { user } = useAuth();
  const { vulnerabilities, repositories, upgradeDependency } = useSystemData();
  const [selectedVulnId, setSelectedVulnId] = useState('');

  const selectedVuln = vulnerabilities.find(v => v.id === selectedVulnId);

  const handleUpgrade = (id) => {
    upgradeDependency(id);
    if (selectedVulnId === id) {
      setSelectedVulnId('');
    }
  };

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '25px' }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Monitor third-party dependencies for known vulnerabilities (CVEs) pulled from the Open Source Vulnerability (OSV.dev) database.
        </p>
      </div>

      <div className="content-grid-2col">
        {/* Left Column: Vulnerabilities list */}
        <div className="glass-panel">
          <div className="glass-panel-header">
            <h4 className="panel-title">Outdated Third-Party Packages</h4>
            <span className="status-badge low" style={{ fontSize: '10px' }}>
              Database: OSV.dev
            </span>
          </div>

          {vulnerabilities.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center' }}>
              <span className="status-badge safe" style={{ padding: '8px 16px', fontSize: '13px', marginBottom: '15px' }}>
                All Dependencies Secure
              </span>
              <p style={{ color: 'var(--text-secondary)', fontSize: '12px', marginTop: '10px' }}>
                No active CVE vulnerabilities identified across code repositories.
              </p>
            </div>
          ) : (
            <div className="custom-table-container">
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Package / CVE</th>
                    <th>Affected Repo</th>
                    <th>Severity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.map(v => {
                    const repo = repositories.find(r => r.id === v.repoId);
                    return (
                      <tr 
                        key={v.id} 
                        style={{ cursor: 'pointer', background: selectedVulnId === v.id ? 'rgba(255,255,255,0.02)' : '' }}
                        onClick={() => setSelectedVulnId(v.id)}
                      >
                        <td>
                          <div style={{ fontWeight: '600' }}>{v.packageName}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '5px', marginTop: '2px' }}>
                            <span style={{ color: 'var(--color-primary)' }}>{v.cveId}</span>
                            <span>({v.currentVersion} → {v.safeVersion})</span>
                          </div>
                        </td>
                        <td>{repo ? repo.name : 'Unknown'}</td>
                        <td>
                          <span className={`status-badge ${v.severity}`}>
                            {v.severity.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn-secondary" 
                            style={{ padding: '4px 10px', fontSize: '11px' }}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedVulnId(v.id);
                            }}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: AI Explainer and Upgrade Details */}
        <div>
          {selectedVuln ? (
            <div className="explain-fix-panel animate-fade-in" style={{ position: 'static' }}>
              <div className="explain-fix-header">
                <div>
                  <h4 style={{ fontSize: '16px', fontWeight: '700' }}>{selectedVuln.packageName}</h4>
                  <code style={{ fontSize: '11px', color: 'var(--color-primary)' }}>{selectedVuln.cveId}</code>
                </div>
                <span className={`status-badge ${selectedVuln.severity}`}>
                  {selectedVuln.severity.toUpperCase()}
                </span>
              </div>

              <div className="risk-alert-box" style={{ background: 'rgba(227, 179, 65, 0.05)', borderColor: 'rgba(227,179,65,0.2)' }}>
                <div className="risk-alert-title" style={{ color: 'var(--color-warning)' }}>EXPLOIT DETAILS</div>
                <p style={{ fontSize: '12px', lineHeight: '1.4', color: 'var(--text-primary)' }}>
                  {selectedVuln.description}
                </p>
              </div>

              <h4 className="section-sub-title">Remediation Action</h4>
              <p className="ai-explanation-text" style={{ fontSize: '13px', lineHeight: '1.5' }}>
                {selectedVuln.remediation} Upgrading standardizes package references and applies downstream security patches automatically.
              </p>

              <h4 className="section-sub-title">Simulated Upgrade Command</h4>
              <div className="diff-viewer" style={{ background: '#04060a', padding: '12px', color: 'var(--text-secondary)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <TerminalIcon />
                  <code>
                    {selectedVuln.packageName.includes('log4j') ? (
                      `mvn dependency:tree -Dincludes=${selectedVuln.packageName}`
                    ) : selectedVuln.packageName.includes('crypto') ? (
                      `go get -u ${selectedVuln.packageName}@${selectedVuln.safeVersion}`
                    ) : (
                      `npm install ${selectedVuln.packageName}@${selectedVuln.safeVersion}`
                    )}
                  </code>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
                {user?.role !== 'CISO' && (
                  <button 
                    className="btn-primary" 
                    onClick={() => handleUpgrade(selectedVuln.id)}
                    style={{ flex: '1', background: 'linear-gradient(135deg, #39d353 0%, #2ea44f 100%)', color: '#000' }}
                  >
                    Auto-Upgrade Package
                  </button>
                )}
                <a 
                  href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cveId}`} 
                  target="_blank" 
                  rel="noreferrer"
                  className="btn-secondary" 
                  style={{ textAlign: 'center', flex: '1' }}
                >
                  View NVD Source
                </a>
              </div>
            </div>
          ) : (
            <div className="glass-panel" style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <InfoIcon />
              <p style={{ marginTop: '10px', fontSize: '13px' }}>
                Select a dependency vulnerability from the grid table to inspect compliance impact, exploit vectors, and run auto-upgrade scripts.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScaScan;
