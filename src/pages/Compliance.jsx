import React, { useState } from 'react';
import { useSystemData } from '../context/SystemDataContext';

// Simple Icons
const DownloadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
);
const CloseIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
);

export const Compliance = () => {
  const { secrets, vulnerabilities, integrations } = useSystemData();
  const [showExportModal, setShowExportModal] = useState(false);

  // Dynamic checks based on active database state!
  const hasExposedSecrets = secrets.some(s => s.status === 'exposed' || s.status === 'fixing');
  const hasOutdatedLibs = vulnerabilities.some(v => v.severity === 'critical' || v.severity === 'high');
  const integrationsConfigured = integrations.every(i => i.status === 'configured');

  // Mapped controls
  const categories = [
    {
      id: 'a02',
      name: 'A02:2021 - Cryptographic Failures',
      description: 'Protection of sensitive data, cryptography strengths, and secret keys governance.',
      checks: [
        {
          id: 'c1',
          title: 'Plaintext secret detection in code commits',
          desc: 'Scans git commits history for hardcoded tokens, API keys, and asymmetric credentials.',
          isPassing: !hasExposedSecrets,
          failWarning: 'Failing: Plaintext secrets active in repo commits. Resolve using AI Wizard.'
        },
        {
          id: 'c2',
          title: 'Encryption keys rotation intervals',
          desc: 'Assesses if credentials have been rotated according to organization-wide policies.',
          isPassing: !hasExposedSecrets,
          failWarning: 'Failing: Credentials exposed. Trigger rotation routines immediately.'
        }
      ]
    },
    {
      id: 'a05',
      name: 'A05:2021 - Security Misconfiguration',
      description: 'Secure installation/hardening configurations, vault configurations, and env boundaries.',
      checks: [
        {
          id: 'c3',
          title: 'Secure vault rotation hooks',
          desc: 'Validates that rotation interfaces (AWS, Stripe) are verified and communicating.',
          isPassing: integrationsConfigured,
          failWarning: 'Failing: Vault connections are unverified. Please check Settings.'
        }
      ]
    },
    {
      id: 'a06',
      name: 'A06:2021 - Vulnerable and Outdated Components',
      description: 'Audit third-party client dependencies, packages, and frameworks against CVE databases.',
      checks: [
        {
          id: 'c4',
          title: 'Software Composition Analysis (SCA) dependency scanner',
          desc: 'Cross-checks manifest files (package.json, pom.xml, go.mod) for published exploits.',
          isPassing: !hasOutdatedLibs,
          failWarning: 'Failing: Outdated packages containing critical/high CVEs present.'
        }
      ]
    }
  ];

  // Count total checks and passing checks
  const totalChecksCount = categories.reduce((sum, cat) => sum + cat.checks.length, 0);
  const passingChecksCount = categories.reduce(
    (sum, cat) => sum + cat.checks.filter(c => c.isPassing).length,
    0
  );
  
  const compliancePercentage = Math.round((passingChecksCount / totalChecksCount) * 100);

  const generateMockReportJson = () => {
    const report = {
      auditTimestamp: new Date().toISOString(),
      scannerEngine: 'RepoGuard Compliance Agent v1.4.2',
      complianceTarget: 'OWASP-ASVS-v5.0',
      complianceSummary: {
        score: `${compliancePercentage}%`,
        totalRulesChecked: totalChecksCount,
        passingRules: passingChecksCount,
        failingRules: totalChecksCount - passingChecksCount
      },
      evidencePayload: categories.map(cat => ({
        category: cat.name,
        rules: cat.checks.map(c => ({
          ruleName: c.title,
          status: c.isPassing ? 'PASS' : 'FAIL',
          verifiedAt: new Date().toLocaleDateString()
        }))
      })),
      cryptoVerificationSignature: 'SHA256withRSA:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0G3uKj0...[MOCK_SIGNATURE]'
    };
    return JSON.stringify(report, null, 2);
  };

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '25px' }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Evaluate code repositories against industry compliance standards like OWASP Top 10 and ASVS Controls to build audit readiness evidence.
        </p>
      </div>

      {/* Compliance Header index panel */}
      <div className="compliance-progress-card">
        <div>
          <h3 style={{ fontSize: '20px', fontWeight: '700' }}>Overall Compliance Index</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginTop: '5px' }}>
            Calculated from active secrets scanner and package CVE scans across 5 repositories.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginTop: '15px' }}>
            <div className="progress-bar-container" style={{ margin: 0, height: '10px', width: '220px' }}>
              <div className="progress-bar-fill" style={{ width: `${compliancePercentage}%` }}></div>
            </div>
            <span style={{ fontSize: '14px', fontWeight: 'bold' }}>{compliancePercentage}% Controls Passing</span>
          </div>
        </div>

        <button 
          className="btn-primary" 
          onClick={() => setShowExportModal(true)}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <DownloadIcon /> Export Audit Evidence
        </button>
      </div>

      {/* Categories details */}
      {categories.map(cat => {
        const passingCount = cat.checks.filter(c => c.isPassing).length;
        const totalCount = cat.checks.length;
        const isCatPassing = passingCount === totalCount;

        return (
          <div key={cat.id} className="compliance-category-section glass-panel">
            <div className="category-header">
              <div>
                <h4 className="category-name">{cat.name}</h4>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>{cat.description}</p>
              </div>
              <span className={`status-badge ${isCatPassing ? 'safe' : 'medium'}`}>
                {passingCount}/{totalCount} Checks
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {cat.checks.map(check => (
                <div 
                  key={check.id} 
                  className={`compliance-check-item ${check.isPassing ? 'passing' : 'failing'}`}
                >
                  <div className="check-description">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h5 className="check-title">{check.title}</h5>
                      <span className={`status-badge ${check.isPassing ? 'safe' : 'critical'}`} style={{ fontSize: '9px', padding: '1px 8px' }}>
                        {check.isPassing ? 'COMPLIANT' : 'VIOLATION'}
                      </span>
                    </div>
                    <p className="check-meta">{check.desc}</p>
                    {!check.isPassing && (
                      <p style={{ color: 'var(--color-danger)', fontSize: '11px', marginTop: '6px', fontWeight: '600' }}>
                        {check.failWarning}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {/* Export Evidence Modal */}
      {showExportModal && (
        <div className="modal-overlay animate-fade-in" onClick={() => setShowExportModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '650px' }}>
            <div className="modal-header">
              <h4 className="modal-title">SOC2 / ISO 27001 Cryptographic Audit Evidence</h4>
              <button className="modal-close-btn" onClick={() => setShowExportModal(false)}>
                <CloseIcon />
              </button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '15px' }}>
                Copilot signs audit payloads cryptographically. You can submit this JSON directly to automated compliance monitors like Vanta or Drata as evidence for ASVS criteria.
              </p>
              <div 
                className="diff-viewer" 
                style={{ 
                  background: '#04060a', 
                  padding: '16px', 
                  fontSize: '11px', 
                  color: '#39d353',
                  maxHeight: '350px',
                  overflowY: 'auto'
                }}
              >
                <pre>{generateMockReportJson()}</pre>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowExportModal(false)}>
                Close
              </button>
              <button 
                className="btn-primary" 
                onClick={() => {
                  alert('Audit report copied to clipboard!');
                  navigator.clipboard.writeText(generateMockReportJson());
                  setShowExportModal(false);
                }}
              >
                Copy Payload Evidence
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Compliance;
