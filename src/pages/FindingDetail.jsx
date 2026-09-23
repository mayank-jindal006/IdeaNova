import React, { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import Header from '../components/Header';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import RotationChecklist from '../components/RotationChecklist';
import EmptyState from '../components/EmptyState';
import {
  ShieldIcon,
  KeyIcon,
  PackageIcon,
  CheckCircleIcon,
  FileCodeIcon,
  DiffIcon
} from '../components/icons';
import {
  calculateComplianceScore,
  calculateHeuristicRisk
} from '../services/repoGuardService';

export const FindingDetail = () => {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const { findings, repositories, markFalsePositive } = useRepoGuard();

  const [isFalsePositiveModalOpen, setIsFalsePositiveModalOpen] = useState(false);
  const [fpReason, setFpReason] = useState('test_fixture');
  const [fpNotes, setFpNotes] = useState('');
  const [copiedMasked, setCopiedMasked] = useState(false);

  const finding = findings.find(f => f.id === findingId);
  const repo = repositories.find(r => r.id === finding?.repoId);

  if (!finding) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Security Finding Not Found"
          message={`No vulnerability or secret finding exists with ID "${findingId}".`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  const repoFindings = findings.filter(f => f.repoId === finding.repoId);
  const repoRisk = repo ? calculateHeuristicRisk(repo, repoFindings) : null;
  const repoCompliance = calculateComplianceScore(repoFindings);

  const handleCopyMasked = () => {
    if (finding.secretMasked) {
      navigator.clipboard.writeText(finding.secretMasked);
      setCopiedMasked(true);
      setTimeout(() => setCopiedMasked(false), 2000);
    }
  };

  const handleConfirmFalsePositive = (e) => {
    e.preventDefault();
    const formattedNote = `[${fpReason.toUpperCase()}] ${fpNotes.trim() || 'Suppressed by security analyst as non-exploitable.'}`;
    markFalsePositive(finding.id, formattedNote);
    setIsFalsePositiveModalOpen(false);
  };

  return (
    <div className="finding-detail-page">
      <Header
        title={finding.title}
        subtitle={`${finding.ruleId} • ${finding.filePath}:${finding.lineNumber}`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo?.name || finding.repoId, path: `/repositories/${finding.repoId}` },
          { label: finding.id }
        ]}
        actions={
          <div className="header-action-group">
            {finding.status !== 'false_positive' && (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setIsFalsePositiveModalOpen(true)}
              >
                Mark as False Positive
              </button>
            )}

            <Link to={`/findings/${finding.id}/fix`} className="btn-primary">
              <DiffIcon size={14} />
              <span>Review & Remediate (AI Fix)</span>
            </Link>
          </div>
        }
      />

      <div className="page-content-padded">
        {/* False Positive Banner */}
        {finding.status === 'false_positive' && (
          <div className="suppression-banner">
            <CheckCircleIcon size={18} className="text-secondary" />
            <div className="suppression-text">
              <strong>Finding Suppressed:</strong> {finding.suppressionNote || 'Marked as false positive by reviewer.'}
              <span className="suppression-meta"> This item is excluded from Heuristic Risk penalties and OWASP compliance deductions.</span>
            </div>
          </div>
        )}

        <div className="detail-layout-grid">
          {/* Main Content Column */}
          <div className="detail-main-col">
            {/* Finding Attributes Overview */}
            <div className="panel-box finding-meta-card">
              <div className="meta-headline-row">
                <div className="meta-badges">
                  <SeverityBadge severity={finding.severity} />
                  <StatusChip status={finding.status} />
                  <span className="badge badge-neutral">
                    {finding.type === 'secret' ? <KeyIcon size={12} /> : <PackageIcon size={12} />}
                    <span style={{ marginLeft: '4px' }}>{finding.type === 'secret' ? 'Secret Leak' : 'Dependency CVE'}</span>
                  </span>
                </div>
                <div className="meta-timestamp text-secondary">
                  Detected: {new Date(finding.detectedAt || Date.now()).toLocaleDateString()}
                </div>
              </div>

              <div className="attributes-grid">
                <div className="attr-item">
                  <span className="attr-label">Rule Identifier</span>
                  <span className="attr-value text-mono">{finding.ruleId}</span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">File Location</span>
                  <span className="attr-value text-mono">
                    <FileCodeIcon size={13} className="text-secondary" style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                    {finding.filePath}:{finding.lineNumber}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Commit SHA</span>
                  <span className="attr-value text-mono text-secondary">
                    {finding.commitSha || 'a1b2c3d4e5f'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Git Tree Status</span>
                  <span className={`attr-value ${finding.inGitHistory ? 'text-warning' : 'text-danger'}`}>
                    {finding.inGitHistory ? 'Exposed in Commit History' : 'Exposed in Working Tree'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Detection Confidence</span>
                  <span className="attr-value">
                    {finding.confidence === 'high' ? 'High (Deterministic pattern)' : 'Medium (Heuristic match)'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Rotation Required</span>
                  <span className={`attr-value ${finding.rotationRequired ? 'text-danger font-bold' : 'text-secondary'}`}>
                    {finding.rotationRequired ? 'Yes (Key invalidation required)' : 'No (Source patch sufficient)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Zero-Raw-Secret Security Box */}
            {finding.type === 'secret' && (
              <div className="panel-box secret-security-box">
                <div className="box-header">
                  <div className="box-title-group">
                    <KeyIcon size={16} className="text-warning" />
                    <h3 className="box-title">Masked Credential Representation</h3>
                  </div>
                  <span className="security-policy-tag">Zero-Raw-Secret Policy</span>
                </div>

                <div className="secret-display-row">
                  <div className="masked-secret-token text-mono">
                    {finding.secretMasked || 'AKIA••••••••••••••••'}
                  </div>
                  <button
                    type="button"
                    className="btn-secondary btn-sm"
                    onClick={handleCopyMasked}
                  >
                    {copiedMasked ? 'Copied' : 'Copy Masked'}
                  </button>
                </div>

                <div className="secret-fingerprint-row">
                  <span className="fingerprint-label">SHA-256 Fingerprint:</span>
                  <code className="fingerprint-hash text-mono">
                    {finding.secretFingerprint || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                  </code>
                </div>

                <div className="security-notice-callout">
                  <strong>Security Architecture Notice:</strong> RepoGuard implements strict zero-disclosure masking. Raw plaintext credentials are purged from memory immediately following AST regex validation. Engineers can identify the exposed token via prefix/suffix tokens and SHA-256 fingerprint without re-exposing sensitive key values in console logs.
                </div>
              </div>
            )}

            {/* Dependency Vulnerability Details */}
            {finding.type === 'dependency' && (
              <div className="panel-box dependency-spec-box">
                <div className="box-header">
                  <div className="box-title-group">
                    <PackageIcon size={16} className="text-warning" />
                    <h3 className="box-title">Vulnerability Advisory Specification</h3>
                  </div>
                  <span className="cvss-tag">CVSS {finding.cvss || '7.5'}</span>
                </div>

                <div className="dep-details-grid">
                  <div className="dep-detail-cell">
                    <span className="cell-label">Package</span>
                    <span className="cell-val text-mono font-bold">{finding.package}</span>
                  </div>
                  <div className="dep-detail-cell">
                    <span className="cell-label">Ecosystem</span>
                    <span className="cell-val">{finding.ecosystem || 'PyPI'}</span>
                  </div>
                  <div className="dep-detail-cell">
                    <span className="cell-label">Installed Version</span>
                    <span className="cell-val text-mono text-danger">{finding.installedVersion}</span>
                  </div>
                  <div className="dep-detail-cell">
                    <span className="cell-label">Patched Version</span>
                    <span className="cell-val text-mono text-success">{finding.fixedVersion || '>= 3.1.4'}</span>
                  </div>
                  <div className="dep-detail-cell full-width">
                    <span className="cell-label">Vulnerability Advisory</span>
                    <span className="cell-val text-mono text-primary font-bold">{finding.cve || 'GHSA-xxxx-yyyy'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* OWASP & ASVS Control Mapping */}
            <div className="panel-box mapping-box">
              <div className="box-header">
                <div className="box-title-group">
                  <ShieldIcon size={16} className="text-secondary" />
                  <h3 className="box-title">Security Standards & Control Mapping</h3>
                </div>
              </div>

              <div className="mapping-grid">
                <div className="mapping-card">
                  <span className="mapping-authority">OWASP Top 10 (2021)</span>
                  <h4 className="mapping-category text-mono">{finding.owaspCategory || 'A01:2021-Broken Access Control'}</h4>
                  <p className="mapping-desc">
                    {finding.type === 'secret'
                      ? 'Failure to enforce strict separation of privilege and secret management allows unauthorized actors to bypass authenticated access controls.'
                      : 'Failure to maintain patched components enables known exploit vectors against application infrastructure.'}
                  </p>
                </div>

                <div className="mapping-card">
                  <span className="mapping-authority">OWASP ASVS v4.0.3</span>
                  <h4 className="mapping-category text-mono">{finding.asvsControl || 'V3.1.1 - Secrets Management'}</h4>
                  <p className="mapping-desc">
                    {finding.type === 'secret'
                      ? 'Verify that secrets, keys, and tokens are stored securely in external vaults or environment variables and never checked into source control.'
                      : 'Verify that all third-party components and libraries are free from known vulnerabilities and kept up-to-date.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Technical Explanation & Hazard Assessment */}
            <div className="panel-box explanation-box">
              <div className="box-header">
                <h3 className="box-title">Technical Description & Threat Assessment</h3>
              </div>
              <div className="explanation-body">
                <p className="explanation-text">{finding.description}</p>
                <div className="remediation-guidance">
                  <strong>Recommended Remediation:</strong> {finding.remediationSuggestion}
                </div>
              </div>
            </div>

            {/* Credential Rotation Section (Mandatory if secret) */}
            {finding.rotationRequired && (
              <div className="panel-box rotation-section-box">
                <RotationChecklist ruleId={finding.ruleId} />
              </div>
            )}
          </div>

          {/* Sidebar Column: Context & Actions */}
          <div className="detail-sidebar-col">
            <div className="panel-box sidebar-context-card">
              <h4 className="sidebar-card-title">Repository Posture</h4>
              <div className="context-repo-name">
                <Link to={`/repositories/${repo?.id || finding.repoId}`} className="repo-link text-mono">
                  {repo?.fullName || finding.repoId}
                </Link>
              </div>

              <div className="context-metrics-list">
                <div className="context-metric-row">
                  <span className="cm-label">Compliance Score</span>
                  <span className={`cm-val text-mono ${repoCompliance >= 80 ? 'text-success' : repoCompliance >= 50 ? 'text-warning' : 'text-danger'}`}>
                    {repoCompliance}%
                  </span>
                </div>
                <div className="context-metric-row">
                  <span className="cm-label">Heuristic Risk Score</span>
                  <span className={`cm-val text-mono ${repoRisk?.score >= 60 ? 'text-danger' : repoRisk?.score >= 30 ? 'text-warning' : 'text-success'}`}>
                    {repoRisk?.score ?? 0} / 100
                  </span>
                </div>
                <div className="context-metric-row">
                  <span className="cm-label">Active Exposures</span>
                  <span className="cm-val text-mono">
                    {repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length}
                  </span>
                </div>
              </div>

              <div className="sidebar-cta-stack">
                <Link to={`/findings/${finding.id}/fix`} className="btn-primary btn-block">
                  <DiffIcon size={14} />
                  <span>Review & Remediate (AI Fix)</span>
                </Link>
                <Link to={`/repositories/${finding.repoId}`} className="btn-secondary btn-block">
                  Back to Findings List
                </Link>
              </div>
            </div>

            <div className="panel-box help-card">
              <h4 className="sidebar-card-title">Remediation Workflow</h4>
              <ol className="remediation-steps-list">
                <li>
                  <strong>1. Generate Patch:</strong> Review before/after code diff in Fix Review.
                </li>
                <li>
                  <strong>2. Automated Validation:</strong> Verify that Gitleaks confirms zero tokens remain.
                </li>
                <li>
                  <strong>3. Rotation Steps:</strong> Invalidate the exposed key with the credential provider.
                </li>
                <li>
                  <strong>4. Pull Request:</strong> Open automated GitHub PR for peer review.
                </li>
              </ol>
            </div>
          </div>
        </div>
      </div>

      {/* Modal: Confirm False Positive */}
      {isFalsePositiveModalOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-card">
            <div className="modal-header">
              <h3 className="modal-title">Mark Finding as False Positive</h3>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setIsFalsePositiveModalOpen(false)}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleConfirmFalsePositive}>
              <div className="modal-body">
                <p className="modal-instruction">
                  Marking this finding as a false positive will suppress it from active exposure counts, restore OWASP compliance points, and recalculate repository Heuristic Risk.
                </p>

                <div className="form-group">
                  <label className="form-label" htmlFor="fp-reason">
                    Suppression Justification Category
                  </label>
                  <select
                    id="fp-reason"
                    className="form-control"
                    value={fpReason}
                    onChange={(e) => setFpReason(e.target.value)}
                  >
                    <option value="test_fixture">Dummy Token in Test Fixture / Mock File</option>
                    <option value="revoked">Credential Already Revoked at Provider</option>
                    <option value="low_entropy">Non-Sensitive Entropy Collision / False Trigger</option>
                    <option value="internal_staging">Isolated Ephemeral Staging Environment</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="fp-notes">
                    Reviewer Audit Notes
                  </label>
                  <textarea
                    id="fp-notes"
                    className="form-control"
                    rows={3}
                    placeholder="Describe verification rationale for security audit trail..."
                    value={fpNotes}
                    onChange={(e) => setFpNotes(e.target.value)}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setIsFalsePositiveModalOpen(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Confirm Suppression
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default FindingDetail;
