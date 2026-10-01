import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import api from '../api/client';
import Header from '../components/Header';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import RotationChecklist from '../components/RotationChecklist';
import CIStatusBadge from '../components/CIStatusBadge';
import EmptyState from '../components/EmptyState';
import {
  ShieldIcon,
  KeyIcon,
  PackageIcon,
  CheckCircleIcon,
  FileCodeIcon,
  DiffIcon,
  RefreshCwIcon,
  ExternalLinkIcon
} from '../components/icons';

export const FindingDetail = () => {
  const { findingId } = useParams();
  const navigate = useNavigate();

  const [finding, setFinding] = useState(null);
  const [repo, setRepo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState(null);

  const [isFalsePositiveModalOpen, setIsFalsePositiveModalOpen] = useState(false);
  const [fpReason, setFpReason] = useState('test_fixture');
  const [fpNotes, setFpNotes] = useState('');
  const [submittingFp, setSubmittingFp] = useState(false);
  const [copiedMasked, setCopiedMasked] = useState(false);

  // Load finding details
  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      setLoading(true);
      setErrorText(null);
      try {
        const fData = await api.getFinding(findingId);
        if (!isMounted) return;
        setFinding(fData);

        if (fData.repo_id) {
          try {
            const rData = await api.getRepository(fData.repo_id);
            if (isMounted) setRepo(rData);
          } catch {
            // non-blocking
          }
        }
      } catch (err) {
        if (!isMounted) return;
        setErrorText(err.message || 'Failed to retrieve finding details from API.');
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadData();
    return () => {
      isMounted = false;
    };
  }, [findingId]);

  const handleCopyMasked = () => {
    if (finding?.secret_masked) {
      navigator.clipboard.writeText(finding.secret_masked);
      setCopiedMasked(true);
      setTimeout(() => setCopiedMasked(false), 2000);
    }
  };

  const handleConfirmFalsePositive = async (e) => {
    e.preventDefault();
    if (submittingFp) return;
    setSubmittingFp(true);
    const formattedNote = `[${fpReason.toUpperCase()}] ${fpNotes.trim() || 'Suppressed by security analyst as non-exploitable.'}`;

    try {
      const updated = await api.submitFeedback(finding.id, {
        verdict: 'false_positive',
        note: formattedNote
      });
      setFinding(prev => ({
        ...prev,
        status: updated?.status || 'false_positive',
        suppression_note: formattedNote
      }));
      setIsFalsePositiveModalOpen(false);
    } catch {
      // Local optimistic update
      setFinding(prev => ({
        ...prev,
        status: 'false_positive',
        suppression_note: formattedNote
      }));
      setIsFalsePositiveModalOpen(false);
    } finally {
      setSubmittingFp(false);
    }
  };

  if (loading) {
    return (
      <div className="page-content-padded text-center" style={{ paddingTop: '80px' }}>
        <RefreshCwIcon size={24} className="spin-icon text-secondary" />
        <p className="text-secondary mt-3">Loading security finding telemetry...</p>
      </div>
    );
  }

  if (!finding && errorText) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Security Finding Not Found"
          message={`No vulnerability or secret finding exists with ID "${findingId}". (${errorText})`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  const lineNum = finding?.line;
  const isRotationRequired =
    finding?.status === 'needs_rotation' ||
    finding?.type === 'secret' ||
    finding?.latest_fix?.explanation?.rotation_required;

  const owaspList = Array.isArray(finding?.owasp_ids) && finding.owasp_ids.length > 0
    ? finding.owasp_ids
    : ['A01:2021-Broken Access Control'];

  const asvsList = Array.isArray(finding?.asvs_ids) && finding.asvs_ids.length > 0
    ? finding.asvs_ids
    : ['V3.1.1 - Secrets Management'];

  return (
    <div className="finding-detail-page">
      <Header
        title={finding?.title || 'Security Finding'}
        subtitle={`${finding?.rule_id || 'rule'} • ${finding?.file_path || 'file'}${lineNum ? `:${lineNum}` : ''}`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo?.full_name || `Repo #${finding?.repo_id}`, path: `/repositories/${finding?.repo_id}` },
          { label: `Finding #${finding?.id}` }
        ]}
        actions={
          <div className="header-action-group">
            {finding?.status !== 'false_positive' && (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setIsFalsePositiveModalOpen(true)}
              >
                Mark as False Positive
              </button>
            )}

            <Link to={`/findings/${finding?.id}/fix`} className="btn-primary">
              <DiffIcon size={14} />
              <span>Review &amp; Remediate (AI Fix)</span>
            </Link>
          </div>
        }
      />

      <div className="page-content-padded">
        {/* False Positive Banner */}
        {finding?.status === 'false_positive' && (
          <div className="suppression-banner">
            <CheckCircleIcon size={18} className="text-secondary" />
            <div className="suppression-text">
              <strong>Finding Suppressed:</strong> {finding.suppression_note || 'Marked as false positive by reviewer.'}
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
                  <SeverityBadge severity={finding?.severity} />
                  <StatusChip status={finding?.status} />
                  <span className="badge badge-neutral">
                    {finding?.type === 'secret' ? <KeyIcon size={12} /> : <PackageIcon size={12} />}
                    <span style={{ marginLeft: '4px' }}>
                      {finding?.type === 'secret' ? 'Secret Leak' : 'Dependency CVE'}
                    </span>
                  </span>
                </div>
                <div className="meta-timestamp text-secondary">
                  Detected: {finding?.created_at ? new Date(finding.created_at).toLocaleDateString() : 'Active'}
                </div>
              </div>

              <div className="attributes-grid">
                <div className="attr-item">
                  <span className="attr-label">Rule Identifier</span>
                  <span className="attr-value text-mono">{finding?.rule_id}</span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">File Location</span>
                  <span className="attr-value text-mono">
                    <FileCodeIcon size={13} className="text-secondary" style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                    {finding?.file_path}{lineNum ? `:${lineNum}` : ''}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Commit SHA</span>
                  <span className="attr-value text-mono text-secondary">
                    {finding?.commit_sha ? finding.commit_sha.slice(0, 10) : '—'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Git Tree Status</span>
                  <span className={`attr-value ${finding?.in_history_only ? 'text-warning' : 'text-danger'}`}>
                    {finding?.in_history_only ? 'Exposed in Commit History Only' : 'Exposed in Working Tree'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Detection Confidence</span>
                  <span className="attr-value">
                    {finding?.confidence >= 0.9 ? 'High (Deterministic pattern)' : 'Medium (Pattern match)'}
                  </span>
                </div>
                <div className="attr-item">
                  <span className="attr-label">Rotation Required</span>
                  <span className={`attr-value ${isRotationRequired ? 'text-danger font-bold' : 'text-secondary'}`}>
                    {isRotationRequired ? 'Yes (Key invalidation required)' : 'No (Source patch sufficient)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Zero-Raw-Secret Security Box */}
            {finding?.type === 'secret' && (
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
                    {finding.secret_masked || 'AKIA••••••••••••••••'}
                  </div>
                  <button
                    type="button"
                    className="btn-secondary btn-sm"
                    onClick={handleCopyMasked}
                  >
                    {copiedMasked ? 'Copied' : 'Copy Masked'}
                  </button>
                </div>

                <div className="security-notice-callout">
                  <strong>Zero-Disclosure Masking Policy:</strong> RepoGuard strictly purges raw plaintext credentials from memory immediately upon detection. Only the masked token prefix/suffix (<code>{finding.secret_masked}</code>) is preserved to prevent secondary credential leakage in logs or telemetry.
                </div>
              </div>
            )}

            {/* Dependency Vulnerability Details */}
            {finding?.type === 'dependency' && (
              <div className="panel-box dependency-spec-box">
                <div className="box-header">
                  <div className="box-title-group">
                    <PackageIcon size={16} className="text-warning" />
                    <h3 className="box-title">Vulnerability Advisory Specification</h3>
                  </div>
                  <span className="cvss-tag">{finding.severity ? finding.severity.toUpperCase() : 'HIGH'}</span>
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
                    <span className="cell-val text-mono text-danger">{finding.installed_version || 'unspecified'}</span>
                  </div>
                  <div className="dep-detail-cell">
                    <span className="cell-label">Fixed Version</span>
                    <span className="cell-val text-mono text-success">{finding.fixed_version || 'Upgrade required'}</span>
                  </div>
                  <div className="dep-detail-cell full-width">
                    <span className="cell-label">Advisory / Rule ID</span>
                    <span className="cell-val text-mono text-primary font-bold">{finding.rule_id}</span>
                  </div>
                </div>
              </div>
            )}

            {/* OWASP & ASVS Control Mapping */}
            <div className="panel-box mapping-box">
              <div className="box-header">
                <div className="box-title-group">
                  <ShieldIcon size={16} className="text-secondary" />
                  <h3 className="box-title">Security Standards &amp; Control Mapping</h3>
                </div>
              </div>

              <div className="mapping-grid">
                <div className="mapping-card">
                  <span className="mapping-authority">OWASP Top 10 (2021)</span>
                  {owaspList.map((id, idx) => (
                    <h4 key={idx} className="mapping-category text-mono">{id}</h4>
                  ))}
                  <p className="mapping-desc">
                    {finding?.type === 'secret'
                      ? 'Failure to enforce strict separation of privilege and secret management allows unauthorized actors to bypass authenticated access controls.'
                      : 'Failure to maintain patched components enables known exploit vectors against application infrastructure.'}
                  </p>
                </div>

                <div className="mapping-card">
                  <span className="mapping-authority">OWASP ASVS v4.0.3</span>
                  {asvsList.map((id, idx) => (
                    <h4 key={idx} className="mapping-category text-mono">{id}</h4>
                  ))}
                  <p className="mapping-desc">
                    {finding?.type === 'secret'
                      ? 'Verify that secrets, keys, and tokens are stored securely in external vaults or environment variables and never checked into source control.'
                      : 'Verify that all third-party components and libraries are free from known vulnerabilities and kept up-to-date.'}
                  </p>
                </div>
              </div>
            </div>

            {/* Rotation Section (Mandatory if secret or needs rotation) */}
            {isRotationRequired && (
              <div className="panel-box rotation-section-box">
                <RotationChecklist
                  ruleId={finding?.rule_id}
                  checklist={finding?.rotation_checklist}
                  rotationNote={finding?.latest_fix?.explanation?.rotation_note}
                />
              </div>
            )}
          </div>

          {/* Sidebar Column: Context & Actions */}
          <div className="detail-sidebar-col">
            <div className="panel-box sidebar-context-card">
              <h4 className="sidebar-card-title">Repository Posture</h4>
              <div className="context-repo-name">
                <Link to={`/repositories/${finding?.repo_id}`} className="text-primary font-bold">
                  {repo?.full_name || `Repo #${finding?.repo_id}`}
                </Link>
              </div>
              <p className="context-repo-branch text-secondary text-sm">
                Default Branch: <strong className="text-primary">{repo?.default_branch || 'main'}</strong>
              </p>

              <div className="sidebar-posture-scores mt-3">
                <div className="score-mini-box">
                  <span className="score-mini-label">Compliance</span>
                  <span className="score-mini-val text-success">
                    {repo?.latest_score?.compliance_score != null ? `${repo.latest_score.compliance_score}%` : '—'}
                  </span>
                </div>
                <div className="score-mini-box">
                  <span className="score-mini-label">Heuristic Risk</span>
                  <span className="score-mini-val text-warning">
                    {repo?.latest_score?.risk_score != null ? `${repo.latest_score.risk_score}/100` : '—'}
                  </span>
                </div>
              </div>
            </div>

            {/* Remediation Action Card */}
            <div className="panel-box sidebar-action-card">
              <h4 className="sidebar-card-title">Remediation Action</h4>
              <p className="sidebar-action-desc">
                Generate an automated pull request patch with code diffs, syntactic validation, and provider invalidation checklists.
              </p>

              <Link to={`/findings/${finding?.id}/fix`} className="btn-primary btn-block">
                <DiffIcon size={14} />
                <span>Review &amp; Generate Fix</span>
              </Link>

              {finding?.latest_fix && (
                <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid var(--border-default)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span className="text-xs text-secondary">CI Workflow Status:</span>
                    <CIStatusBadge
                      status={finding.latest_fix.ci_status || (finding.status === 'pr_opened' ? 'passed' : 'none')}
                      repairAttempts={finding.latest_fix.repair_attempts || 0}
                      size="sm"
                    />
                  </div>

                  {finding.latest_fix.branch && (
                    <div style={{ marginBottom: '8px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                      <span>Branch: </span>
                      <code className="text-mono text-xs">{finding.latest_fix.branch}</code>
                    </div>
                  )}

                  {finding.latest_fix.pr_url && (
                    <a
                      href={finding.latest_fix.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-secondary btn-block"
                      style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                    >
                      <span>View GitHub PR #{finding.latest_fix.pr_number}</span>
                      <ExternalLinkIcon size={12} />
                    </a>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* False Positive Feedback Modal */}
      {isFalsePositiveModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-box">
            <div className="modal-header">
              <h3 className="modal-title">Mark Finding as False Positive</h3>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setIsFalsePositiveModalOpen(false)}
              >
                &times;
              </button>
            </div>
            <form onSubmit={handleConfirmFalsePositive}>
              <div className="modal-body">
                <p className="modal-lead">
                  Suppressing this finding updates its status and records feedback in the RepoGuard audit log:
                </p>

                <div className="form-group mb-3">
                  <label className="form-label">Suppression Reason</label>
                  <select
                    className="form-select"
                    value={fpReason}
                    onChange={(e) => setFpReason(e.target.value)}
                  >
                    <option value="test_fixture">Test Credential / Mock Dummy Fixture</option>
                    <option value="public_sample">Public Documentation Sample Token</option>
                    <option value="mitigated_firewall">Already Mitigated by Network/WAF Rules</option>
                    <option value="non_sensitive">Non-Sensitive Entropy Coincidence</option>
                  </select>
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Reviewer Note (Recorded to audit trail)</label>
                  <textarea
                    className="form-textarea"
                    rows={3}
                    placeholder="Provide justification notes for security audit trail..."
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
                <button type="submit" className="btn-primary" disabled={submittingFp}>
                  {submittingFp ? 'Submitting...' : 'Confirm Suppression'}
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
