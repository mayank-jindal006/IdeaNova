import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useRepoGuard } from '../context/useRepoGuard';
import Header from '../components/Header';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import EmptyState from '../components/EmptyState';
import { securityApi } from '../services/securityApi';
import { exportAvailability } from '../services/exportPresentation';
import { AlertTriangleIcon, CheckCircleIcon, RefreshCwIcon } from '../components/icons';

const formatStatus = (status) => (status || 'unknown').replaceAll('_', ' ');

export const FixReview = () => {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const {
    findings,
    fixes,
    repositories,
    loadFix,
    generateFix,
    reviewFix,
    validateFix,
    openPullRequest
  } = useRepoGuard();
  const finding = findings.find((item) => item.id === findingId);
  const repo = repositories.find((item) => item.id === finding?.repoId);
  const fix = fixes[findingId];
  const [loadingFix, setLoadingFix] = useState(true);
  const [pendingAction, setPendingAction] = useState(null);
  const [reviewNote, setReviewNote] = useState('');
  const [errorText, setErrorText] = useState(null);
  const [exportStatus, setExportStatus] = useState(null);
  const [exportMessage, setExportMessage] = useState('');
  const [prEligibility, setPrEligibility] = useState(null);

  useEffect(() => {
    let active = true;
    setLoadingFix(true);
    setErrorText(null);
    loadFix(findingId)
      .catch((error) => {
        if (active) setErrorText(error.message || 'Unable to load the persisted remediation proposal.');
      })
      .finally(() => {
        if (active) setLoadingFix(false);
      });
    return () => {
      active = false;
    };
  }, [findingId, loadFix]);

  useEffect(() => {
    let active = true;
    setExportStatus(null);
    setExportMessage('');
    if (fix?.id && repo?.sourceType === 'local') {
      securityApi.patchExportStatus(fix.id)
        .then((status) => {
          if (!active) return;
          setExportStatus(exportAvailability(status));
        })
        .catch(() => { if (active) setExportStatus({ eligible: false, reason: 'Unable to check export eligibility.' }); });
    }
    return () => { active = false; };
  }, [fix?.id, fix?.status, repo?.sourceType]);

  useEffect(() => {
    let active = true;
    setPrEligibility(null);
    if (fix?.id && fix.status === 'validation_passed' && repo?.sourceType === 'github') {
      securityApi.pullRequestEligibility(fix.id)
        .then((status) => { if (active) setPrEligibility(status); })
        .catch(() => { if (active) setPrEligibility({ eligible: false, reason: 'Unable to verify GitHub connection.' }); });
    }
    return () => { active = false; };
  }, [fix?.id, fix?.status, repo?.sourceType]);

  if (!finding) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Security Finding Not Found"
          message="The selected finding is not available in the current account."
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  const runAction = async (action, callback) => {
    setPendingAction(action);
    setErrorText(null);
    try {
      await callback();
    } catch (error) {
      setErrorText(error.message || 'The remediation action could not be completed.');
    } finally {
      setPendingAction(null);
    }
  };

  const createProposal = () => runAction('generate', () => generateFix(findingId));
  const submitReview = (decision) => runAction(decision, () => reviewFix(findingId, decision, reviewNote));
  const validateProposal = () => runAction('validate', () => validateFix(findingId));
  const createPullRequest = () => runAction('open-pr', () => openPullRequest(findingId));
  const downloadPatch = () => runAction('export', async () => {
    setExportMessage('');
    const archive = await securityApi.exportPatch(fix.id);
    const url = URL.createObjectURL(archive);
    try {
      const link = document.createElement('a');
      link.href = url;
      link.download = `repoguard-fix-${fix.id}.zip`;
      link.click();
    } finally {
      URL.revokeObjectURL(url);
    }
    setExportMessage('Patch downloaded. It has not been applied; the original repository was not modified. Review it before manual application. Security validation does not mean repository tests passed.');
  });
  const validation = fix?.validation;

  return (
    <div className="fix-review-page">
      <Header
        title="Remediation Review"
        subtitle={`${finding.title} · ${repo?.fullName || finding.repoId}`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo?.name || finding.repoId, path: `/repositories/${finding.repoId}` },
          { label: finding.id, path: `/findings/${finding.id}` },
          { label: 'Fix Review' }
        ]}
        actions={
          <div className="header-action-group">
            <Link to={`/findings/${finding.id}`} className="btn-secondary">Back to Finding</Link>
            <button
              type="button"
              className="btn-primary"
              onClick={createProposal}
              disabled={pendingAction !== null || loadingFix}
            >
              <RefreshCwIcon size={14} className={pendingAction === 'generate' ? 'spin-icon' : ''} />
              <span>{pendingAction === 'generate' ? 'Generating proposal…' : fix ? 'Generate New Proposal' : 'Generate Proposal'}</span>
            </button>
          </div>
        }
      />

      <div className="page-content-padded">
        {loadingFix && <div className="panel-box mb-4" role="status">Loading persisted remediation history…</div>}
        {errorText && (
          <div className="panel-box error-alert-box mb-4" role="alert">
            <div className="alert-top">
              <AlertTriangleIcon size={18} className="text-danger" />
              <h3 className="alert-title">Remediation action failed</h3>
            </div>
            <p className="alert-message">{errorText}</p>
          </div>
        )}

        <section className="panel-box fix-summary-panel">
          <div className="fix-panel-header">
            <div className="panel-headline-group">
              <SeverityBadge severity={finding.severity} />
              <StatusChip status={finding.status} />
              <span className="file-badge text-mono">Scanner: {finding.scanner || 'unavailable'}</span>
              <span className="file-badge text-mono">{finding.filePath}</span>
            </div>
          </div>
          <p>{finding.description || finding.title}</p>
          <p className="text-secondary">A proposal is never applied automatically. Review, approval, validation, and pull-request creation are separate recorded actions.</p>
        </section>

        {!loadingFix && !fix && (
          <section className="panel-box mt-4">
            <h3 className="box-title">No persisted proposal</h3>
            <p>Generate a server-side proposal to create a reviewable, database-backed remediation record.</p>
          </section>
        )}

        {fix && (
          <>
            <section className="panel-box mt-4">
              <div className="box-header">
                <h3 className="box-title">Proposal status: {formatStatus(fix.status)}</h3>
                <span className="text-xs text-secondary">
                  Created {fix.generatedAt ? new Date(fix.generatedAt).toLocaleString() : 'date unavailable'}
                </span>
              </div>
              <div className="remediation-strategy-card">
                <h4 className="strategy-heading">{fix.explanation.what}</h4>
                <p><strong>Why it matters:</strong> {fix.explanation.whyDangerous}</p>
                <p><strong>Proposed remediation:</strong> {fix.explanation.howFixed}</p>
                <p><strong>Risk assessment:</strong> {fix.riskLevel || 'unavailable'}</p>
                {fix.explanation.rotationRequired && <p role="note">{fix.explanation.rotationNote}</p>}
              </div>
              {fix.patch ? (
                <details className="mt-4">
                  <summary>Review proposed patch for {fix.targetFile}</summary>
                  <pre className="text-mono" style={{ whiteSpace: 'pre-wrap', overflowX: 'auto' }}>{fix.patch}</pre>
                </details>
              ) : (
                <p className="text-secondary mt-4">No code patch was generated; only explanatory guidance is available. This suggestion has not been validated.</p>
              )}
            </section>

            {fix.status === 'pending_review' && (
              <section className="panel-box mt-4">
                <h3 className="box-title">Human review</h3>
                <label className="form-label" htmlFor="review-note">Review note (optional)</label>
                <textarea
                  id="review-note"
                  className="form-input"
                  maxLength={2000}
                  value={reviewNote}
                  onChange={(event) => setReviewNote(event.target.value)}
                />
                <div className="header-action-group mt-4">
                  <button type="button" className="btn-primary" onClick={() => submitReview('approved')} disabled={pendingAction !== null}>
                    {pendingAction === 'approved' ? 'Recording approval…' : 'Approve proposal'}
                  </button>
                  <button type="button" className="btn-secondary" onClick={() => submitReview('rejected')} disabled={pendingAction !== null}>
                    {pendingAction === 'rejected' ? 'Recording rejection…' : 'Reject proposal'}
                  </button>
                </div>
              </section>
            )}

            {fix.reviews?.length > 0 && (
              <section className="panel-box mt-4">
                <h3 className="box-title">Review history</h3>
                <ul>
                  {fix.reviews.map((review) => (
                    <li key={review.id}>
                      {review.decision} by {review.reviewer_email} on {new Date(review.created_at).toLocaleString()}
                      {review.note ? ` — ${review.note}` : ''}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {['approved', 'validation_failed'].includes(fix.status) && (
              <section className="panel-box mt-4">
                <h3 className="box-title">Disposable-checkout validation</h3>
                <p>After approval, RepoGuard applies the candidate only in a disposable clone and reruns the relevant security scanners. Repository test commands are not executed.</p>
                <button type="button" className="btn-primary" onClick={validateProposal} disabled={pendingAction !== null || !fix.patch}>
                  {pendingAction === 'validate' ? 'Validating…' : 'Validate approved proposal'}
                </button>
              </section>
            )}

            {validation && (
              <section className="panel-box mt-4" aria-live="polite">
                <div className="box-header">
                  <h3 className="box-title">Validation results</h3>
                  <span className={`validation-status-badge ${fix.status === 'validation_passed' ? 'val-pass' : 'val-pending'}`}>
                    {fix.status === 'validation_passed' && validation.tests === 'not_run' ? 'Security rescan passed; tests not run' : formatStatus(fix.status)}
                  </span>
                </div>
                <ul className="validation-checks-list">
                  <li>{validation.patch_syntax || 'not_run'} — patch syntax</li>
                  <li>{validation.target_exists === true ? 'passed' : validation.target_exists === false ? 'failed' : 'not_run'} — target file check</li>
                  <li>{validation.syntaxOk ? 'passed' : 'failed'} — supported syntax validation</li>
                  <li>{validation.security_rescan || 'not_run'} — security rescan</li>
                  <li>{validation.tests || 'not_run'} — repository tests (intentionally not executed)</li>
                </ul>
                {validation.notes?.length > 0 && (
                  <ul>{validation.notes.map((note, index) => <li key={`${index}-${note}`}>{note}</li>)}</ul>
                )}
              </section>
            )}

            {repo?.sourceType === 'local' && fix.status === 'validation_passed' && (
              <section className="panel-box mt-4" role="status">
                <h3 className="box-title">Local application unavailable</h3>
                <p>The security rescan did not change the original repository. Applying this proposal is disabled until concurrent file replacement can be handled safely.</p>
              </section>
            )}

            {repo?.sourceType === 'local' && (
              <section className="panel-box mt-4">
                <h3 className="box-title">Manual patch export</h3>
                {exportStatus === null ? <p>Checking export eligibility…</p> : exportStatus.eligible ? (
                  <>
                    <p>Approved proposal: <span className="text-mono">{exportStatus.proposal_digest?.slice(0, 12)}</span></p>
                    <button type="button" className="btn-secondary" onClick={downloadPatch} disabled={pendingAction !== null}>
                      {pendingAction === 'export' ? 'Preparing patch…' : 'Download Patch'}
                    </button>
                  </>
                ) : <p>Export unavailable: {exportStatus.reason}</p>}
                {exportMessage && <p role="status">{exportMessage}</p>}
              </section>
            )}

            {fix.status === 'validation_passed' && !fix.prUrl && repo?.sourceType !== 'local' && (
              <section className="panel-box mt-4">
                <h3 className="box-title">Open a review pull request</h3>
                {prEligibility === null ? <p>Checking GitHub connection…</p> : prEligibility.eligible === true ? (
                  <button type="button" className="btn-primary" onClick={createPullRequest} disabled={pendingAction !== null}>
                    {pendingAction === 'open-pr' ? 'Opening pull request…' : 'Open GitHub pull request'}
                  </button>
                ) : <p>Pull request unavailable: {prEligibility.reason || 'GitHub authorization could not be verified.'}</p>}
              </section>
            )}

            {fix.prUrl && (
              <section className="panel-box mt-4" role="status">
                <CheckCircleIcon size={18} className="text-success" />
                <a href={fix.prUrl} target="_blank" rel="noreferrer">Pull request #{fix.prNumber} opened for review</a>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default FixReview;
