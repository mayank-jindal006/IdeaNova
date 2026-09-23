import React, { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import Header from '../components/Header';
import DiffViewer from '../components/DiffViewer';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import RotationChecklist from '../components/RotationChecklist';
import EmptyState from '../components/EmptyState';
import {
  DiffIcon,
  CheckCircleIcon,
  AlertTriangleIcon,
  RefreshCwIcon,
  FileCodeIcon
} from '../components/icons';

export const FixReview = () => {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const { findings, fixes, repositories, generateFix, openPullRequest } = useRepoGuard();

  const finding = findings.find(f => f.id === findingId);
  const repo = repositories.find(r => r.id === finding?.repoId);
  const existingFix = fixes[findingId];

  const [genState, setGenState] = useState(existingFix ? 'generated' : 'idle'); // 'idle' | 'generating' | 'generated' | 'failed'
  const [prState, setPrState] = useState(existingFix?.prNumber ? 'opened' : 'idle'); // 'idle' | 'opening' | 'opened' | 'failed'
  const [errorText, setErrorText] = useState(null);

  if (!finding) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Security Finding Not Found"
          message={`Unable to locate finding with identifier "${findingId}".`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  // Handle fix generation
  const handleGenerateFix = async () => {
    if (genState === 'generating') return;
    setGenState('generating');
    setErrorText(null);
    try {
      await generateFix(finding.id);
      setGenState('generated');
    } catch (err) {
      setGenState('failed');
      setErrorText(err.message || 'Fix generation pipeline failed.');
    }
  };

  // Handle opening pull request
  const handleOpenPR = async () => {
    if (prState === 'opening' || prState === 'opened') return;
    setPrState('opening');
    setErrorText(null);
    try {
      await openPullRequest(finding.id);
      setPrState('opened');
    } catch (err) {
      setPrState('failed');
      setErrorText(err.message || 'Failed to initialize pull request.');
    }
  };

  const currentFix = fixes[findingId] || existingFix;

  return (
    <div className="fix-review-page">
      <Header
        title={`Remediation Review: ${finding.title}`}
        subtitle={`Repository: ${repo?.fullName || finding.repoId} • File: ${finding.filePath}`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo?.name || finding.repoId, path: `/repositories/${finding.repoId}` },
          { label: finding.id, path: `/findings/${finding.id}` },
          { label: 'Fix Review' }
        ]}
        actions={
          <div className="header-action-group">
            <Link to={`/findings/${finding.id}`} className="btn-secondary">
              Back to Finding
            </Link>

            {/* Step 1: Generate Fix Button */}
            {!currentFix && (
              <button
                type="button"
                className="btn-primary"
                onClick={handleGenerateFix}
                disabled={genState === 'generating'}
              >
                <RefreshCwIcon size={14} className={genState === 'generating' ? 'spin-icon' : ''} />
                <span>{genState === 'generating' ? 'Generating Validated Patch...' : 'Generate Proposed Fix'}</span>
              </button>
            )}

            {/* Step 2: Open PR Button */}
            {currentFix && !currentFix.prNumber && prState !== 'opened' && (
              <button
                type="button"
                className="btn-primary"
                onClick={handleOpenPR}
                disabled={prState === 'opening'}
              >
                <DiffIcon size={14} className={prState === 'opening' ? 'spin-icon' : ''} />
                <span>{prState === 'opening' ? 'Creating Pull Request...' : 'Open GitHub Pull Request'}</span>
              </button>
            )}

            {/* Step 3: PR Created Indicator */}
            {(currentFix?.prNumber || prState === 'opened') && (
              <span className="badge badge-success" style={{ padding: '6px 12px', fontSize: '13px' }}>
                <CheckCircleIcon size={14} style={{ marginRight: '6px' }} />
                PR #{currentFix?.prNumber || 42} Opened
              </span>
            )}
          </div>
        }
      />

      <div className="page-content-padded">
        {/* Error notification if any */}
        {errorText && (
          <div className="panel-box error-alert-box mb-4">
            <div className="alert-top">
              <AlertTriangleIcon size={18} className="text-danger" />
              <h3 className="alert-title">Remediation Pipeline Error</h3>
            </div>
            <p className="alert-message">{errorText}</p>
          </div>
        )}

        {/* PR Successfully Created Callout */}
        {(currentFix?.prNumber || prState === 'opened') && (
          <div className="pr-success-callout">
            <div className="pr-callout-top">
              <CheckCircleIcon size={20} className="text-success" />
              <div>
                <h4 className="pr-callout-title">
                  Pull Request #{currentFix?.prNumber || 42} Successfully Created
                </h4>
                <p className="pr-callout-desc">
                  A dedicated remediation branch has been opened for peer review. Code changes and AST validation certificates have been attached.
                </p>
              </div>
            </div>
            <div className="pr-meta-row text-mono">
              <span>Target Branch: <strong className="text-primary">{repo?.defaultBranch || 'main'}</strong></span>
              <span>Source Branch: <strong className="text-secondary">repoguard/fix-{finding.id}</strong></span>
              <span className="text-secondary">Mock Environment URL: github.com/repoguard-org/{repo?.name}/pull/{currentFix?.prNumber || 42}</span>
            </div>
          </div>
        )}

        <div className="fix-grid-layout">
          {/* Main Column */}
          <div className="fix-main-col">
            {/* Finding Summary & Danger Context */}
            <div className="panel-box fix-summary-panel">
              <div className="fix-panel-header">
                <div className="panel-headline-group">
                  <SeverityBadge severity={finding.severity} />
                  <StatusChip status={finding.status} />
                  <span className="file-badge text-mono">
                    <FileCodeIcon size={12} style={{ marginRight: '4px' }} />
                    {finding.filePath}
                  </span>
                </div>
              </div>

              <div className="danger-assessment-card">
                <div className="danger-heading">
                  <AlertTriangleIcon size={16} className="text-danger" />
                  <h4>Why This Exposure Is Hazardous</h4>
                </div>
                <p className="danger-text">
                  {currentFix?.explanation?.whyDangerous ||
                    'Hardcoded credentials or unpatched dependencies directly undermine repository boundary security. Committed tokens can be extracted from public mirrors or build pipelines to compromise infrastructure.'}
                </p>
              </div>

              <div className="remediation-strategy-card">
                <h4 className="strategy-heading">Proposed Remediation Strategy</h4>
                <p className="strategy-text">
                  {currentFix?.explanation?.howFixed ||
                    'Extract raw secrets into environment variable references (`process.env` or `os.environ`), purge credential literals from source, and verify template configuration.'}
                </p>
              </div>
            </div>

            {/* Code Diff Viewer */}
            <div className="panel-box fix-diff-panel">
              <div className="box-header">
                <div className="box-title-group">
                  <DiffIcon size={16} className="text-secondary" />
                  <h3 className="box-title">Remediation Code Diff</h3>
                </div>
                <span className="diff-badge text-mono">
                  {currentFix?.diff?.filePath || finding.filePath}
                </span>
              </div>

              {currentFix?.diff ? (
                <DiffViewer
                  filePath={currentFix.diff.filePath}
                  beforeContent={currentFix.diff.beforeContent}
                  afterContent={currentFix.diff.afterContent}
                />
              ) : (
                <div className="diff-placeholder-card">
                  <p>Awaiting fix generation. Click "Generate Proposed Fix" in the header to run AST validation.</p>
                  <button
                    type="button"
                    className="btn-primary btn-sm"
                    onClick={handleGenerateFix}
                    disabled={genState === 'generating'}
                  >
                    {genState === 'generating' ? 'Generating...' : 'Generate Proposed Fix'}
                  </button>
                </div>
              )}
            </div>

            {/* Validation & Verification Panel */}
            <div className="panel-box validation-panel">
              <div className="box-header">
                <div className="box-title-group">
                  <CheckCircleIcon size={16} className="text-success" />
                  <h3 className="box-title">Static Analysis AST Validation</h3>
                </div>
                <span className={`validation-status-badge ${currentFix?.validation ? 'val-pass' : 'val-pending'}`}>
                  {currentFix?.validation ? 'PASSED VERIFICATION' : 'NOT RUN'}
                </span>
              </div>

              <div className="validation-checks-list">
                <div className="val-check-item">
                  <span className="check-icon">
                    {currentFix?.validation?.secretRemoved ? (
                      <CheckCircleIcon size={16} className="text-success" />
                    ) : (
                      <span className="status-dot-pending" />
                    )}
                  </span>
                  <div className="check-details">
                    <span className="check-title">Zero Matching Token Verification</span>
                    <span className="check-desc">
                      Gitleaks AST scanner executed over proposed patch to guarantee no residual secrets exist.
                    </span>
                  </div>
                </div>

                <div className="val-check-item">
                  <span className="check-icon">
                    {currentFix?.validation?.syntaxOk ? (
                      <CheckCircleIcon size={16} className="text-success" />
                    ) : (
                      <span className="status-dot-pending" />
                    )}
                  </span>
                  <div className="check-details">
                    <span className="check-title">Syntactic Compilation & AST Integrity</span>
                    <span className="check-desc">
                      Abstract syntax tree parsed cleanly without syntax breakage or unresolved imports.
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Rotation Requirement Section */}
            {finding.rotationRequired && (
              <div className="panel-box fix-rotation-panel">
                <RotationChecklist ruleId={finding.ruleId} />
              </div>
            )}
          </div>

          {/* Sidebar Column: Review Tier & Pipeline Status */}
          <div className="fix-sidebar-col">
            <div className="panel-box tier-card">
              <h4 className="sidebar-card-title">Review Tier Classification</h4>
              <div className="tier-display">
                <span className="tier-name text-mono">
                  {currentFix?.tier === 'auto_branch' ? 'AUTO BRANCH' : 'PR REVIEW'}
                </span>
                <p className="tier-desc">
                  {currentFix?.tier === 'auto_branch'
                    ? 'A validated remediation path with high confidence, suitable for automated patch branch creation.'
                    : 'The proposed modification involves operational variables and requires human engineer review.'}
                </p>
              </div>

              <div className="tier-criteria-list">
                <div className="criteria-item">
                  <span className="criteria-bullet">▪</span>
                  <span>Requires human code review before merge</span>
                </div>
                <div className="criteria-item">
                  <span className="criteria-bullet">▪</span>
                  <span>Continuous integration tests must execute</span>
                </div>
                <div className="criteria-item">
                  <span className="criteria-bullet">▪</span>
                  <span>Credential rotation must complete at provider</span>
                </div>
              </div>
            </div>

            <div className="panel-box pr-action-card">
              <h4 className="sidebar-card-title">Pull Request Pipeline</h4>
              <p className="pr-pipeline-desc">
                Deploying this fix opens a clean Git branch with the AST-validated patch file and signs the commit.
              </p>

              {(!currentFix?.prNumber && prState !== 'opened') ? (
                <button
                  type="button"
                  className="btn-primary btn-block"
                  onClick={handleOpenPR}
                  disabled={!currentFix || prState === 'opening'}
                >
                  <DiffIcon size={14} />
                  <span>{prState === 'opening' ? 'Opening PR...' : 'Open GitHub Pull Request'}</span>
                </button>
              ) : (
                <div className="pr-completed-box">
                  <CheckCircleIcon size={16} className="text-success" />
                  <span>Branch active: PR opened</span>
                </div>
              )}

              <Link to={`/repositories/${finding.repoId}`} className="btn-secondary btn-block mt-3">
                Return to Repository
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FixReview;
