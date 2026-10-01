import React, { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/client';
import {
  CheckCircleIcon,
  AlertTriangleIcon,
  RefreshCwIcon,
  DiffIcon,
  ExternalLinkIcon,
  KeyIcon,
  FileCodeIcon
} from './icons';

// Step visual and semantic configuration
const STEP_CONFIG = {
  detected: {
    label: 'Secret Detected',
    badgeClass: 'step-badge-detected',
    dotClass: 'dot-warning',
    desc: 'Scanner discovered exposed credential in commit/working tree.',
    icon: KeyIcon
  },
  fix_generated: {
    label: 'AI Fix Synthesized',
    badgeClass: 'step-badge-generated',
    dotClass: 'dot-primary',
    desc: 'LLM generated full-file remediation patch and env templates.',
    icon: DiffIcon
  },
  skipped: {
    label: 'Remediation Skipped',
    badgeClass: 'step-badge-skipped',
    dotClass: 'dot-muted',
    desc: 'Fix bypassed: low confidence or architectural change required.',
    icon: AlertTriangleIcon
  },
  pr_opened: {
    label: 'Pull Request Opened',
    badgeClass: 'step-badge-opened',
    dotClass: 'dot-primary',
    desc: 'Created remediation branch and opened GitHub pull request.',
    icon: ExternalLinkIcon
  },
  ci_pending: {
    label: 'CI Check Pending',
    badgeClass: 'step-badge-pending',
    dotClass: 'dot-pending pulse-dot',
    desc: 'GitHub Actions workflow triggered on remediation branch.',
    icon: RefreshCwIcon,
    spin: true
  },
  ci_passed: {
    label: 'CI Workflow Passed',
    badgeClass: 'step-badge-passed',
    dotClass: 'dot-success',
    desc: 'Automated test suite passed cleanly. Ready for human review.',
    icon: CheckCircleIcon
  },
  ci_failed: {
    label: 'CI Workflow Failed',
    badgeClass: 'step-badge-failed',
    dotClass: 'dot-danger',
    desc: 'Automated test failure detected. Invoking self-healing repair.',
    icon: AlertTriangleIcon
  },
  repaired: {
    label: 'Self-Healing Patch Pushed',
    badgeClass: 'step-badge-repaired',
    dotClass: 'dot-success pulse-dot',
    desc: 'Agent inspected CI logs, repaired syntax/import error, and pushed commit.',
    icon: RefreshCwIcon
  },
  repair_failed: {
    label: 'Self-Healing Repair Failed',
    badgeClass: 'step-badge-failed',
    dotClass: 'dot-danger',
    desc: 'Repair patch did not pass Gitleaks or syntax validation.',
    icon: AlertTriangleIcon
  },
  gave_up: {
    label: 'Manual Review Requested',
    badgeClass: 'step-badge-gaveup',
    dotClass: 'dot-danger',
    desc: 'Reached MAX_REPAIR_ATTEMPTS (2). Human intervention required.',
    icon: AlertTriangleIcon
  },
  error: {
    label: 'Agent Pipeline Error',
    badgeClass: 'step-badge-failed',
    dotClass: 'dot-danger',
    desc: 'An unexpected exception halted the self-healing workflow.',
    icon: AlertTriangleIcon
  }
};

export const AgentActivityTimeline = ({
  repoId,
  findingId = null,
  fixId = null,
  title = 'Self-Healing Agent Activity Timeline',
  compact = false
}) => {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState(null);
  const [isPolling, setIsPolling] = useState(true);
  const [filterStep, setFilterStep] = useState('all');
  const timerRef = useRef(null);

  const fetchRuns = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setErrorText(null);
    try {
      const data = await api.getAgentRuns({
        repo_id: repoId,
        finding_id: findingId,
        fix_id: fixId
      });

      if (Array.isArray(data)) {
        setRuns(data);
      } else {
        setRuns([]);
      }
    } catch (err) {
      setErrorText(err.message || 'Could not load agent activity');
      setRuns([]);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [repoId, findingId, fixId]);

  useEffect(() => {
    fetchRuns(false);
  }, [fetchRuns]);

  // Polling setup: while active steps exist or polling is enabled
  useEffect(() => {
    if (!isPolling) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      fetchRuns(true);
    }, 4000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPolling, fetchRuns]);

  // Filter runs
  const filteredRuns = runs.filter((run) => {
    if (filterStep !== 'all' && run.step !== filterStep) return false;
    return true;
  });

  // Check if any run is currently active
  const hasActiveRun = runs.some((r) =>
    ['detected', 'fix_generated', 'pr_opened', 'ci_pending', 'repaired'].includes(r.step)
  );

  return (
    <div className={`agent-timeline-container ${compact ? 'timeline-compact' : ''}`}>
      {/* Timeline Controls & Header */}
      <div className="timeline-header-bar">
        <div className="timeline-title-area">
          <div className="timeline-live-indicator">
            <span className={`pulse-circle ${hasActiveRun ? 'active-pulse' : 'settled-pulse'}`} />
            <span className="live-status-text">
              {hasActiveRun ? 'Self-Healing Agent Active' : 'Agent Pipeline Settled'}
            </span>
          </div>
          <h3 className="timeline-title">{title}</h3>
          <p className="timeline-subtitle text-xs text-secondary">
            Continuous loop: Detect → Synthesize Fix → Open PR → CI Telemetry → Automated Log Repair.
          </p>
        </div>

        <div className="timeline-actions">
          <div className="filter-group">
            <label className="text-xs text-muted">Step:</label>
            <select
              className="filter-select select-xs"
              value={filterStep}
              onChange={(e) => setFilterStep(e.target.value)}
            >
              <option value="all">All Steps ({runs.length})</option>
              <option value="detected">Detected</option>
              <option value="fix_generated">Fix Generated</option>
              <option value="pr_opened">PR Opened</option>
              <option value="ci_failed">CI Failed</option>
              <option value="repaired">Repaired</option>
              <option value="ci_passed">CI Passed</option>
            </select>
          </div>

          <button
            type="button"
            className={`btn-ghost btn-xs ${isPolling ? 'active-poll' : ''}`}
            onClick={() => setIsPolling(!isPolling)}
            title={isPolling ? 'Pause background polling' : 'Resume live polling'}
          >
            <RefreshCwIcon size={12} className={isPolling && hasActiveRun ? 'spin-icon' : ''} />
            <span>{isPolling ? 'Polling (4s)' : 'Paused'}</span>
          </button>

          <button
            type="button"
            className="btn-secondary btn-xs"
            onClick={() => fetchRuns(false)}
            disabled={loading}
          >
            <RefreshCwIcon size={12} className={loading ? 'spin-icon' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Error state with Retry */}
      {errorText && (
        <div className="panel-box error-alert-box m-3" style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangleIcon size={16} className="text-danger" />
              <span className="text-sm font-bold text-danger">Could not load agent activity</span>
            </div>
            <button
              type="button"
              className="btn-secondary btn-xs"
              onClick={() => fetchRuns(false)}
            >
              <RefreshCwIcon size={11} style={{ marginRight: '4px' }} />
              <span>Retry</span>
            </button>
          </div>
          <p className="text-xs text-secondary mt-1 mb-0">{errorText}</p>
        </div>
      )}

      {/* Timeline Steps Stream */}
      <div className="timeline-body">
        {loading && runs.length === 0 ? (
          <div className="text-center p-4 text-secondary text-sm">
            <RefreshCwIcon size={16} className="spin-icon text-muted" style={{ marginRight: '8px' }} />
            <span>Loading agent activity...</span>
          </div>
        ) : filteredRuns.length === 0 && !errorText ? (
          <div className="timeline-empty text-center p-4">
            <p style={{ margin: '0 0 4px', fontWeight: 600, color: 'var(--text-primary)' }}>
              No agent activity yet
            </p>
            <p className="text-xs text-secondary" style={{ margin: 0 }}>
              Runs will appear here automatically when security scans or push events trigger self-healing remediation.
            </p>
          </div>
        ) : (
          <div className="timeline-stream">
            {filteredRuns.map((run, idx) => {
              const cfg = STEP_CONFIG[run.step] || STEP_CONFIG.error;
              const Icon = cfg.icon;
              const isCiFail = run.step === 'ci_failed';
              const isRepaired = run.step === 'repaired';
              const isPassed = run.step === 'ci_passed';

              return (
                <div
                  key={run.id || idx}
                  className={`timeline-item ${isCiFail ? 'item-failed' : ''} ${isRepaired ? 'item-repaired' : ''} ${isPassed ? 'item-passed' : ''}`}
                >
                  {/* Vertical connecting line & dot */}
                  <div className="timeline-gutter">
                    <span className={`timeline-dot ${cfg.dotClass}`}>
                      {Icon && <Icon size={11} className={cfg.spin ? 'spin-icon' : ''} />}
                    </span>
                    {idx < filteredRuns.length - 1 && <span className="timeline-line" />}
                  </div>

                  {/* Event Content */}
                  <div className="timeline-card">
                    <div className="timeline-card-header">
                      <div className="timeline-card-badges">
                        <span className={`step-badge ${cfg.badgeClass}`}>
                          {cfg.label}
                        </span>
                        {run.attempt > 0 && (
                          <span className="attempt-badge text-mono text-xs">
                            Repair #{run.attempt}
                          </span>
                        )}
                        {run.fix_id && (
                          <span className="badge badge-neutral text-mono text-xs">
                            Fix #{run.fix_id}
                          </span>
                        )}
                        {run.finding_id && (
                          <span className="badge badge-neutral text-mono text-xs">
                            Finding #{run.finding_id}
                          </span>
                        )}
                      </div>
                      <time className="timeline-time text-xs text-muted">
                        {run.created_at ? new Date(run.created_at).toLocaleTimeString() : 'Just now'}
                      </time>
                    </div>

                    <p className="timeline-desc text-xs text-secondary">
                      {cfg.desc}
                    </p>

                    {/* Detail block - with special highlighting for CI failures and log output */}
                    {run.detail && (
                      <div className={`timeline-detail-box ${isCiFail ? 'detail-ci-failure' : ''} ${isRepaired ? 'detail-repaired' : ''}`}>
                        {isCiFail ? (
                          <div className="ci-failure-block">
                            <div className="ci-failure-label text-mono text-xs">
                              <AlertTriangleIcon size={12} className="text-danger" />
                              <span>CI Failure Log Output:</span>
                            </div>
                            <pre className="ci-error-terminal text-mono text-xs">
                              {run.detail}
                            </pre>
                            <span className="ci-repair-trigger-hint text-xs">
                              ⚡ Self-healing agent intercepted test failure → Triggering LLM repair routine...
                            </span>
                          </div>
                        ) : isRepaired ? (
                          <div className="repaired-block">
                            <div className="repaired-label text-mono text-xs text-success">
                              <CheckCircleIcon size={12} />
                              <span>Self-Healing Patch Applied:</span>
                            </div>
                            <p className="repaired-text text-mono text-xs">
                              {run.detail}
                            </p>
                          </div>
                        ) : (
                          <div className="detail-standard text-mono text-xs">
                            <FileCodeIcon size={11} className="detail-icon" />
                            <span>{run.detail}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentActivityTimeline;
