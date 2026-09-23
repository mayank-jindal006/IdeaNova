import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import Header from '../components/Header';
import EmptyState from '../components/EmptyState';
import {
  RefreshCwIcon,
  CheckCircleIcon,
  AlertTriangleIcon,
  ArrowRightIcon
} from '../components/icons';

export const ScanProgress = () => {
  const { repoId } = useParams();
  const navigate = useNavigate();
  const { repositories, findings, runScan } = useRepoGuard();

  const repo = repositories.find(r => r.id === repoId);

  const [scanState, setScanState] = useState({
    stage: 'idle', // 'idle' | 'queued' | 'scanning_secrets' | 'scanning_deps' | 'analysing' | 'completed' | 'failed'
    label: 'Ready to scan',
    progress: 0
  });
  const [logs, setLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const terminalRef = useRef(null);

  const stagesList = [
    { key: 'queued', name: '1. Ingestion', desc: 'Git tree clone & HEAD checkout' },
    { key: 'scanning_secrets', name: '2. Secret Scan', desc: 'Gitleaks entropy & regex pattern scan' },
    { key: 'scanning_deps', name: '3. Dependency Scan', desc: 'OSV.dev CVE database reconciliation' },
    { key: 'analysing', name: '4. Analysis', desc: 'OWASP / ASVS mapping & Heuristic risk computation' },
    { key: 'completed', name: '5. Completed', desc: 'Telemetry updated & scan artifact recorded' }
  ];

  const addLog = (text) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${text}`]);
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  // Execute scan
  const executeScan = async () => {
    if (isScanning || !repo) return;
    setIsScanning(true);
    setErrorMsg(null);
    setLogs([]);
    addLog(`Initiating RepoGuard pipeline for repository: ${repo.fullName} (branch: ${repo.defaultBranch})`);

    try {
      const result = await runScan(repo.id, (update) => {
        setScanState(update);
        addLog(update.label);
      });
      setScanResult(result);
      addLog(`Scan pipeline finished. Discovered ${result.findingsCount} active finding(s). Duration: ${result.durationSeconds}s.`);
    } catch (err) {
      setScanState({
        stage: 'failed',
        label: 'Scan failed: ' + (err.message || 'Unknown error'),
        progress: 0
      });
      setErrorMsg(err.message || 'Scan execution encountered an error.');
      addLog(`FATAL: ${err.message || 'Scan aborted.'}`);
    } finally {
      setIsScanning(false);
    }
  };

  const hasTriggeredRef = useRef(false);

  // Auto-start scan on first entry if repo scan is queued
  useEffect(() => {
    if (repo && !hasTriggeredRef.current) {
      hasTriggeredRef.current = true;
      executeScan();
    }
  }, [repo]);

  if (!repo) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Repository Not Found"
          message={`Repository with identifier "${repoId}" does not exist in the monitored inventory.`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  const getStageStatus = (stageKey) => {
    const order = ['queued', 'scanning_secrets', 'scanning_deps', 'analysing', 'completed'];
    const currentIndex = order.indexOf(scanState.stage);
    const targetIndex = order.indexOf(stageKey);

    if (scanState.stage === 'completed') return 'done';
    if (scanState.stage === 'failed') {
      if (targetIndex < currentIndex) return 'done';
      if (targetIndex === currentIndex) return 'failed';
      return 'pending';
    }
    if (currentIndex > targetIndex) return 'done';
    if (currentIndex === targetIndex) return 'active';
    return 'pending';
  };

  const repoFindings = findings.filter(f => f.repoId === repo.id);
  const secretCount = repoFindings.filter(f => f.type === 'secret').length;
  const depCount = repoFindings.filter(f => f.type === 'dependency').length;

  return (
    <div className="scan-progress-page">
      <Header
        title={`Scan Pipeline: ${repo.name}`}
        subtitle={`Branch ${repo.defaultBranch} • Real-time Gitleaks and OSV.dev static analysis execution.`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo.name, path: `/repositories/${repo.id}` },
          { label: 'Scan Pipeline' }
        ]}
        actions={
          <div className="header-action-group">
            <Link to={`/repositories/${repo.id}`} className="btn-secondary">
              Back to Repository
            </Link>
            <button
              className="btn-primary"
              onClick={executeScan}
              disabled={isScanning}
            >
              <RefreshCwIcon size={14} className={isScanning ? 'spin-icon' : ''} />
              <span>{isScanning ? 'Scanning in Progress...' : 'Run Scan Again'}</span>
            </button>
          </div>
        }
      />

      <div className="page-content-padded">
        {/* Progress Bar & Summary */}
        <div className="panel-box scan-summary-card">
          <div className="scan-header-top">
            <div className="scan-status-info">
              <span className={`status-pill ${scanState.stage === 'completed' ? 'pill-success' : scanState.stage === 'failed' ? 'pill-danger' : 'pill-active'}`}>
                {scanState.stage === 'completed' ? 'SCAN COMPLETE' : scanState.stage === 'failed' ? 'SCAN FAILED' : 'ANALYSIS IN PROGRESS'}
              </span>
              <h2 className="scan-stage-headline">{scanState.label}</h2>
            </div>
            <div className="scan-percentage text-mono">
              {scanState.progress}%
            </div>
          </div>

          <div className="progress-bar-track">
            <div
              className={`progress-bar-fill ${scanState.stage === 'completed' ? 'fill-success' : scanState.stage === 'failed' ? 'fill-danger' : 'fill-primary'}`}
              style={{ width: `${scanState.progress}%` }}
              role="progressbar"
              aria-valuenow={scanState.progress}
              aria-valuemin="0"
              aria-valuemax="100"
            />
          </div>

          {/* Sequential Stages Grid */}
          <div className="scan-stages-grid">
            {stagesList.map((stg) => {
              const status = getStageStatus(stg.key);
              return (
                <div key={stg.key} className={`scan-stage-col stage-${status}`}>
                  <div className="stage-top">
                    <span className="stage-indicator">
                      {status === 'done' && <CheckCircleIcon size={14} className="text-success" />}
                      {status === 'active' && <span className="status-dot-pulse" />}
                      {status === 'failed' && <AlertTriangleIcon size={14} className="text-danger" />}
                      {status === 'pending' && <span className="stage-dot-pending" />}
                    </span>
                    <span className="stage-name">{stg.name}</span>
                  </div>
                  <p className="stage-desc">{stg.desc}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live Scan Log Terminal */}
        <div className="panel-box terminal-box">
          <div className="terminal-header">
            <div className="terminal-dots">
              <span className="terminal-dot" />
              <span className="terminal-dot" />
              <span className="terminal-dot" />
            </div>
            <div className="terminal-title text-mono">
              repoguard-scanner-agent // {repo.fullName}
            </div>
            <div className="terminal-badge text-mono">
              {isScanning ? 'RUNNING' : scanState.stage === 'completed' ? 'EXIT CODE 0' : 'IDLE'}
            </div>
          </div>

          <div className="terminal-body text-mono" ref={terminalRef}>
            {logs.length === 0 ? (
              <div className="terminal-empty">Ready. Awaiting scan pipeline initialization...</div>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="terminal-line">
                  {log}
                </div>
              ))
            )}
            {isScanning && (
              <div className="terminal-line terminal-cursor-line">
                <span className="terminal-prompt">&gt;</span> Executing static analysis AST walkers...
                <span className="terminal-blinking-cursor">_</span>
              </div>
            )}
          </div>
        </div>

        {/* Completion Result Card */}
        {scanState.stage === 'completed' && (
          <div className="panel-box scan-results-box">
            <div className="results-top">
              <div className="results-icon-wrap">
                <CheckCircleIcon size={24} className="text-success" />
              </div>
              <div className="results-text">
                <h3 className="results-title">Pipeline Analysis Complete</h3>
                <p className="results-desc">
                  Repository scan successfully analyzed the current branch. All findings have been indexed into the central security dashboard.
                </p>
              </div>
            </div>

            <div className="results-metrics-grid">
              <div className="result-metric-card">
                <span className="metric-num text-danger">{secretCount}</span>
                <span className="metric-lbl">Secret Findings</span>
              </div>
              <div className="result-metric-card">
                <span className="metric-num text-warning">{depCount}</span>
                <span className="metric-lbl">Dependency Vulnerabilities</span>
              </div>
              <div className="result-metric-card">
                <span className="metric-num">{scanResult?.durationSeconds || 3}s</span>
                <span className="metric-lbl">Execution Duration</span>
              </div>
              <div className="result-metric-card">
                <span className="metric-num text-mono text-secondary">
                  {scanResult?.commitSha?.slice(0, 10) || 'head-latest'}
                </span>
                <span className="metric-lbl">Commit Hash</span>
              </div>
            </div>

            <div className="results-actions">
              <Link to={`/repositories/${repo.id}`} className="btn-primary">
                <span>View Findings in Repository</span>
                <ArrowRightIcon size={14} />
              </Link>
              <button className="btn-secondary" onClick={executeScan} disabled={isScanning}>
                Run Another Scan
              </button>
            </div>
          </div>
        )}

        {/* Failure Box */}
        {scanState.stage === 'failed' && (
          <div className="panel-box error-alert-box">
            <div className="alert-top">
              <AlertTriangleIcon size={20} className="text-danger" />
              <h3 className="alert-title">Scan Failed</h3>
            </div>
            <p className="alert-message">{errorMsg || 'An unexpected error interrupted the scan pipeline.'}</p>
            <div className="alert-actions">
              <button className="btn-primary" onClick={executeScan}>
                Retry Scan
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanProgress;
