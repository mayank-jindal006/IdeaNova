import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client';
import Header from '../components/Header';
import {
  RepoIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  PlusIcon,
  RefreshCwIcon
} from '../components/icons';

export const Dashboard = () => {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState(null);

  useEffect(() => {
    let isMounted = true;
    async function loadSummary() {
      setLoading(true);
      setErrorText(null);
      try {
        const data = await api.getDashboardSummary();
        if (isMounted) setSummary(data);
      } catch (err) {
        if (!isMounted) return;
        setErrorText(err.message || 'Failed to connect to RepoGuard Security API.');
        setSummary(null);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadSummary();
    return () => {
      isMounted = false;
    };
  }, []);

  const totals = summary?.totals || { repos: 0, findings: 0 };
  const sev = summary?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const repoScores = summary?.repo_scores || [];
  const trend = summary?.trend || [];

  const avgCompliance = repoScores.length > 0
    ? Math.round(repoScores.reduce((acc, r) => acc + (r.compliance_score || 0), 0) / repoScores.length)
    : null;

  return (
    <div className="dashboard-page">
      <Header
        title="Security Operations Overview"
        subtitle="Repository vulnerability posture, active credential exposures, and compliance telemetry."
        breadcrumbs={[]}
        actions={
          <Link to="/repositories" className="btn-primary">
            <PlusIcon size={14} />
            <span>Manage Repositories</span>
          </Link>
        }
      />

      <div className="page-content-padded">
        {/* Error notification if any */}
        {errorText && (
          <div className="panel-box error-alert-box mb-4">
            <div className="alert-top">
              <AlertTriangleIcon size={18} className="text-danger" />
              <h3 className="alert-title">Backend API Notice</h3>
            </div>
            <p className="alert-message">{errorText}</p>
          </div>
        )}

        {loading && (
          <div className="text-center py-4 mb-4">
            <RefreshCwIcon size={20} className="spin-icon text-secondary" />
            <span className="text-secondary ml-2">Loading security summary...</span>
          </div>
        )}

        {/* KPI Summary Cards */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Monitored Repos</span>
              <RepoIcon size={16} className="text-secondary" />
            </div>
            <span className="kpi-value text-mono">{totals.repos}</span>
            <span className="kpi-meta text-muted">All active branches</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Total Findings</span>
              <AlertTriangleIcon size={16} className={totals.findings > 0 ? "text-danger" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${totals.findings > 0 ? 'text-danger' : 'text-primary'}`}>
              {totals.findings}
            </span>
            <span className="kpi-meta text-muted">Detected exposures</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Critical Severity</span>
              <AlertTriangleIcon size={16} className={sev.critical > 0 ? "text-danger" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${sev.critical > 0 ? 'text-danger' : 'text-success'}`}>
              {sev.critical}
            </span>
            <span className="kpi-meta text-muted">Immediate action required</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">High Severity</span>
              <AlertTriangleIcon size={16} className={sev.high > 0 ? "text-warning" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${sev.high > 0 ? 'text-warning' : 'text-primary'}`}>
              {sev.high}
            </span>
            <span className="kpi-meta text-muted">Priority remediation</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Avg Compliance</span>
              <CheckCircleIcon size={16} className="text-success" />
            </div>
            <span className="kpi-value text-mono text-success">
              {avgCompliance != null ? `${avgCompliance}%` : '—'}
            </span>
            <span className="kpi-meta text-muted">OWASP &amp; ASVS index</span>
          </div>
        </div>

        {/* 2-Column Grid: Repositories Posture & Severity Distribution */}
        <div className="dashboard-grid-2col">
          {/* Repositories Security Posture Table */}
          <div className="card dashboard-main-card">
            <div className="card-header">
              <div>
                <h3 className="card-title">Repository Security Posture</h3>
                <p className="card-subtitle">Compliance score and Heuristic Risk Score per repository.</p>
              </div>
              <Link to="/repositories" className="card-header-link">
                View All &rarr;
              </Link>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Compliance Index</th>
                    <th>Heuristic Risk Score</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {repoScores.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="text-center py-4 text-muted">
                        No repository score data recorded yet. Run a scan to compute security metrics.
                      </td>
                    </tr>
                  ) : (
                    repoScores.map((repo) => (
                      <tr key={repo.repo_id}>
                        <td>
                          <Link to={`/repositories/${repo.repo_id}`} className="repo-table-link">
                            <RepoIcon size={14} className="text-secondary mr-2" />
                            <span className="font-bold text-primary">{repo.full_name}</span>
                          </Link>
                        </td>
                        <td>
                          <div className="score-meter-wrap">
                            <span className="score-number font-bold text-success">
                              {repo.compliance_score ?? 100}%
                            </span>
                            <div className="meter-track">
                              <div
                                className="meter-fill fill-compliance"
                                style={{ width: `${repo.compliance_score ?? 100}%` }}
                              />
                            </div>
                          </div>
                        </td>
                        <td>
                          <div className="score-meter-wrap">
                            <span className={`score-number font-bold ${(repo.risk_score || 0) > 40 ? 'text-danger' : (repo.risk_score || 0) > 20 ? 'text-warning' : 'text-success'}`}>
                              {repo.risk_score ?? 0}/100
                            </span>
                            <div className="meter-track">
                              <div
                                className="meter-fill"
                                style={{
                                  width: `${Math.min(repo.risk_score ?? 0, 100)}%`,
                                  backgroundColor: (repo.risk_score || 0) > 40 ? 'var(--color-danger)' : (repo.risk_score || 0) > 20 ? 'var(--color-warning)' : 'var(--color-success)'
                                }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="text-right">
                          <Link to={`/repositories/${repo.repo_id}`} className="btn-secondary btn-sm">
                            Inspect
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Severity Distribution & Trend Panel */}
          <div className="card dashboard-side-card">
            <div className="card-header">
              <h3 className="card-title">Severity Breakdown</h3>
            </div>
            <div className="card-body">
              <div className="severity-dist-list">
                <div className="sev-dist-row">
                  <span className="sev-dist-label">
                    <span className="dot dot-critical" />
                    <span>Critical</span>
                  </span>
                  <span className="sev-dist-count text-mono font-bold text-danger">{sev.critical}</span>
                </div>
                <div className="sev-dist-row">
                  <span className="sev-dist-label">
                    <span className="dot dot-high" />
                    <span>High</span>
                  </span>
                  <span className="sev-dist-count text-mono font-bold text-warning">{sev.high}</span>
                </div>
                <div className="sev-dist-row">
                  <span className="sev-dist-label">
                    <span className="dot dot-medium" />
                    <span>Medium</span>
                  </span>
                  <span className="sev-dist-count text-mono font-bold">{sev.medium}</span>
                </div>
                <div className="sev-dist-row">
                  <span className="sev-dist-label">
                    <span className="dot dot-low" />
                    <span>Low</span>
                  </span>
                  <span className="sev-dist-count text-mono text-muted">{sev.low}</span>
                </div>
              </div>

              {/* 7-Day Trend Section */}
              <div className="trend-section mt-4 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
                <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                  7-Day Detection Trend
                </h4>
                {trend.length === 0 ? (
                  <p className="text-muted text-sm italic">No trend points recorded within the last 7 days.</p>
                ) : (
                  <div className="trend-bars" style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', height: '60px' }}>
                    {trend.map((t, idx) => {
                      const count = t.findings || 0;
                      const maxCount = Math.max(...trend.map(item => item.findings || 0), 1);
                      const heightPct = Math.max(Math.round((count / maxCount) * 100), 15);
                      return (
                        <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', marginBottom: '2px' }}>{count}</span>
                          <div
                            style={{
                              width: '100%',
                              height: `${heightPct}%`,
                              backgroundColor: 'var(--color-primary)',
                              borderRadius: '2px'
                            }}
                            title={`${t.date}: ${count} findings`}
                          />
                          <span style={{ fontSize: '9px', color: 'var(--text-muted)', marginTop: '4px' }}>
                            {t.date ? t.date.slice(5) : ''}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
