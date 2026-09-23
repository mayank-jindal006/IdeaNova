import React from 'react';
import { Link } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import Header from '../components/Header';
import {
  RepoIcon,
  AlertTriangleIcon,
  KeyIcon,
  CheckCircleIcon,
  PlusIcon
} from '../components/icons';
import {
  calculateComplianceScore,
  calculateHeuristicRisk
} from '../services/repoGuardService';

export const Dashboard = () => {
  const { repositories, findings, activities, metrics } = useRepoGuard();

  // Urgent findings requiring direct attention (Critical/High severity & Open or Needs Rotation)
  const urgentFindings = findings.filter(
    f => ['critical', 'high'].includes(f.severity) && ['open', 'needs_rotation'].includes(f.status)
  ).slice(0, 5);

  // Grouped active findings count by severity
  const activeFindings = findings.filter(f => !['fixed', 'false_positive'].includes(f.status));
  const sevCounts = {
    critical: activeFindings.filter(f => f.severity === 'critical').length,
    high: activeFindings.filter(f => f.severity === 'high').length,
    medium: activeFindings.filter(f => f.severity === 'medium').length,
    low: activeFindings.filter(f => f.severity === 'low').length,
  };

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
        {/* KPI Summary Cards */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Monitored Repos</span>
              <RepoIcon size={16} className="text-secondary" />
            </div>
            <span className="kpi-value text-mono">{metrics.totalRepos}</span>
            <span className="kpi-meta text-muted">All branches tracked</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Open Findings</span>
              <AlertTriangleIcon size={16} className={metrics.openFindingsCount > 0 ? "text-danger" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${metrics.openFindingsCount > 0 ? 'text-danger' : 'text-primary'}`}>
              {metrics.openFindingsCount}
            </span>
            <span className="kpi-meta text-muted">Requires remediation</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Critical Exposures</span>
              <AlertTriangleIcon size={16} className={metrics.criticalFindingsCount > 0 ? "text-danger" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${metrics.criticalFindingsCount > 0 ? 'text-danger' : 'text-success'}`}>
              {metrics.criticalFindingsCount}
            </span>
            <span className="kpi-meta text-muted">Immediate risk</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Needs Rotation</span>
              <KeyIcon size={16} className={metrics.needsRotationCount > 0 ? "text-warning" : "text-muted"} />
            </div>
            <span className={`kpi-value text-mono ${metrics.needsRotationCount > 0 ? 'text-warning' : 'text-primary'}`}>
              {metrics.needsRotationCount}
            </span>
            <span className="kpi-meta text-muted">Historical / leaked</span>
          </div>

          <div className="kpi-card">
            <div className="kpi-top">
              <span className="kpi-label">Avg Compliance</span>
              <CheckCircleIcon size={16} className="text-success" />
            </div>
            <span className="kpi-value text-mono text-success">
              {metrics.avgCompliance}%
            </span>
            <span className="kpi-meta text-muted">OWASP & ASVS index</span>
          </div>
        </div>

        {/* 2-Column Grid: Repositories Posture & Severity Distribution */}
        <div className="dashboard-grid-2col">
          {/* Repositories Security Posture Table */}
          <div className="card dashboard-main-card">
            <div className="card-header">
              <div>
                <h3 className="card-title">Repository Security Posture</h3>
                <p className="card-subtitle">Calculated compliance index and transparent heuristic risk per repository.</p>
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
                    <th className="text-right">Open Findings</th>
                    <th className="text-right">Critical</th>
                    <th className="text-right">Compliance</th>
                    <th className="text-right">Heuristic Risk</th>
                    <th className="text-right">Last Scan</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {repositories.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="text-center text-muted py-4">
                        No repositories connected yet. Add a repository to begin monitoring.
                      </td>
                    </tr>
                  ) : (
                    repositories.map((repo) => {
                      const repoFindings = findings.filter(f => f.repoId === repo.id);
                      const openCount = repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length;
                      const critCount = repoFindings.filter(f => f.severity === 'critical' && !['fixed', 'false_positive'].includes(f.status)).length;
                      const complianceScore = calculateComplianceScore(repoFindings);
                      const riskData = calculateHeuristicRisk(repo, repoFindings);

                      return (
                        <tr key={repo.id}>
                          <td>
                            <Link to={`/repositories/${repo.id}`} className="font-semibold text-mono text-link">
                              {repo.name}
                            </Link>
                            <div className="text-xs text-muted">{repo.fullName}</div>
                          </td>
                          <td className="text-right text-mono font-medium">
                            {openCount > 0 ? (
                              <span className="badge-counter text-danger">{openCount}</span>
                            ) : (
                              <span className="badge-counter text-success">0</span>
                            )}
                          </td>
                          <td className="text-right text-mono font-semibold text-danger">
                            {critCount > 0 ? critCount : '-'}
                          </td>
                          <td className="text-right font-medium">
                            <span className={complianceScore >= 80 ? 'text-success' : complianceScore >= 50 ? 'text-warning' : 'text-danger'}>
                              {complianceScore}%
                            </span>
                          </td>
                          <td className="text-right text-mono font-semibold">
                            <span className={riskData.score >= 60 ? 'text-danger' : riskData.score >= 30 ? 'text-warning' : 'text-success'}>
                              {riskData.score} / 100
                            </span>
                          </td>
                          <td className="text-right text-xs text-secondary">
                            {repo.lastScannedAt ? new Date(repo.lastScannedAt).toLocaleDateString() : 'Never'}
                          </td>
                          <td className="text-right">
                            <Link to={`/repositories/${repo.id}`} className="btn-sm btn-secondary">
                              Inspect
                            </Link>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right Column: Severity Breakdown & Attention Required */}
          <div className="dashboard-side-col">
            {/* Severity Distribution */}
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Active Severity Breakdown</h3>
              </div>
              <div className="severity-distribution-list">
                <div className="severity-row">
                  <div className="severity-label-wrap">
                    <SeverityBadge severity="critical" />
                    <span className="severity-row-desc">Immediate exploitation threat</span>
                  </div>
                  <span className="severity-row-count text-danger font-bold text-mono">
                    {sevCounts.critical}
                  </span>
                </div>

                <div className="severity-row">
                  <div className="severity-label-wrap">
                    <SeverityBadge severity="high" />
                    <span className="severity-row-desc">Elevated risk / known CVE</span>
                  </div>
                  <span className="severity-row-count text-warning font-bold text-mono">
                    {sevCounts.high}
                  </span>
                </div>

                <div className="severity-row">
                  <div className="severity-label-wrap">
                    <SeverityBadge severity="medium" />
                    <span className="severity-row-desc">Configuration / limited impact</span>
                  </div>
                  <span className="severity-row-count text-info font-bold text-mono">
                    {sevCounts.medium}
                  </span>
                </div>

                <div className="severity-row">
                  <div className="severity-label-wrap">
                    <SeverityBadge severity="low" />
                    <span className="severity-row-desc">Informational / hygiene</span>
                  </div>
                  <span className="severity-row-count text-muted font-bold text-mono">
                    {sevCounts.low}
                  </span>
                </div>
              </div>
            </div>

            {/* Recent Activity Log */}
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Recent Security Activity</h3>
              </div>
              <div className="activity-timeline-list">
                {activities.slice(0, 4).map((act) => (
                  <div key={act.id} className="activity-item">
                    <div className="activity-dot" />
                    <div className="activity-content">
                      <div className="activity-header">
                        <span className="activity-title">{act.title}</span>
                        <span className="activity-time text-mono">
                          {new Date(act.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                      <p className="activity-desc">{act.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Immediate Attention Required Section */}
        {urgentFindings.length > 0 && (
          <div className="card mt-4">
            <div className="card-header">
              <div>
                <h3 className="card-title text-danger">⚠️ High Priority Findings Requiring Attention</h3>
                <p className="card-subtitle">Exposed credentials and critical dependencies that impact overall risk.</p>
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Vulnerability / Secret ID</th>
                    <th>Repository</th>
                    <th>Location</th>
                    <th>Status</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {urgentFindings.map((f) => (
                    <tr key={f.id}>
                      <td><SeverityBadge severity={f.severity} /></td>
                      <td className="text-capitalize font-medium">{f.type}</td>
                      <td>
                        <Link to={`/findings/${f.id}`} className="font-semibold text-mono text-link">
                          {f.ruleId}
                        </Link>
                        <div className="text-xs text-secondary">{f.title}</div>
                      </td>
                      <td className="text-mono text-sm">{f.repoId}</td>
                      <td className="text-mono text-sm">{f.filePath}{f.line ? `:${f.line}` : ''}</td>
                      <td><StatusChip status={f.status} /></td>
                      <td className="text-right">
                        <Link to={`/findings/${f.id}/fix`} className="btn-sm btn-primary">
                          Review Fix &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
