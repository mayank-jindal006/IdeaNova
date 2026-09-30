import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import api from '../api/client';
import Header from '../components/Header';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import RiskFactorBreakdown from '../components/RiskFactorBreakdown';
import EmptyState from '../components/EmptyState';
import {
  ShieldIcon,
  AlertTriangleIcon,
  RefreshCwIcon,
  SearchIcon,
  XIcon,
  KeyIcon,
  PackageIcon,
  FileCodeIcon,
  DiffIcon
} from '../components/icons';

export const RepositoryDetail = () => {
  const { repoId } = useParams();
  const navigate = useNavigate();

  const [repo, setRepo] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState('all'); // 'all' | 'secret' | 'dependency'
  const [severityFilter, setSeverityFilter] = useState('all'); // 'all' | 'critical' | 'high' | 'medium' | 'low'
  const [statusFilter, setStatusFilter] = useState('all'); // 'all' | 'open' | 'fix_proposed' | 'pr_opened' | 'fixed' | 'false_positive' | 'needs_rotation'
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    let isMounted = true;
    const fetchRepoData = async () => {
      setLoading(true);
      setErrorText(null);
      try {
        const repoData = await api.getRepository(repoId);
        if (!isMounted) return;
        setRepo(repoData);

        const findingsData = await api.getRepositoryFindings(repoId);
        if (!isMounted) return;
        setFindings(findingsData || []);
      } catch (err) {
        if (!isMounted) return;
        setErrorText(err.message || 'Failed to load repository details from API.');
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchRepoData();
    return () => {
      isMounted = false;
    };
  }, [repoId]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (typeFilter !== 'all' && f.type !== typeFilter) return false;
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && f.status !== statusFilter) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const matchesTitle = (f.title || '').toLowerCase().includes(q);
        const matchesRule = (f.rule_id || '').toLowerCase().includes(q);
        const matchesPath = (f.file_path || '').toLowerCase().includes(q);
        if (!matchesTitle && !matchesRule && !matchesPath) return false;
      }
      return true;
    });
  }, [findings, typeFilter, severityFilter, statusFilter, searchQuery]);

  if (loading) {
    return (
      <div className="page-content-padded text-center" style={{ paddingTop: '80px' }}>
        <RefreshCwIcon size={24} className="spin-icon text-secondary" />
        <p className="text-secondary mt-3">Loading repository findings &amp; security posture...</p>
      </div>
    );
  }

  if (!repo && errorText) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Repository Not Found"
          message={`Repository #${repoId} could not be located.`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  const latestScore = repo?.latest_score;
  const complianceScore = latestScore?.compliance_score ?? null;
  const riskScore = latestScore?.risk_score ?? null;
  const riskFactors = latestScore?.risk_factors || [];

  return (
    <div className="repository-detail-page">
      <Header
        title={repo?.full_name || `Repository #${repoId}`}
        subtitle={`Branch: ${repo?.default_branch || 'main'} • Last scan: ${repo?.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleString() : 'Never'}`}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo?.full_name || `Repo #${repoId}` }
        ]}
        actions={
          <div className="header-action-group">
            <Link to={`/repositories/${repo?.id}/scan`} className="btn-primary">
              <RefreshCwIcon size={14} />
              <span>Run Security Scan</span>
            </Link>
          </div>
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

        {/* Repo Telemetry Posture Grid */}
        <div className="posture-grid">
          {/* Compliance Card */}
          <div className="card posture-card">
            <div className="card-header-clean">
              <div className="card-title-group">
                <ShieldIcon size={16} className="text-success" />
                <h3 className="card-title">Compliance Index</h3>
              </div>
              <span className="badge badge-success">OWASP &amp; ASVS</span>
            </div>
            <div className="posture-score-display">
              <span className="posture-score-number text-success font-bold">
                {complianceScore != null ? `${complianceScore}%` : '—'}
              </span>
              <p className="posture-score-desc">
                {complianceScore != null
                  ? 'Measured against OWASP Top 10 and ASVS security control verification.'
                  : 'No compliance index recorded yet. Run a scan to compute security metrics.'}
              </p>
            </div>
            <div className="meter-track">
              <div
                className="meter-fill fill-compliance"
                style={{ width: `${complianceScore != null ? complianceScore : 0}%` }}
              />
            </div>
          </div>

          {/* Heuristic Risk Score Card */}
          <div className="card posture-card">
            <div className="card-header-clean">
              <div className="card-title-group">
                <AlertTriangleIcon size={16} className="text-warning" />
                <h3 className="card-title">Heuristic Risk Score</h3>
              </div>
              <span className="badge badge-neutral">Signal-weighted</span>
            </div>
            <div className="posture-score-display">
              <span
                className={`posture-score-number font-bold ${
                  riskScore != null
                    ? riskScore > 40
                      ? 'text-danger'
                      : riskScore > 20
                      ? 'text-warning'
                      : 'text-success'
                    : 'text-muted'
                }`}
              >
                {riskScore != null ? `${riskScore}/100` : '—'}
              </span>
              <p className="posture-score-desc">
                {riskScore != null
                  ? 'Derived from Git history depth, credential severity, and environment hygiene.'
                  : 'Heuristic risk score pending repository security scan.'}
              </p>
            </div>
            <div className="meter-track">
              <div
                className="meter-fill"
                style={{
                  width: `${riskScore != null ? Math.min(riskScore, 100) : 0}%`,
                  backgroundColor:
                    riskScore != null
                      ? riskScore > 40
                        ? 'var(--color-danger)'
                        : riskScore > 20
                        ? 'var(--color-warning)'
                        : 'var(--color-success)'
                      : 'var(--border-color)'
                }}
              />
            </div>
          </div>
        </div>

        {/* Heuristic Risk Factors Breakdown */}
        <div className="card mb-4">
          <div className="card-header">
            <h3 className="card-title">Heuristic Risk Factor Breakdown</h3>
            <p className="card-subtitle">Transparent signal weights and score deductions for this repository.</p>
          </div>
          <div className="card-body">
            <RiskFactorBreakdown factors={riskFactors} totalScore={riskScore} />
          </div>
        </div>

        {/* Findings Filter Toolbar */}
        <div className="table-toolbar">
          <div className="search-box">
            <SearchIcon size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Filter findings by rule, file path, or title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button type="button" className="search-clear-btn" onClick={() => setSearchQuery('')}>
                <XIcon size={12} />
              </button>
            )}
          </div>

          <div className="toolbar-actions">
            <div className="filter-group">
              <label className="filter-label">Type:</label>
              <select className="filter-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                <option value="all">All Types</option>
                <option value="secret">Secrets Only</option>
                <option value="dependency">Dependencies Only</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Severity:</label>
              <select className="filter-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div className="filter-group">
              <label className="filter-label">Status:</label>
              <select className="filter-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="fix_proposed">Fix Proposed</option>
                <option value="pr_opened">PR Opened</option>
                <option value="needs_rotation">Needs Rotation</option>
                <option value="false_positive">False Positive</option>
                <option value="fixed">Fixed</option>
              </select>
            </div>
          </div>
        </div>

        {/* Findings Data Table */}
        <div className="card">
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding Title / Rule</th>
                  <th>Type</th>
                  <th>File Location</th>
                  <th>Status</th>
                  <th className="text-right">Remediation</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <EmptyState
                        title="No Security Findings Found"
                        message={findings.length === 0 ? "No active findings detected. Run a scan to inspect this repository." : "No findings match the current filter criteria."}
                      />
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <div className="finding-title-cell">
                          <Link to={`/findings/${finding.id}`} className="finding-title-link">
                            {finding.title}
                          </Link>
                          <span className="finding-rule-sub text-mono text-muted text-xs">
                            {finding.rule_id}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-neutral text-xs">
                          {finding.type === 'secret' ? <KeyIcon size={11} style={{ marginRight: '4px' }} /> : <PackageIcon size={11} style={{ marginRight: '4px' }} />}
                          {finding.type === 'secret' ? 'Secret' : 'Dependency'}
                        </span>
                      </td>
                      <td>
                        <span className="text-mono text-xs text-secondary">
                          <FileCodeIcon size={11} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                          {finding.file_path}{finding.line ? `:${finding.line}` : ''}
                        </span>
                      </td>
                      <td>
                        <StatusChip status={finding.status} />
                      </td>
                      <td className="text-right">
                        <div className="table-actions-group">
                          <Link to={`/findings/${finding.id}`} className="btn-secondary btn-sm">
                            Details
                          </Link>
                          <Link to={`/findings/${finding.id}/fix`} className="btn-primary btn-sm">
                            <DiffIcon size={12} style={{ marginRight: '4px' }} />
                            Fix / PR
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RepositoryDetail;
