import React, { useState, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import Header from '../components/Header';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import RiskFactorBreakdown from '../components/RiskFactorBreakdown';
import EmptyState from '../components/EmptyState';
import {
  RefreshCwIcon,
  SearchIcon,
  CheckCircleIcon,
  ClockIcon
} from '../components/icons';
import {
  calculateComplianceScore,
  calculateHeuristicRisk,
  getOWASPComplianceBreakdown
} from '../services/repoGuardService';

export const RepositoryDetail = () => {
  const { repoId } = useParams();
  const navigate = useNavigate();
  const { repositories, findings, scans } = useRepoGuard();

  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'findings' | 'scans' | 'compliance' | 'risk'

  // Finding filters
  const [filterType, setFilterType] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const repo = repositories.find(r => r.id === repoId);
  const repoFindings = useMemo(() => {
    return findings.filter(f => f.repoId === repoId);
  }, [findings, repoId]);

  const repoScans = useMemo(() => {
    return scans.filter(s => s.repoId === repoId);
  }, [scans, repoId]);

  // Filtered findings for the Findings tab (called unconditionally)
  const filteredFindings = useMemo(() => {
    return repoFindings.filter(f => {
      if (filterType && f.type !== filterType) return false;
      if (filterSeverity && f.severity !== filterSeverity) return false;
      if (filterStatus && f.status !== filterStatus) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase().trim();
        const matches = (
          f.title.toLowerCase().includes(q) ||
          f.ruleId.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          (f.package && f.package.toLowerCase().includes(q))
        );
        if (!matches) return false;
      }
      return true;
    });
  }, [repoFindings, filterType, filterSeverity, filterStatus, searchQuery]);

  if (!repo) {
    return (
      <div className="page-content-padded">
        <EmptyState
          title="Repository Not Found"
          message={`The repository with ID "${repoId}" could not be located.`}
          actionText="Back to Repositories"
          onAction={() => navigate('/repositories')}
        />
      </div>
    );
  }

  // Calculated metrics
  const complianceScore = calculateComplianceScore(repoFindings);
  const riskData = calculateHeuristicRisk(repo, repoFindings);
  const openCount = repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length;
  const critCount = repoFindings.filter(f => f.severity === 'critical' && !['fixed', 'false_positive'].includes(f.status)).length;
  const owaspControls = getOWASPComplianceBreakdown(repoFindings);

  return (
    <div className="repository-detail-page">
      <Header
        title={repo.name}
        subtitle={repo.fullName}
        breadcrumbs={[
          { label: 'Repositories', path: '/repositories' },
          { label: repo.name }
        ]}
        actions={
          <Link to={`/repositories/${repo.id}/scan`} className="btn-primary">
            <RefreshCwIcon size={14} />
            <span>Run Security Scan</span>
          </Link>
        }
      />

      <div className="page-content-padded">
        {/* Repo Meta Overview Bar */}
        <div className="repo-meta-bar">
          <div className="meta-item">
            <span className="meta-label">Default Branch:</span>
            <span className="meta-value text-mono">{repo.defaultBranch}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Last Scanned:</span>
            <span className="meta-value">
              {repo.lastScannedAt ? new Date(repo.lastScannedAt).toLocaleString() : 'Never'}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Primary Stack:</span>
            <span className="meta-value font-medium">{repo.language}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Git Commits (90d):</span>
            <span className="meta-value text-mono">{repo.signals?.commitCount90d || 0}</span>
          </div>
        </div>

        {/* Top KPI Cards */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <span className="kpi-label">Compliance Index</span>
            <span className={`kpi-value text-mono ${complianceScore >= 80 ? 'text-success' : complianceScore >= 50 ? 'text-warning' : 'text-danger'}`}>
              {complianceScore}%
            </span>
            <span className="kpi-meta text-muted">OWASP & ASVS evaluated</span>
          </div>

          <div className="kpi-card">
            <span className="kpi-label">Heuristic Risk Score</span>
            <span className={`kpi-value text-mono ${riskData.score >= 60 ? 'text-danger' : riskData.score >= 30 ? 'text-warning' : 'text-success'}`}>
              {riskData.score} <span className="text-sm text-muted">/ 100</span>
            </span>
            <span className="kpi-meta text-muted">Weighted signals</span>
          </div>

          <div className="kpi-card">
            <span className="kpi-label">Open Findings</span>
            <span className={`kpi-value text-mono ${openCount > 0 ? 'text-danger' : 'text-success'}`}>
              {openCount}
            </span>
            <span className="kpi-meta text-muted">Unresolved exposures</span>
          </div>

          <div className="kpi-card">
            <span className="kpi-label">Critical Vulnerabilities</span>
            <span className={`kpi-value text-mono ${critCount > 0 ? 'text-danger' : 'text-muted'}`}>
              {critCount}
            </span>
            <span className="kpi-meta text-muted">Immediate action required</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="tabs-bar">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'tab-btn-active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button
            className={`tab-btn ${activeTab === 'findings' ? 'tab-btn-active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings <span className="tab-counter">{repoFindings.length}</span>
          </button>
          <button
            className={`tab-btn ${activeTab === 'scans' ? 'tab-btn-active' : ''}`}
            onClick={() => setActiveTab('scans')}
          >
            Scan History <span className="tab-counter">{repoScans.length}</span>
          </button>
          <button
            className={`tab-btn ${activeTab === 'compliance' ? 'tab-btn-active' : ''}`}
            onClick={() => setActiveTab('compliance')}
          >
            Compliance Posture
          </button>
          <button
            className={`tab-btn ${activeTab === 'risk' ? 'tab-btn-active' : ''}`}
            onClick={() => setActiveTab('risk')}
          >
            Heuristic Risk Breakdown
          </button>
        </div>

        {/* TAB 1: OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="tab-content">
            <div className="grid-2col">
              {/* Left Column: Urgent Findings */}
              <div className="card">
                <div className="card-header">
                  <h3 className="card-title">Active Security Findings</h3>
                  <button className="btn-sm btn-secondary" onClick={() => setActiveTab('findings')}>
                    View All ({repoFindings.length}) &rarr;
                  </button>
                </div>
                {repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length === 0 ? (
                  <EmptyState
                    icon={CheckCircleIcon}
                    title="No Open Findings"
                    message="All detected credentials and dependency packages in this repository are secure or remediated."
                  />
                ) : (
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Rule / Vulnerability</th>
                          <th>Location</th>
                          <th>Status</th>
                          <th className="text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {repoFindings
                          .filter(f => !['fixed', 'false_positive'].includes(f.status))
                          .slice(0, 5)
                          .map((f) => (
                            <tr key={f.id}>
                              <td><SeverityBadge severity={f.severity} /></td>
                              <td>
                                <Link to={`/findings/${f.id}`} className="font-semibold text-mono text-link">
                                  {f.ruleId}
                                </Link>
                              </td>
                              <td className="text-mono text-xs">{f.filePath}{f.line ? `:${f.line}` : ''}</td>
                              <td><StatusChip status={f.status} /></td>
                              <td className="text-right">
                                <Link to={`/findings/${f.id}/fix`} className="btn-sm btn-primary">
                                  Fix &rarr;
                                </Link>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Right Column: Key Risk Factors */}
              <div>
                <RiskFactorBreakdown
                  factors={riskData.factors}
                  riskScore={riskData.score}
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: FINDINGS TABLE */}
        {activeTab === 'findings' && (
          <div className="tab-content">
            <div className="card">
              <div className="card-header findings-header">
                <div>
                  <h3 className="card-title">Repository Findings ({filteredFindings.length})</h3>
                  <p className="card-subtitle">Detailed security findings discovered during automated code scanning.</p>
                </div>

                {/* Filter Toolbar */}
                <div className="findings-filter-bar">
                  <div className="search-box-mini">
                    <SearchIcon size={12} className="search-icon" />
                    <input
                      type="text"
                      className="search-input-mini"
                      placeholder="Filter by title, rule, path..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>

                  <select
                    className="filter-select"
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                  >
                    <option value="">All Types</option>
                    <option value="secret">Secrets Only</option>
                    <option value="dependency">Dependencies Only</option>
                  </select>

                  <select
                    className="filter-select"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>

                  <select
                    className="filter-select"
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                  >
                    <option value="">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="needs_rotation">Needs Rotation</option>
                    <option value="fix_proposed">Fix Proposed</option>
                    <option value="pr_opened">PR Opened</option>
                    <option value="fixed">Fixed</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </div>
              </div>

              {filteredFindings.length === 0 ? (
                <EmptyState
                  title="No findings match filter criteria"
                  message="Try clearing your search query or adjusting the filters."
                  actionText="Reset Filters"
                  onAction={() => {
                    setFilterType('');
                    setFilterSeverity('');
                    setFilterStatus('');
                    setSearchQuery('');
                  }}
                />
              ) : (
                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Vulnerability / Rule ID</th>
                        <th>Location</th>
                        <th>Status</th>
                        <th>Confidence</th>
                        <th>OWASP Controls</th>
                        <th className="text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((f) => (
                        <tr key={f.id}>
                          <td><SeverityBadge severity={f.severity} /></td>
                          <td className="text-capitalize font-medium">{f.type}</td>
                          <td>
                            <Link to={`/findings/${f.id}`} className="font-semibold text-mono text-link">
                              {f.ruleId}
                            </Link>
                            <div className="text-xs text-muted">{f.title}</div>
                          </td>
                          <td className="text-mono text-xs">{f.filePath}{f.line ? `:${f.line}` : ''}</td>
                          <td><StatusChip status={f.status} /></td>
                          <td className="text-mono text-xs font-semibold">{Math.round(f.confidence * 100)}%</td>
                          <td>
                            {f.owaspIds?.map(id => (
                              <span key={id} className="badge-owasp">{id}</span>
                            ))}
                          </td>
                          <td className="text-right table-actions-cell">
                            <Link to={`/findings/${f.id}`} className="btn-sm btn-secondary mr-2">
                              Inspect
                            </Link>
                            <Link to={`/findings/${f.id}/fix`} className="btn-sm btn-primary">
                              Fix
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: SCANS */}
        {activeTab === 'scans' && (
          <div className="tab-content">
            <div className="card">
              <div className="card-header">
                <div>
                  <h3 className="card-title">Scan History</h3>
                  <p className="card-subtitle">Historical scan executions, discovered exposures, and run durations.</p>
                </div>
                <Link to={`/repositories/${repo.id}/scan`} className="btn-sm btn-primary">
                  <RefreshCwIcon size={12} />
                  <span>Execute New Scan</span>
                </Link>
              </div>

              {repoScans.length === 0 ? (
                <EmptyState
                  icon={ClockIcon}
                  title="No scan history recorded"
                  message="This repository has not executed an automated security scan yet."
                  actionText="Run First Scan"
                  onAction={() => navigate(`/repositories/${repo.id}/scan`)}
                />
              ) : (
                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Scan ID</th>
                        <th>Trigger</th>
                        <th>Commit SHA</th>
                        <th>Status</th>
                        <th>Started At</th>
                        <th>Duration</th>
                        <th className="text-right">Findings Discovered</th>
                      </tr>
                    </thead>
                    <tbody>
                      {repoScans.map((s) => (
                        <tr key={s.id}>
                          <td className="font-semibold text-mono">{s.id}</td>
                          <td className="text-capitalize">{s.trigger}</td>
                          <td className="text-mono text-xs">{s.commitSha.slice(0, 10)}</td>
                          <td>
                            <span className="badge-success text-capitalize">{s.status}</span>
                          </td>
                          <td className="text-xs text-secondary">
                            {new Date(s.startedAt).toLocaleString()}
                          </td>
                          <td className="text-mono text-xs">{s.durationSeconds}s</td>
                          <td className="text-right font-bold text-mono">
                            {s.findingsCount > 0 ? (
                              <span className="text-danger">{s.findingsCount}</span>
                            ) : (
                              <span className="text-success">0</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: COMPLIANCE */}
        {activeTab === 'compliance' && (
          <div className="tab-content">
            <div className="card">
              <div className="card-header">
                <div>
                  <h3 className="card-title">OWASP Top 10 & ASVS Control Mapping</h3>
                  <p className="card-subtitle">Automated evaluation against standardized industry security benchmarks.</p>
                </div>
                <div className="compliance-badge-large">
                  Score: <strong className="text-success">{complianceScore}%</strong>
                </div>
              </div>

              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Control ID</th>
                      <th>Standard Control Name</th>
                      <th>Description</th>
                      <th>Status</th>
                      <th className="text-right">Violations</th>
                    </tr>
                  </thead>
                  <tbody>
                    {owaspControls.map((ctrl) => (
                      <tr key={ctrl.id}>
                        <td className="font-semibold text-mono">{ctrl.id}</td>
                        <td className="font-medium">{ctrl.name}</td>
                        <td className="text-xs text-secondary">{ctrl.description}</td>
                        <td>
                          {ctrl.status === 'passing' ? (
                            <span className="badge-success">Passing</span>
                          ) : (
                            <span className="badge-danger">Failing</span>
                          )}
                        </td>
                        <td className="text-right">
                          {ctrl.findingsCount > 0 ? (
                            <button
                              className="btn-sm btn-secondary text-danger"
                              onClick={() => {
                                setActiveTab('findings');
                                setSearchQuery(ctrl.id);
                              }}
                            >
                              {ctrl.findingsCount} Issue(s) &rarr;
                            </button>
                          ) : (
                            <span className="text-muted text-xs">None</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: RISK */}
        {activeTab === 'risk' && (
          <div className="tab-content">
            <RiskFactorBreakdown
              factors={riskData.factors}
              riskScore={riskData.score}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default RepositoryDetail;
