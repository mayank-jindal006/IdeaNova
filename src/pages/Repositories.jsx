import React, { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useRepoGuard } from '../context/RepoGuardContext';
import Header from '../components/Header';
import AddRepoModal from '../components/AddRepoModal';
import EmptyState from '../components/EmptyState';
import {
  SearchIcon,
  PlusIcon,
  XIcon,
  RefreshCwIcon,
  RepoIcon
} from '../components/icons';
import {
  calculateComplianceScore,
  calculateHeuristicRisk
} from '../services/repoGuardService';

export const Repositories = () => {
  const navigate = useNavigate();
  const { repositories, findings } = useRepoGuard();

  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('risk_desc'); // 'risk_desc' | 'risk_asc' | 'compliance_desc' | 'name_asc'
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Filter and sort repositories
  const filteredRepos = useMemo(() => {
    let list = [...repositories];

    // Search filter
    const query = searchQuery.trim().toLowerCase();
    if (query) {
      list = list.filter(r =>
        r.name.toLowerCase().includes(query) ||
        r.fullName.toLowerCase().includes(query) ||
        (r.description && r.description.toLowerCase().includes(query))
      );
    }

    // Sort
    list.sort((a, b) => {
      const aFindings = findings.filter(f => f.repoId === a.id);
      const bFindings = findings.filter(f => f.repoId === b.id);
      const aRisk = calculateHeuristicRisk(a, aFindings).score;
      const bRisk = calculateHeuristicRisk(b, bFindings).score;
      const aCompliance = calculateComplianceScore(aFindings);
      const bCompliance = calculateComplianceScore(bFindings);

      switch (sortBy) {
        case 'risk_desc': return bRisk - aRisk;
        case 'risk_asc': return aRisk - bRisk;
        case 'compliance_desc': return bCompliance - aCompliance;
        case 'compliance_asc': return aCompliance - bCompliance;
        case 'name_asc': return a.name.localeCompare(b.name);
        default: return 0;
      }
    });

    return list;
  }, [repositories, findings, searchQuery, sortBy]);

  return (
    <div className="repositories-page">
      <Header
        title="Repositories"
        subtitle="Manage monitored code repositories, audit security postures, and initiate targeted scans."
        breadcrumbs={[{ label: 'Repositories' }]}
        actions={
          <button className="btn-primary" onClick={() => setIsModalOpen(true)}>
            <PlusIcon size={14} />
            <span>Add Repository</span>
          </button>
        }
      />

      <div className="page-content-padded">
        {/* Controls Toolbar: Search & Sort */}
        <div className="table-toolbar">
          <div className="search-box">
            <SearchIcon size={14} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search repositories by name or organization..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                type="button"
                className="search-clear-btn"
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
              >
                <XIcon size={12} />
              </button>
            )}
          </div>

          <div className="toolbar-actions">
            <label htmlFor="repo-sort-select" className="filter-label">Sort by:</label>
            <select
              id="repo-sort-select"
              className="filter-select"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="risk_desc">Highest Risk First</option>
              <option value="risk_asc">Lowest Risk First</option>
              <option value="compliance_desc">Highest Compliance</option>
              <option value="compliance_asc">Lowest Compliance</option>
              <option value="name_asc">Name (A-Z)</option>
            </select>
          </div>
        </div>

        {/* Repositories Table */}
        <div className="card">
          {filteredRepos.length === 0 ? (
            searchQuery ? (
              <EmptyState
                title="No matching repositories"
                message={`No repositories matched the query "${searchQuery}".`}
                actionText="Clear Search Filter"
                onAction={() => setSearchQuery('')}
              />
            ) : (
              <EmptyState
                icon={RepoIcon}
                title="No monitored repositories"
                message="You have not added any repositories to monitor yet."
                actionText="Add First Repository"
                onAction={() => setIsModalOpen(true)}
              />
            )
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Branch</th>
                    <th className="text-right">Open Findings</th>
                    <th className="text-right">Critical</th>
                    <th className="text-right">Compliance Score</th>
                    <th className="text-right">Heuristic Risk Score</th>
                    <th className="text-right">Last Scan</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRepos.map((repo) => {
                    const repoFindings = findings.filter(f => f.repoId === repo.id);
                    const openCount = repoFindings.filter(f => !['fixed', 'false_positive'].includes(f.status)).length;
                    const critCount = repoFindings.filter(f => f.severity === 'critical' && !['fixed', 'false_positive'].includes(f.status)).length;
                    const compliance = calculateComplianceScore(repoFindings);
                    const risk = calculateHeuristicRisk(repo, repoFindings).score;

                    return (
                      <tr key={repo.id}>
                        <td>
                          <Link to={`/repositories/${repo.id}`} className="font-semibold text-mono text-link">
                            {repo.name}
                          </Link>
                          <div className="text-xs text-muted">{repo.fullName}</div>
                        </td>
                        <td className="text-mono text-xs">{repo.defaultBranch}</td>
                        <td className="text-right font-medium text-mono">
                          {openCount > 0 ? (
                            <span className="badge-counter text-danger">{openCount}</span>
                          ) : (
                            <span className="badge-counter text-success">0</span>
                          )}
                        </td>
                        <td className="text-right font-bold text-mono">
                          {critCount > 0 ? (
                            <span className="text-danger">{critCount}</span>
                          ) : (
                            <span className="text-muted">-</span>
                          )}
                        </td>
                        <td className="text-right font-medium">
                          <span className={compliance >= 80 ? 'text-success' : compliance >= 50 ? 'text-warning' : 'text-danger'}>
                            {compliance}%
                          </span>
                        </td>
                        <td className="text-right font-bold text-mono">
                          <span className={risk >= 60 ? 'text-danger' : risk >= 30 ? 'text-warning' : 'text-success'}>
                            {risk} / 100
                          </span>
                        </td>
                        <td className="text-right text-xs text-secondary">
                          {repo.lastScannedAt ? new Date(repo.lastScannedAt).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="text-right table-actions-cell">
                          <Link to={`/repositories/${repo.id}/scan`} className="btn-sm btn-primary mr-2" title="Run Security Scan">
                            <RefreshCwIcon size={12} />
                            <span>Scan</span>
                          </Link>
                          <Link to={`/repositories/${repo.id}`} className="btn-sm btn-secondary">
                            Details
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Add Repository Modal */}
      <AddRepoModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onRepoAdded={(created) => navigate(`/repositories/${created.id}`)}
      />
    </div>
  );
};

export default Repositories;
