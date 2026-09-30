import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client';
import Header from '../components/Header';
import AddRepoModal from '../components/AddRepoModal';
import EmptyState from '../components/EmptyState';
import {
  SearchIcon,
  PlusIcon,
  XIcon,
  RefreshCwIcon,
  RepoIcon,
  AlertTriangleIcon
} from '../components/icons';

export const Repositories = () => {
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('risk_desc'); // 'risk_desc' | 'compliance_desc' | 'name_asc'
  const [isModalOpen, setIsModalOpen] = useState(false);

  const [errorText, setErrorText] = useState(null);

  const fetchRepositories = async () => {
    setLoading(true);
    setErrorText(null);
    try {
      const data = await api.listRepositories();
      setRepositories(data || []);
    } catch (err) {
      setErrorText(err.message || 'Failed to load repositories from API.');
      setRepositories([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRepositories();
  }, []);

  const handleAddRepo = async (fullName) => {
    try {
      await api.createRepository(fullName);
      await fetchRepositories();
      setIsModalOpen(false);
    } catch (err) {
      alert(err.message || 'Failed to add repository');
    }
  };

  // Filter and sort
  const filteredRepos = useMemo(() => {
    let list = [...repositories];

    const q = searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(r => (r.full_name || '').toLowerCase().includes(q));
    }

    list.sort((a, b) => {
      const aRisk = a.latest_score?.risk_score ?? 0;
      const bRisk = b.latest_score?.risk_score ?? 0;
      const aComp = a.latest_score?.compliance_score ?? 100;
      const bComp = b.latest_score?.compliance_score ?? 100;

      switch (sortBy) {
        case 'risk_desc': return bRisk - aRisk;
        case 'risk_asc': return aRisk - bRisk;
        case 'compliance_desc': return bComp - aComp;
        case 'compliance_asc': return aComp - bComp;
        case 'name_asc': return (a.full_name || '').localeCompare(b.full_name || '');
        default: return 0;
      }
    });

    return list;
  }, [repositories, searchQuery, sortBy]);

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
            <div className="sort-group">
              <label htmlFor="repo-sort" className="sort-label">Sort by:</label>
              <select
                id="repo-sort"
                className="sort-select"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
              >
                <option value="risk_desc">Heuristic Risk: High to Low</option>
                <option value="risk_asc">Heuristic Risk: Low to High</option>
                <option value="compliance_desc">Compliance: High to Low</option>
                <option value="name_asc">Repository Name: A to Z</option>
              </select>
            </div>
            <button
              type="button"
              className="btn-secondary btn-icon-only"
              onClick={fetchRepositories}
              title="Refresh repositories"
            >
              <RefreshCwIcon size={14} className={loading ? 'spin-icon' : ''} />
            </button>
          </div>
        </div>

        {/* Repositories Table */}
        <div className="card">
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Repository Name</th>
                  <th>Default Branch</th>
                  <th>Compliance Index</th>
                  <th>Heuristic Risk Score</th>
                  <th className="text-right">Last Scan</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRepos.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <EmptyState
                        title="No Repositories Found"
                        message={searchQuery ? `No matches found for "${searchQuery}".` : "No repositories monitored yet."}
                        actionText="Add Repository"
                        onAction={() => setIsModalOpen(true)}
                      />
                    </td>
                  </tr>
                ) : (
                  filteredRepos.map((repo) => {
                    const compScore = repo.latest_score?.compliance_score ?? null;
                    const riskScore = repo.latest_score?.risk_score ?? null;

                    return (
                      <tr key={repo.id}>
                        <td>
                          <div className="repo-name-cell">
                            <RepoIcon size={16} className="text-secondary" />
                            <div>
                              <Link to={`/repositories/${repo.id}`} className="repo-title-link">
                                {repo.full_name}
                              </Link>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="badge badge-neutral text-mono">
                            {repo.default_branch || 'main'}
                          </span>
                        </td>
                        <td>
                          {compScore != null ? (
                            <div className="score-meter-wrap">
                              <span className="score-number font-bold text-success">
                                {compScore}%
                              </span>
                              <div className="meter-track">
                                <div
                                  className="meter-fill fill-compliance"
                                  style={{ width: `${compScore}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-secondary text-sm">Not scanned</span>
                          )}
                        </td>
                        <td>
                          {riskScore != null ? (
                            <div className="score-meter-wrap">
                              <span className={`score-number font-bold ${riskScore > 40 ? 'text-danger' : riskScore > 20 ? 'text-warning' : 'text-success'}`}>
                                {riskScore}/100
                              </span>
                              <div className="meter-track">
                                <div
                                  className="meter-fill"
                                  style={{
                                    width: `${Math.min(riskScore, 100)}%`,
                                    backgroundColor: riskScore > 40 ? 'var(--color-danger)' : riskScore > 20 ? 'var(--color-warning)' : 'var(--color-success)'
                                  }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-secondary text-sm">Pending</span>
                          )}
                        </td>
                        <td className="text-right text-secondary text-mono text-sm">
                          {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleDateString() : 'Never'}
                        </td>
                        <td className="text-right">
                          <div className="table-actions-group">
                            <Link
                              to={`/repositories/${repo.id}/scan`}
                              className="btn-secondary btn-sm"
                              title="Start security scan"
                            >
                              <RefreshCwIcon size={12} style={{ marginRight: '4px' }} />
                              Scan
                            </Link>
                            <Link
                              to={`/repositories/${repo.id}`}
                              className="btn-primary btn-sm"
                            >
                              Inspect
                            </Link>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Add Repository Modal */}
      {isModalOpen && (
        <AddRepoModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          onAdd={handleAddRepo}
        />
      )}
    </div>
  );
};

export default Repositories;
