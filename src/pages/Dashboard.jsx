import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useSystemData } from '../context/SystemDataContext';
import { useAuth } from '../context/AuthContext';

// Simple SVGs for metrics icons
const RepoIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
);
const KeyIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3M12.4 12.4l-1.9-1.9"/></svg>
);
const AlertIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
);
const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
);
const BrainIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.44 2.5 2.5 0 0 1 0-3.12 3 3 0 0 1 0-4.88 2.5 2.5 0 0 1 0-3.12A2.5 2.5 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.44 2.5 2.5 0 0 0 0-3.12 3 3 0 0 0 0-4.88 2.5 2.5 0 0 0 0-3.12A2.5 2.5 0 0 0 14.5 2Z"/></svg>
);

export const Dashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { repositories, secrets, vulnerabilities, prs } = useSystemData();

  // 1. Calculations
  const totalRepos = repositories.length;
  
  // Active Secrets (only count 'exposed' and 'fixing')
  const activeSecrets = secrets.filter(s => s.status === 'exposed' || s.status === 'fixing').length;
  
  // Total CVEs (vulnerabilities count)
  const totalCVEs = vulnerabilities.length;
  
  // Average Compliance Score
  const avgCompliance = Math.round(repositories.reduce((sum, r) => sum + r.complianceScore, 0) / totalRepos);
  
  // Resolved Issues
  const resolvedIssues = secrets.filter(s => s.status === 'resolved').length;

  // Sorting repositories by risk probability for the predictive forecast
  const sortedRiskRepos = [...repositories].sort((a, b) => b.leakProbability - a.leakProbability);

  // Severe alert level counts
  const criticalIssuesCount = secrets.filter(s => s.severity === 'critical' && (s.status === 'exposed' || s.status === 'fixing')).length +
                               vulnerabilities.filter(v => v.severity === 'critical').length;
  const highIssuesCount = secrets.filter(s => s.severity === 'high' && (s.status === 'exposed' || s.status === 'fixing')).length +
                           vulnerabilities.filter(v => v.severity === 'high').length;
  const medIssuesCount = secrets.filter(s => s.severity === 'medium' && (s.status === 'exposed' || s.status === 'fixing')).length +
                          vulnerabilities.filter(v => v.severity === 'medium').length;

  return (
    <div className="animate-fade-in">
      {/* Welcome Banner */}
      <div style={{ marginBottom: '25px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ fontSize: '20px', fontWeight: '700' }}>Welcome back, {user?.username}</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
            System state analyzed. Security scoring reflects current repository posture.
          </p>
        </div>
        <div className="repo-lang-badge" style={{ padding: '6px 12px', fontSize: '12px' }}>
          Role: <strong style={{ color: 'var(--color-primary)' }}>{user?.role}</strong>
        </div>
      </div>

      {/* KPI metrics row */}
      <div className="metrics-grid">
        <div className="metric-card" onClick={() => navigate('/repositories')} style={{ cursor: 'pointer' }}>
          <div className="metric-info">
            <span className="metric-label">Compliance Index</span>
            <span className="metric-value" style={{ color: avgCompliance > 70 ? 'var(--color-success)' : avgCompliance > 50 ? 'var(--color-warning)' : 'var(--color-danger)' }}>
              {avgCompliance}%
            </span>
            <span className="metric-trend down">
              Average across teams
            </span>
          </div>
          <div className="metric-icon-box">
            <CheckIcon />
          </div>
        </div>

        <div className="metric-card" onClick={() => navigate('/repositories')} style={{ cursor: 'pointer' }}>
          <div className="metric-info">
            <span className="metric-label">Exposed Secrets</span>
            <span className="metric-value" style={{ color: activeSecrets > 0 ? 'var(--color-danger)' : 'var(--color-success)' }}>
              {activeSecrets}
            </span>
            <span className="metric-trend up">
              {activeSecrets > 0 ? 'Rotation required!' : 'None exposed'}
            </span>
          </div>
          <div className="metric-icon-box" style={{ color: activeSecrets > 0 ? 'var(--color-danger)' : '' }}>
            <KeyIcon />
          </div>
        </div>

        <div className="metric-card" onClick={() => navigate('/sca')} style={{ cursor: 'pointer' }}>
          <div className="metric-info">
            <span className="metric-label">Dependency CVEs</span>
            <span className="metric-value" style={{ color: totalCVEs > 0 ? 'var(--color-warning)' : 'var(--color-success)' }}>
              {totalCVEs}
            </span>
            <span className="metric-trend neutral">
              Software Composition
            </span>
          </div>
          <div className="metric-icon-box" style={{ color: totalCVEs > 0 ? 'var(--color-warning)' : '' }}>
            <AlertIcon />
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-info">
            <span className="metric-label">AI Fixed Items</span>
            <span className="metric-value" style={{ color: 'var(--color-success)' }}>
              {resolvedIssues}
            </span>
            <span className="metric-trend down" style={{ color: 'var(--color-success)' }}>
              Auto-Remediation PRs
            </span>
          </div>
          <div className="metric-icon-box" style={{ color: 'var(--color-success)' }}>
            <CheckIcon />
          </div>
        </div>
      </div>

      {/* Analytics Charts Grid */}
      <div className="content-grid-2col">
        {/* Compliance Trend Line Chart */}
        <div className="glass-panel">
          <div className="glass-panel-header">
            <div>
              <h4 className="panel-title">Compliance Score Trend</h4>
              <p className="panel-description">Historical performance over the last 6 weeks</p>
            </div>
          </div>
          <div style={{ padding: '10px 0' }}>
            <svg className="line-chart-svg" viewBox="0 0 500 180">
              <defs>
                <linearGradient id="chart-gradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-primary)" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="var(--color-primary)" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              {/* Grid Lines */}
              <line x1="40" y1="20" x2="480" y2="20" className="svg-grid-line" />
              <line x1="40" y1="60" x2="480" y2="60" className="svg-grid-line" />
              <line x1="40" y1="100" x2="480" y2="100" className="svg-grid-line" />
              <line x1="40" y1="140" x2="480" y2="140" className="svg-grid-line" />

              {/* Area path */}
              <path 
                className="svg-area"
                d="M 40 140 L 40 120 L 128 108 L 216 112 L 304 88 L 392 64 L 480 40 L 480 140 Z"
              />

              {/* Line path */}
              <path 
                className="svg-line"
                d="M 40 120 L 128 108 L 216 112 L 304 88 L 392 64 L 480 40"
              />

              {/* Data points */}
              <circle cx="40" cy="120" className="svg-point" title="Week 1: 50%" />
              <circle cx="128" cy="108" className="svg-point" title="Week 2: 55%" />
              <circle cx="216" cy="112" className="svg-point" title="Week 3: 53%" />
              <circle cx="304" cy="88" className="svg-point" title="Week 4: 65%" />
              <circle cx="392" cy="64" className="svg-point" title="Week 5: 75%" />
              <circle cx="480" cy="40" className="svg-point" title="Week 6: 85%" />

              {/* Labels */}
              <text x="40" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Wk 1</text>
              <text x="128" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Wk 2</text>
              <text x="216" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Wk 3</text>
              <text x="304" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Wk 4</text>
              <text x="392" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Wk 5</text>
              <text x="480" y="162" fill="var(--text-secondary)" fontSize="10" textAnchor="middle">Current</text>

              <text x="30" y="123" fill="var(--text-primary)" fontSize="9" fontWeight="bold" textAnchor="end">50%</text>
              <text x="490" y="43" fill="var(--color-primary)" fontSize="9" fontWeight="bold" textAnchor="start">85%</text>
            </svg>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="glass-panel">
          <div className="glass-panel-header">
            <div>
              <h4 className="panel-title">Active Vulnerabilities</h4>
              <p className="panel-description">Findings grouped by severity rating</p>
            </div>
          </div>
          <div className="chart-container-mock">
            <div className="chart-bar-wrapper">
              <div 
                className="chart-bar" 
                style={{ height: `${(criticalIssuesCount / 6) * 100}%`, background: 'var(--color-danger)' }}
                data-value={criticalIssuesCount}
              ></div>
              <span className="chart-label">Critical</span>
            </div>
            <div className="chart-bar-wrapper">
              <div 
                className="chart-bar" 
                style={{ height: `${(highIssuesCount / 6) * 100}%`, background: 'var(--color-warning)' }}
                data-value={highIssuesCount}
              ></div>
              <span className="chart-label">High</span>
            </div>
            <div className="chart-bar-wrapper">
              <div 
                className="chart-bar" 
                style={{ height: `${(medIssuesCount / 6) * 100}%`, background: 'var(--color-info)' }}
                data-value={medIssuesCount}
              ></div>
              <span className="chart-label">Medium</span>
            </div>
          </div>
        </div>
      </div>

      {/* Predictive Risk Forecast Section */}
      <div className="glass-panel" style={{ marginBottom: '30px' }}>
        <div className="glass-panel-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BrainIcon />
              <h4 className="panel-title">Predictive Leak Forecast</h4>
            </div>
            <p className="panel-description">
              AI-driven risk model calculating the probability of a secret exposure in the next 30 days based on developer behavior and repository configuration.
            </p>
          </div>
          <span className="status-badge critical">
            Predictive Model Engine v1.0
          </span>
        </div>

        <div className="custom-table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Leak Probability (30d)</th>
                <th>Risk Classification</th>
                <th>Key Risk Factors Identified</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sortedRiskRepos.map((repo) => (
                <tr key={repo.id}>
                  <td>
                    <div style={{ fontWeight: '600' }}>{repo.name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Language: {repo.language} | Branch: {repo.branch}
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontWeight: '700', fontSize: '14px', width: '35px' }}>{repo.leakProbability}%</span>
                      <div className="progress-bar-container" style={{ margin: 0, maxWidth: '120px' }}>
                        <div 
                          className="progress-bar-fill" 
                          style={{ 
                            width: `${repo.leakProbability}%`,
                            background: repo.leakProbability > 80 ? 'var(--color-danger)' : repo.leakProbability > 50 ? 'var(--color-warning)' : 'var(--color-success)'
                          }}
                        ></div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className={`status-badge ${repo.riskLevel}`}>
                      {repo.riskLevel.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ maxWidth: '350px' }}>
                    <ul style={{ paddingLeft: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {repo.factors.map((factor, index) => (
                        <li key={index} style={{ marginBottom: '2px' }}>{factor}</li>
                      ))}
                    </ul>
                  </td>
                  <td>
                    <button 
                      className="btn-secondary" 
                      style={{ padding: '6px 12px', fontSize: '12px' }}
                      onClick={() => navigate(`/repositories?id=${repo.id}`)}
                    >
                      Audit Code
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent AI PRs list */}
      <div className="glass-panel">
        <div className="glass-panel-header">
          <div>
            <h4 className="panel-title">Active AI Remediation Pull Requests</h4>
            <p className="panel-description">PRs created by the AI Copilot to automatically seal code vulnerabilities</p>
          </div>
        </div>
        
        {prs.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '20px' }}>
            No active pull requests. Run security scans to generate remediation branches.
          </p>
        ) : (
          <div className="custom-table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Pull Request</th>
                  <th>Source Repository</th>
                  <th>Fix Type</th>
                  <th>Created</th>
                  <th>Status</th>
                  {user?.role !== 'CISO' && <th>Action</th>}
                </tr>
              </thead>
              <tbody>
                {prs.map(pr => {
                  const linkedRepo = repositories.find(r => r.id === pr.repoId);
                  return (
                    <tr key={pr.id}>
                      <td>
                        <div style={{ fontWeight: '600' }}>{pr.title}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          Author: <code style={{ color: 'var(--color-primary)' }}>{pr.author}</code>
                        </div>
                      </td>
                      <td>{linkedRepo ? linkedRepo.name : 'Unknown'}</td>
                      <td>
                        <span className="repo-lang-badge">Code Patch</span>
                      </td>
                      <td>{pr.createdAt}</td>
                      <td>
                        <span className={`status-badge ${pr.status === 'merged' ? 'resolved' : 'active-pr'}`}>
                          {pr.status === 'merged' ? 'MERGED' : 'OPEN'}
                        </span>
                      </td>
                      {user?.role !== 'CISO' && (
                        <td>
                          {pr.status === 'open' ? (
                            <button 
                              className="btn-primary" 
                              style={{ padding: '5px 10px', fontSize: '11px' }}
                              onClick={() => navigate(`/repositories?id=${pr.repoId}&prId=${pr.id}`)}
                            >
                              Review PR
                            </button>
                          ) : (
                            <span style={{ fontSize: '11px', color: 'var(--color-success)', fontWeight: '600' }}>Patch Applied</span>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
