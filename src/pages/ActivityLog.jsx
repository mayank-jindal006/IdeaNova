import React from 'react';
import { Link } from 'react-router-dom';
import { useRepoGuard } from '../context/useRepoGuard';
import Header from '../components/Header';

export const ActivityLog = () => {
  const { activities, loading, apiError, refresh } = useRepoGuard();

  return (
    <div>
      <Header
        title="Security Activity"
        subtitle="Tenant-scoped audit history for repository, AI, review, validation, and pull-request actions."
        breadcrumbs={[{ label: 'Dashboard', path: '/' }, { label: 'Activity' }]}
        actions={<button type="button" className="btn-secondary" onClick={refresh}>Refresh</button>}
      />
      <div className="page-content-padded">
        {loading && <div className="panel-box mb-4" role="status">Loading audit history…</div>}
        {apiError && <div className="panel-box error-alert-box mb-4" role="alert">{apiError}</div>}
        {!loading && !apiError && activities.length === 0 && (
          <div className="panel-box">No audit events are available for this account yet.</div>
        )}
        {activities.length > 0 && (
          <div className="panel-box">
            <ol className="activity-timeline-list">
              {activities.map((activity) => (
                <li className="activity-item" key={activity.id}>
                  <div className="activity-dot" />
                  <div className="activity-content">
                    <div className="activity-header">
                      <strong className="activity-title">{activity.title}</strong>
                      <time className="activity-time text-mono" dateTime={activity.timestamp}>
                        {new Date(activity.timestamp).toLocaleString()}
                      </time>
                    </div>
                    <p className="activity-desc">{activity.description || 'Recorded security activity.'}</p>
                  </div>
                </li>
              ))}
            </ol>
            <Link to="/" className="btn-secondary mt-4">Back to dashboard</Link>
          </div>
        )}
      </div>
    </div>
  );
};

export default ActivityLog;
