import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Header from '../components/Header';
import { RepoIcon, DashboardIcon } from '../components/icons';

export const NotFound = () => {
  const location = useLocation();

  return (
    <div className="not-found-page">
      <Header
        title="404: Route Not Found"
        subtitle="The requested endpoint does not correspond to an active security console view."
        breadcrumbs={[{ label: '404' }]}
      />

      <div className="page-content-padded">
        <div className="panel-box not-found-card">
          <div className="not-found-code text-mono">404</div>
          <h2 className="not-found-title">Endpoint Not Found</h2>
          <p className="not-found-desc">
            No route matches the requested URL <code className="text-mono text-danger">{location.pathname}</code>.
            Verify the path in the address bar or return to one of the primary operations views below.
          </p>

          <div className="not-found-links">
            <Link to="/" className="btn-primary">
              <DashboardIcon size={14} />
              <span>Security Operations Dashboard</span>
            </Link>
            <Link to="/repositories" className="btn-secondary">
              <RepoIcon size={14} />
              <span>Repositories Inventory</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
