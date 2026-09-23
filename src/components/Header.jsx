import React from 'react';
import { Link } from 'react-router-dom';

export const Header = ({ title, subtitle, breadcrumbs = [], actions = null }) => {

  return (
    <header className="page-header-bar">
      <div className="header-top-row">
        <nav aria-label="Breadcrumb" className="breadcrumbs-nav">
          <ol className="breadcrumbs-list">
            <li className="breadcrumb-item">
              <Link to="/">RepoGuard</Link>
            </li>
            {breadcrumbs.map((crumb, idx) => {
              const isLast = idx === breadcrumbs.length - 1;
              return (
                <li key={idx} className="breadcrumb-item">
                  <span className="breadcrumb-separator">/</span>
                  {isLast || !crumb.path ? (
                    <span className="breadcrumb-current" aria-current="page">
                      {crumb.label}
                    </span>
                  ) : (
                    <Link to={crumb.path}>{crumb.label}</Link>
                  )}
                </li>
              );
            })}
          </ol>
        </nav>

        <div className="header-status-pill">
          <span className="status-dot-pulse" />
          <span className="status-pill-text">Local Prototype Environment</span>
        </div>
      </div>

      <div className="header-main-row">
        <div className="header-titles">
          <h1 className="header-page-title">{title}</h1>
          {subtitle && <p className="header-page-subtitle">{subtitle}</p>}
        </div>

        {actions && <div className="header-actions-area">{actions}</div>}
      </div>
    </header>
  );
};

export default Header;
