import React from 'react';
import { AlertTriangleIcon } from './icons';

export const EmptyState = ({
  icon: Icon = AlertTriangleIcon,
  title = "No Data Found",
  message = "There are no records matching the requested filter or query.",
  actionText = null,
  onAction = null
}) => {
  return (
    <div className="empty-state-box">
      <div className="empty-state-icon-wrap">
        <Icon size={24} className="empty-state-icon" />
      </div>
      <h3 className="empty-state-title">{title}</h3>
      <p className="empty-state-message">{message}</p>
      {actionText && onAction && (
        <button className="btn-secondary btn-sm" onClick={onAction}>
          {actionText}
        </button>
      )}
    </div>
  );
};

export default EmptyState;
