import React from 'react';

export const SeverityBadge = ({ severity = 'medium' }) => {
  const norm = (severity || 'medium').toLowerCase();
  const label = norm.toUpperCase();

  return (
    <span className={`badge badge-${norm}`} title={`Severity level: ${label}`}>
      {label}
    </span>
  );
};

export default SeverityBadge;
