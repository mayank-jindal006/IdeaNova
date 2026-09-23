import React from 'react';

const STATUS_MAP = {
  open: { label: 'Open', className: 'status-open' },
  fix_proposed: { label: 'Fix Proposed', className: 'status-fix_proposed' },
  pr_opened: { label: 'PR Opened', className: 'status-pr_opened' },
  fixed: { label: 'Fixed', className: 'status-fixed' },
  false_positive: { label: 'False Positive', className: 'status-false_positive' },
  needs_rotation: { label: 'Needs Rotation', className: 'status-needs_rotation' }
};

export const StatusChip = ({ status = 'open' }) => {
  const norm = (status || 'open').toLowerCase();
  const config = STATUS_MAP[norm] || { label: norm.replace('_', ' '), className: 'status-open' };

  return (
    <span className={`status-chip ${config.className}`}>
      <span className="status-chip-dot" />
      <span>{config.label}</span>
    </span>
  );
};

export default StatusChip;
