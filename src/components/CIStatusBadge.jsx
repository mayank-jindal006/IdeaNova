import React from 'react';
import { CheckCircleIcon, AlertTriangleIcon, RefreshCwIcon } from './icons';

const CI_CONFIG = {
  passed: {
    label: 'CI Passed',
    className: 'ci-badge-passed',
    icon: CheckCircleIcon,
    spin: false
  },
  failed: {
    label: 'CI Failed',
    className: 'ci-badge-failed',
    icon: AlertTriangleIcon,
    spin: false
  },
  pending: {
    label: 'CI Running',
    className: 'ci-badge-pending',
    icon: RefreshCwIcon,
    spin: true
  },
  none: {
    label: 'CI Not Run',
    className: 'ci-badge-none',
    icon: null,
    spin: false
  }
};

export const CIStatusBadge = ({
  status = 'none',
  repairAttempts = 0,
  showLabel = true,
  size = 'md',
  className = ''
}) => {
  const norm = (status || 'none').toLowerCase();
  const config = CI_CONFIG[norm] || CI_CONFIG.none;
  const Icon = config.icon;

  return (
    <span
      className={`ci-status-badge ci-size-${size} ${config.className} ${className}`}
      title={`CI Status: ${config.label}${repairAttempts > 0 ? ` (Repair attempt #${repairAttempts})` : ''}`}
    >
      {Icon && (
        <Icon
          size={size === 'sm' ? 11 : 13}
          className={`ci-badge-icon ${config.spin ? 'spin-icon' : ''}`}
        />
      )}
      {!Icon && <span className="ci-badge-dot" />}
      {showLabel && <span className="ci-badge-text">{config.label}</span>}
      {repairAttempts > 0 && (
        <span className="ci-badge-attempt" title={`${repairAttempts} automated self-healing repair attempts`}>
          #{repairAttempts}
        </span>
      )}
    </span>
  );
};

export default CIStatusBadge;
