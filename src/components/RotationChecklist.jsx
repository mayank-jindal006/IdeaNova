import React from 'react';
import { KeyIcon, CheckCircleIcon } from './icons';
import { useRepoGuard } from '../context/RepoGuardContext';

export const RotationChecklist = ({ ruleId }) => {
  const { rotation, toggleRotationStep } = useRepoGuard();

  const checklistData = rotation[ruleId] || rotation["generic-api-key"] || {
    provider: "Credential Service Provider",
    steps: []
  };

  const steps = checklistData.steps || [];
  const completedCount = steps.filter(s => s.completed).length;
  const progressPercent = steps.length > 0 ? Math.round((completedCount / steps.length) * 100) : 0;

  return (
    <div className="rotation-checklist-card">
      <div className="rotation-checklist-header">
        <div className="rotation-icon-wrap">
          <KeyIcon size={18} className="text-warning" />
        </div>
        <div className="rotation-header-text">
          <h4 className="rotation-title">Credential Invalidation & Rotation Checklist</h4>
          <p className="rotation-subtitle">
            Target Provider: <strong className="text-primary">{checklistData.provider}</strong>
          </p>
        </div>
        <div className="rotation-progress-badge">
          {completedCount} / {steps.length} Steps Done ({progressPercent}%)
        </div>
      </div>

      <div className="rotation-progress-track">
        <div 
          className="rotation-progress-fill" 
          style={{ width: `${progressPercent}%` }} 
          role="progressbar" 
          aria-valuenow={progressPercent} 
          aria-valuemin="0" 
          aria-valuemax="100" 
        />
      </div>

      <div className="rotation-notice-box">
        <strong>⚠️ Crucial Security Context:</strong> Merging a code fix removes the secret from the latest commit,
        but the credential remains accessible in commit history, previous forks, and git logs. You must rotate the key with
        the cloud provider before closing this incident.
      </div>

      <ul className="rotation-step-list">
        {steps.map((step) => (
          <li key={step.id} className={`rotation-step-item ${step.completed ? 'step-completed' : ''}`}>
            <label className="rotation-checkbox-label">
              <input
                type="checkbox"
                className="rotation-checkbox"
                checked={step.completed}
                onChange={() => toggleRotationStep(ruleId, step.id)}
              />
              <span className="step-text">{step.label}</span>
            </label>
            {step.completed && (
              <span className="step-verified-badge" title="Step completed">
                <CheckCircleIcon size={14} className="text-success" />
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default RotationChecklist;
