import React, { useState, useEffect } from 'react';
import { KeyIcon, CheckCircleIcon, AlertTriangleIcon } from './icons';

const DEFAULT_RULE_CHECKLISTS = {
  'aws-access-token': {
    provider: 'Amazon Web Services (IAM)',
    steps: [
      { id: 'aws-1', label: 'Log into AWS IAM Console and identify compromised Access Key ID', completed: false },
      { id: 'aws-2', label: 'Deactivate key state from Active to Inactive', completed: false },
      { id: 'aws-3', label: 'Create new replacement AWS Access Key & Secret Key in IAM', completed: false },
      { id: 'aws-4', label: 'Update environment variables / secrets manager with new credentials', completed: false },
      { id: 'aws-5', label: 'Inspect AWS CloudTrail audit logs for unauthorized API activity', completed: false },
      { id: 'aws-6', label: 'Permanently delete the deactivated key from AWS IAM', completed: false }
    ]
  },
  'stripe-secret-key': {
    provider: 'Stripe Payments',
    steps: [
      { id: 'stripe-1', label: 'Access Stripe Dashboard -> Developers -> API Keys', completed: false },
      { id: 'stripe-2', label: 'Roll the compromised restricted/secret key with expiration window', completed: false },
      { id: 'stripe-3', label: 'Deploy new Stripe Secret Key to server environment secrets', completed: false },
      { id: 'stripe-4', label: 'Audit recent charges, webhook events, and customer exports in Stripe logs', completed: false }
    ]
  },
  'github-pat': {
    provider: 'GitHub Personal Access Tokens',
    steps: [
      { id: 'gh-1', label: 'Navigate to GitHub Settings -> Developer Settings -> Personal Access Tokens', completed: false },
      { id: 'gh-2', label: 'Revoke the exposed personal access token immediately', completed: false },
      { id: 'gh-3', label: 'Generate a new fine-grained PAT with minimal repository permissions', completed: false },
      { id: 'gh-4', label: 'Update CI/CD secrets and developer local configs', completed: false },
      { id: 'gh-5', label: 'Check security log in GitHub account settings for anomalous usage', completed: false }
    ]
  },
  'generic-api-key': {
    provider: 'Credential Service Provider',
    steps: [
      { id: 'gen-1', label: 'Log into vendor admin portal and identify exposed API token', completed: false },
      { id: 'gen-2', label: 'Revoke and invalidate the compromised token', completed: false },
      { id: 'gen-3', label: 'Generate new secret token with principle of least privilege', completed: false },
      { id: 'gen-4', label: 'Inject new credential into secure runtime environment', completed: false },
      { id: 'gen-5', label: 'Review vendor access logs for unverified IP requests', completed: false }
    ]
  }
};

export const RotationChecklist = ({ ruleId = 'generic-api-key', checklist = null, rotationNote = null }) => {
  const [steps, setSteps] = useState([]);
  const [provider, setProvider] = useState('Credential Service Provider');

  useEffect(() => {
    if (checklist && Array.isArray(checklist) && checklist.length > 0) {
      setSteps(
        checklist.map((item, idx) => {
          if (typeof item === 'string') {
            return { id: `step-${idx}`, label: item, completed: false };
          }
          return { id: item.id || `step-${idx}`, label: item.label || item.step || item.text, completed: !!item.completed };
        })
      );
      setProvider(ruleId ? ruleId.replace(/-/g, ' ').toUpperCase() : 'Credential Provider');
    } else {
      const fallback = DEFAULT_RULE_CHECKLISTS[ruleId] || DEFAULT_RULE_CHECKLISTS['generic-api-key'];
      setSteps(fallback.steps.map(s => ({ ...s })));
      setProvider(fallback.provider);
    }
  }, [ruleId, checklist]);

  const toggleStep = (id) => {
    setSteps(prev =>
      prev.map(s => (s.id === id ? { ...s, completed: !s.completed } : s))
    );
  };

  const completedCount = steps.filter(s => s.completed).length;
  const progressPercent = steps.length > 0 ? Math.round((completedCount / steps.length) * 100) : 0;

  return (
    <div className="rotation-checklist-card">
      <div className="rotation-checklist-header">
        <div className="rotation-icon-wrap">
          <KeyIcon size={18} className="text-warning" />
        </div>
        <div className="rotation-header-text">
          <h4 className="rotation-title">Credential Invalidation &amp; Rotation Checklist</h4>
          <p className="rotation-subtitle">
            Provider: <strong className="text-primary">{provider}</strong>
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

      {rotationNote && (
        <div className="rotation-notice-box" style={{ borderColor: 'var(--amber-dim, #d29922)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
            <AlertTriangleIcon size={16} className="text-warning" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Rotation Advisory:</strong> {rotationNote}
            </div>
          </div>
        </div>
      )}

      {!rotationNote && (
        <div className="rotation-notice-box">
          <strong>⚠️ Crucial Security Context:</strong> Merging a code fix removes the secret from the latest commit,
          but the credential remains accessible in commit history and git logs. You must rotate the key with
          the provider before closing this incident.
        </div>
      )}

      <ul className="rotation-step-list">
        {steps.map((step) => (
          <li key={step.id} className={`rotation-step-item ${step.completed ? 'step-completed' : ''}`}>
            <label className="rotation-checkbox-label">
              <input
                type="checkbox"
                className="rotation-checkbox"
                checked={step.completed}
                onChange={() => toggleStep(step.id)}
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
