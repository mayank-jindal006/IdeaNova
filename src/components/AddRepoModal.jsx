import React, { useState, useEffect } from 'react';
import { XIcon, PlusIcon } from './icons';
import { useRepoGuard } from '../context/RepoGuardContext';

export const AddRepoModal = ({ isOpen, onClose, onRepoAdded }) => {
  const { addRepository } = useRepoGuard();

  const [fullName, setFullName] = useState('');
  const [defaultBranch, setDefaultBranch] = useState('main');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setFullName('');
      setDefaultBranch('main');
      setError('');
      setSubmitting(false);
    }
  }, [isOpen]);

  // Support ESC key to close
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    const trimmed = fullName.trim();
    if (!trimmed) {
      setError('Please provide a repository full name.');
      return;
    }

    if (!trimmed.includes('/') || trimmed.split('/').length !== 2 || !trimmed.split('/')[0] || !trimmed.split('/')[1]) {
      setError("Repository must follow 'owner/repository' format (e.g. organization/repo-name).");
      return;
    }

    setSubmitting(true);
    try {
      const created = addRepository(trimmed, defaultBranch);
      onRepoAdded?.(created);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to add repository.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-header-titles">
            <h2 id="modal-title" className="modal-title">Track New Repository</h2>
            <p className="modal-subtitle">Connect a GitHub repository for secret scanning and dependency auditing.</p>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close dialog">
            <XIcon size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-form">
          {error && (
            <div className="form-error-banner" role="alert">
              {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="repo-full-name" className="form-label">
              GitHub Repository Name <span className="text-danger">*</span>
            </label>
            <input
              id="repo-full-name"
              type="text"
              className="form-input text-mono"
              placeholder="e.g. repoguard-org/payment-service"
              value={fullName}
              onChange={(e) => {
                setFullName(e.target.value);
                if (error) setError('');
              }}
              autoFocus
              required
            />
            <span className="form-hint">Specify the GitHub owner organization and repository name.</span>
          </div>

          <div className="form-group">
            <label htmlFor="repo-branch" className="form-label">
              Default Monitored Branch
            </label>
            <input
              id="repo-branch"
              type="text"
              className="form-input text-mono"
              placeholder="main"
              value={defaultBranch}
              onChange={(e) => setDefaultBranch(e.target.value)}
            />
            <span className="form-hint">Target branch for push webhooks and HEAD secret inspection.</span>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn-secondary" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={submitting}>
              <PlusIcon size={14} />
              <span>{submitting ? 'Registering...' : 'Register Repository'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddRepoModal;
