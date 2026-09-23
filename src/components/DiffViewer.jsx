import React, { useState } from 'react';
import { FileCodeIcon } from './icons';

export const DiffViewer = ({ filePath, beforeContent = "", afterContent = "" }) => {
  const [viewMode, setViewMode] = useState('split'); // 'split' | 'unified'

  const beforeLines = beforeContent ? beforeContent.split('\n') : [];
  const afterLines = afterContent ? afterContent.split('\n') : [];

  return (
    <div className="diff-viewer-wrapper">
      <div className="diff-header-bar">
        <div className="diff-file-info">
          <FileCodeIcon size={14} className="text-secondary" />
          <span className="diff-file-path text-mono">{filePath}</span>
        </div>

        <div className="diff-mode-toggle">
          <button
            type="button"
            className={`diff-toggle-btn ${viewMode === 'split' ? 'diff-toggle-active' : ''}`}
            onClick={() => setViewMode('split')}
          >
            Side-by-Side
          </button>
          <button
            type="button"
            className={`diff-toggle-btn ${viewMode === 'unified' ? 'diff-toggle-active' : ''}`}
            onClick={() => setViewMode('unified')}
          >
            Unified
          </button>
        </div>
      </div>

      {viewMode === 'split' ? (
        <div className="diff-split-container">
          <div className="diff-pane diff-pane-before">
            <div className="diff-pane-label">Current Source (Vulnerable)</div>
            <div className="diff-code-area text-mono">
              {beforeLines.map((line, idx) => (
                <div key={idx} className="diff-line diff-line-deletion">
                  <span className="diff-line-num">{idx + 1}</span>
                  <span className="diff-line-marker">-</span>
                  <span className="diff-line-content">{line || ' '}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="diff-pane diff-pane-after">
            <div className="diff-pane-label">Proposed Patch (Remediated)</div>
            <div className="diff-code-area text-mono">
              {afterLines.map((line, idx) => (
                <div key={idx} className="diff-line diff-line-addition">
                  <span className="diff-line-num">{idx + 1}</span>
                  <span className="diff-line-marker">+</span>
                  <span className="diff-line-content">{line || ' '}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="diff-unified-container text-mono">
          <div className="diff-pane-label">Source Changes</div>
          {beforeLines.map((line, idx) => (
            <div key={`b-${idx}`} className="diff-line diff-line-deletion">
              <span className="diff-line-num">{idx + 1}</span>
              <span className="diff-line-marker">-</span>
              <span className="diff-line-content">{line || ' '}</span>
            </div>
          ))}
          {afterLines.map((line, idx) => (
            <div key={`a-${idx}`} className="diff-line diff-line-addition">
              <span className="diff-line-num">{idx + 1}</span>
              <span className="diff-line-marker">+</span>
              <span className="diff-line-content">{line || ' '}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default DiffViewer;
