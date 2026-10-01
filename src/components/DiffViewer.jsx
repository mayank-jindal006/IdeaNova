import React, { useState, useMemo } from 'react';
import { FileCodeIcon } from './icons';

// Compute line-by-line diff using Longest Common Subsequence (LCS)
function computeLineDiff(originalText = '', newText = '') {
  const origLines = originalText === '' ? [] : originalText.split(/\r?\n/);
  const newLines = newText === '' ? [] : newText.split(/\r?\n/);

  // Quick paths
  if (origLines.length === 0) {
    return newLines.map((line, idx) => ({
      type: 'addition',
      oldLine: null,
      newLine: idx + 1,
      content: line
    }));
  }
  if (newLines.length === 0) {
    return origLines.map((line, idx) => ({
      type: 'deletion',
      oldLine: idx + 1,
      newLine: null,
      content: line
    }));
  }

  const m = origLines.length;
  const n = newLines.length;

  // For very large files, limit LCS table size to prevent freeze
  if (m * n > 40000) {
    // Fast block diff
    const result = [];
    origLines.forEach((line, idx) => {
      result.push({ type: 'deletion', oldLine: idx + 1, newLine: null, content: line });
    });
    newLines.forEach((line, idx) => {
      result.push({ type: 'addition', oldLine: null, newLine: idx + 1, content: line });
    });
    return result;
  }

  // Dynamic programming LCS table
  const dp = Array.from({ length: m + 1 }, () => new Int32Array(n + 1));
  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (origLines[i] === newLines[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  // Backtrack to build diff ops
  const diffOps = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && origLines[i - 1] === newLines[j - 1]) {
      diffOps.push({
        type: 'unchanged',
        oldLine: i,
        newLine: j,
        content: origLines[i - 1]
      });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      diffOps.push({
        type: 'addition',
        oldLine: null,
        newLine: j,
        content: newLines[j - 1]
      });
      j--;
    } else if (i > 0) {
      diffOps.push({
        type: 'deletion',
        oldLine: i,
        newLine: null,
        content: origLines[i - 1]
      });
      i--;
    }
  }

  diffOps.reverse();
  return diffOps;
}

export const DiffViewer = ({
  filePath = '',
  originalContent = '',
  newContent = '',
  beforeContent = '',
  afterContent = ''
}) => {
  const [viewMode, setViewMode] = useState('unified'); // 'unified' | 'split'

  const orig = originalContent || beforeContent || '';
  const modified = newContent || afterContent || '';

  const diffLines = useMemo(() => computeLineDiff(orig, modified), [orig, modified]);

  const additionsCount = useMemo(
    () => diffLines.filter((l) => l.type === 'addition').length,
    [diffLines]
  );
  const deletionsCount = useMemo(
    () => diffLines.filter((l) => l.type === 'deletion').length,
    [diffLines]
  );

  const origLines = orig ? orig.split(/\r?\n/) : [];
  const modLines = modified ? modified.split(/\r?\n/) : [];

  return (
    <div className="diff-viewer-wrapper">
      <div className="diff-header-bar">
        <div className="diff-file-info">
          <FileCodeIcon size={14} className="text-secondary" />
          <span className="diff-file-path text-mono">{filePath || 'patch.diff'}</span>
          <span className="diff-stat-badges">
            <span className="diff-stat-add">+{additionsCount}</span>
            <span className="diff-stat-del">-{deletionsCount}</span>
          </span>
        </div>

        <div className="diff-mode-toggle">
          <button
            type="button"
            className={`diff-toggle-btn ${viewMode === 'unified' ? 'diff-toggle-active' : ''}`}
            onClick={() => setViewMode('unified')}
          >
            Unified Diff
          </button>
          <button
            type="button"
            className={`diff-toggle-btn ${viewMode === 'split' ? 'diff-toggle-active' : ''}`}
            onClick={() => setViewMode('split')}
          >
            Side-by-Side
          </button>
        </div>
      </div>

      {viewMode === 'split' ? (
        <div className="diff-split-container">
          <div className="diff-pane diff-pane-before">
            <div className="diff-pane-label">Original Content ({filePath})</div>
            <div className="diff-code-area text-mono">
              {origLines.length === 0 ? (
                <div className="diff-empty-file-note text-muted italic p-2">(New file - no original content)</div>
              ) : (
                origLines.map((line, idx) => (
                  <div key={idx} className="diff-line diff-line-deletion">
                    <span className="diff-line-num">{idx + 1}</span>
                    <span className="diff-line-marker">-</span>
                    <span className="diff-line-content">{line || ' '}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="diff-pane diff-pane-after">
            <div className="diff-pane-label">Proposed Remediated Content</div>
            <div className="diff-code-area text-mono">
              {modLines.length === 0 ? (
                <div className="diff-empty-file-note text-muted italic p-2">(File removed)</div>
              ) : (
                modLines.map((line, idx) => (
                  <div key={idx} className="diff-line diff-line-addition">
                    <span className="diff-line-num">{idx + 1}</span>
                    <span className="diff-line-marker">+</span>
                    <span className="diff-line-content">{line || ' '}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="diff-unified-container text-mono">
          {diffLines.length === 0 ? (
            <div className="diff-empty-note text-muted italic p-3">No content changes detected.</div>
          ) : (
            diffLines.map((line, idx) => {
              const lineClass =
                line.type === 'addition'
                  ? 'diff-line-addition'
                  : line.type === 'deletion'
                  ? 'diff-line-deletion'
                  : 'diff-line-context';

              const marker = line.type === 'addition' ? '+' : line.type === 'deletion' ? '-' : ' ';

              return (
                <div key={idx} className={`diff-line ${lineClass}`}>
                  <span className="diff-line-num diff-line-num-old">
                    {line.oldLine ?? ''}
                  </span>
                  <span className="diff-line-num diff-line-num-new">
                    {line.newLine ?? ''}
                  </span>
                  <span className="diff-line-marker">{marker}</span>
                  <span className="diff-line-content">{line.content || ' '}</span>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
};

export default DiffViewer;
