import React from 'react';

export const RiskFactorBreakdown = ({ factors = [], riskScore = 0 }) => {
  return (
    <div className="risk-breakdown-card">
      <div className="risk-breakdown-header">
        <div>
          <h4 className="risk-breakdown-title">Heuristic Risk Score Breakdown</h4>
          <p className="risk-breakdown-subtitle">
            Weighted rule-based aggregation over repository security signals, configuration exposure, and historical leaks.
          </p>
        </div>
        <div className="risk-score-display">
          <span className={`risk-score-number ${
            riskScore >= 60 ? 'text-danger' : riskScore >= 30 ? 'text-warning' : 'text-success'
          }`}>
            {riskScore}
          </span>
          <span className="risk-score-scale">/ 100</span>
        </div>
      </div>

      <div className="table-responsive">
        <table className="data-table">
          <thead>
            <tr>
              <th>Risk Factor</th>
              <th>Observed Signal</th>
              <th className="text-right">Weight</th>
              <th className="text-right">Contribution</th>
            </tr>
          </thead>
          <tbody>
            {factors.length === 0 ? (
              <tr>
                <td colSpan="4" className="text-center text-muted">
                  No risk factors available for this repository.
                </td>
              </tr>
            ) : (
              factors.map((factor, idx) => (
                <tr key={idx}>
                  <td className="font-medium">{factor.name}</td>
                  <td className="text-mono text-sm">{factor.signal || String(factor.value)}</td>
                  <td className="text-right text-muted">&times;{factor.weight}</td>
                  <td className="text-right font-semibold">
                    <span className={factor.contribution > 0 ? "text-danger" : "text-muted"}>
                      +{factor.contribution} pts
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
          <tfoot>
            <tr className="tfoot-row">
              <td colSpan="3" className="font-semibold">Total Heuristic Risk Score</td>
              <td className="text-right font-bold text-mono">{riskScore} / 100</td>
            </tr>
          </tfoot>
        </table>
      </div>
      
      <p className="risk-disclaimer">
        * Score is capped at 100. This is an explicit rule-based heuristic, not a machine learning model.
      </p>
    </div>
  );
};

export default RiskFactorBreakdown;
