import React, { useState } from 'react';
import SecurityScore from '../components/SecurityScore';
import RiskSummary from '../components/RiskSummary';
import SeverityBreakdown from '../components/SeverityBreakdown';
import AnalyzerStatus from '../components/AnalyzerStatus';
import FindingsList from '../components/FindingsList';
import FindingDetails from '../components/FindingDetails';
import EmptyState from '../components/EmptyState';
import { Play, ShieldAlert, Cpu, FileCode, CheckCircle2, AlertCircle, Info } from 'lucide-react';

export default function DashboardPage({ analysisResult, onNavigate }) {
  const [selectedFinding, setSelectedFinding] = useState(null);

  if (!analysisResult) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
              SECURITY DASHBOARD
            </h2>
            <p className="text-xs text-slate-400">
              Centralized SAST metrics, risk assessment & findings summary
            </p>
          </div>
        </div>

        <EmptyState onAction={() => onNavigate('analyzer')} />
      </div>
    );
  }

  const { security, summary, findings, analyzers, scan } = analysisResult;

  const targetFilename = scan?.filename || (findings[0]?.source_file) || 'input.py';
  const targetLanguage = (scan?.language || analysisResult.language || 'Python').toUpperCase();
  const analyzersList = scan?.analyzers_requested?.join(' + ') || analyzers?.join(' + ') || 'Bandit + Semgrep';

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
            SECURITY DASHBOARD
          </h2>
          <p className="text-xs text-slate-400">
            Latest static analysis results & risk evaluation
          </p>
        </div>

        <button
          onClick={() => onNavigate('analyzer')}
          className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all border border-cyan-400 self-start sm:self-auto flex items-center gap-2"
        >
          <Play className="h-4 w-4 fill-current" />
          <span>NEW CODE SCAN</span>
        </button>
      </div>

      {/* Part 13: SCAN INFORMATION Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
        <h3 className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-bold flex items-center gap-2">
          <Info className="h-4 w-4" />
          SCAN INFORMATION
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 font-mono text-xs">
          <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-xl space-y-1">
            <span className="text-slate-500 text-[10px] uppercase font-semibold block">File</span>
            <span className="text-slate-200 font-bold truncate block">{targetFilename}</span>
          </div>

          <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-xl space-y-1">
            <span className="text-slate-500 text-[10px] uppercase font-semibold block">Language</span>
            <span className="text-cyan-400 font-bold block">{targetLanguage}</span>
          </div>

          <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-xl space-y-1">
            <span className="text-slate-500 text-[10px] uppercase font-semibold block">Analyzers</span>
            <span className="text-slate-200 font-bold capitalize block">{analyzersList}</span>
          </div>

          <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-xl space-y-1">
            <span className="text-slate-500 text-[10px] uppercase font-semibold block">Logical Findings</span>
            <span className="text-rose-400 font-bold block text-sm">{security?.logical_vulnerabilities ?? findings.length}</span>
          </div>

          <div className="bg-slate-950 border border-slate-800/80 p-3 rounded-xl space-y-1">
            <span className="text-slate-500 text-[10px] uppercase font-semibold block">Raw Detections</span>
            <span className="text-amber-400 font-bold block text-sm">{security?.raw_detections ?? findings.length}</span>
          </div>
        </div>

        {/* Analyzer Execution Status Details */}
        {scan?.analyzer_status && scan.analyzer_status.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono">
            <span className="text-slate-500 font-semibold uppercase">Engine Status:</span>
            {scan.analyzer_status.map((st) => (
              <span key={st.name} className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 px-2.5 py-1 rounded-lg">
                <span className="capitalize text-slate-300 font-medium">{st.name}:</span>
                {st.status === 'completed' ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="h-3 w-3" /> Completed
                  </span>
                ) : (
                  <span className="text-rose-400 flex items-center gap-1">
                    <AlertCircle className="h-3 w-3" /> Failed ({st.error || 'Unavailable'})
                  </span>
                )}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Top Metrics Summary Grid */}
      <RiskSummary security={security} findings={findings} />

      {/* Main Grid: Score, Breakdown, Analyzer Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SecurityScore
          score={security?.score ?? 100}
          riskLevel={security?.risk_level ?? 'MINIMAL'}
        />

        <SeverityBreakdown summary={summary} />

        <AnalyzerStatus analyzers={analyzers} />
      </div>

      {/* Recent Logical Findings */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-mono text-slate-200 uppercase tracking-wider font-bold flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            TOP LOGICAL FINDINGS
          </h3>
          <button
            onClick={() => onNavigate('findings')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 font-semibold"
          >
            View All ({findings.length}) &rarr;
          </button>
        </div>

        <FindingsList
          findings={findings.slice(0, 3)}
          onSelectFinding={setSelectedFinding}
        />
      </div>

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <FindingDetails
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
