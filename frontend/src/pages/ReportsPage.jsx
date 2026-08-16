import React, { useState, useEffect } from 'react';
import ReportModal from '../components/ReportModal';
import { getReports } from '../services/api';
import { FileText, Play, ShieldAlert, ArrowUpRight, ArrowDownRight, Minus, RefreshCw, AlertCircle, Info } from 'lucide-react';

export default function ReportsPage({ reportHistory, setReportHistory, onNavigate }) {
  const [selectedReport, setSelectedReport] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const fetchReports = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    const res = await getReports();
    setIsLoading(false);
    if (res.success && res.data) {
      setReportHistory(res.data);
    } else if (res.error) {
      setErrorMsg(res.error);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const getRiskBadgeStyle = (lvl) => {
    switch ((lvl || '').toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  // Compute report score comparisons for reports with identical target filenames
  const computeScoreComparison = (reportIndex, allReports) => {
    const currentReport = allReports[reportIndex];
    const targetFile = currentReport.executive_summary?.target_file || currentReport.scan_metadata?.filename;
    if (!targetFile) return null;

    // Find previous report (chronologically older) with same filename
    for (let i = reportIndex + 1; i < allReports.length; i++) {
      const prevReport = allReports[i];
      const prevFile = prevReport.executive_summary?.target_file || prevReport.scan_metadata?.filename;
      if (prevFile === targetFile) {
        const delta = currentReport.security_score - prevReport.security_score;
        return {
          prevScore: prevReport.security_score,
          currScore: currentReport.security_score,
          delta: delta,
        };
      }
    }
    return null;
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
            SECURITY REVIEW REPORTS & HISTORY
          </h2>
          <p className="text-xs text-slate-400">
            Audit history, generated security review reports & visual score comparisons
          </p>
        </div>

        <button
          onClick={fetchReports}
          disabled={isLoading}
          className="px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors self-start sm:self-auto flex items-center gap-2"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>REFRESH HISTORY</span>
        </button>
      </div>

      {/* Storage Disclaimer Banner */}
      <div className="bg-amber-950/40 border border-amber-800/40 rounded-xl p-3.5 text-xs text-amber-300/90 font-mono flex items-center gap-2.5">
        <Info className="h-4 w-4 text-amber-400 shrink-0" />
        <span>
          <strong>Storage Disclaimer:</strong> Current implementation uses in-memory session storage. Stored reports reset when backend process restarts.
        </span>
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="p-12 text-center font-mono text-slate-400 text-xs flex flex-col items-center gap-2">
          <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
          <span>Fetching report history from backend...</span>
        </div>
      )}

      {/* Error Banner */}
      {errorMsg && (
        <div className="bg-rose-950/70 border border-rose-800 rounded-xl p-4 text-xs text-rose-300 font-mono flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && reportHistory.length === 0 && (
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-12 text-center space-y-4 max-w-lg mx-auto">
          <div className="bg-slate-800/60 border border-slate-700 p-4 rounded-2xl inline-block text-slate-400">
            <FileText className="h-8 w-8" />
          </div>

          <div className="space-y-1">
            <h3 className="text-base font-bold font-mono text-slate-200">
              No security reports yet
            </h3>
            <p className="text-xs text-slate-400">
              Run a code analysis to generate your first security review report.
            </p>
          </div>

          <button
            onClick={() => onNavigate('analyzer')}
            className="px-4 py-2.5 rounded-xl text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all border border-cyan-400 inline-flex items-center gap-2"
          >
            <Play className="h-4 w-4 fill-current" />
            <span>RUN CODE ANALYSIS</span>
          </button>
        </div>
      )}

      {/* Reports History List */}
      {!isLoading && reportHistory.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
            <span>SHOWING {reportHistory.length} GENERATED REPORT{reportHistory.length > 1 ? 'S' : ''}</span>
          </div>

          <div className="space-y-3">
            {reportHistory.map((rep, index) => {
              const comp = computeScoreComparison(index, reportHistory);
              const targetFile = rep.executive_summary?.target_file || rep.scan_metadata?.filename || 'input.py';

              return (
                <div
                  key={rep.report_id || index}
                  onClick={() => setSelectedReport(rep)}
                  className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 rounded-2xl p-4 sm:p-5 transition-all cursor-pointer shadow-lg hover:shadow-cyan-500/5 group flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="space-y-2">
                    <div className="flex items-center space-x-3">
                      <div className="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-xl text-cyan-400 group-hover:scale-105 transition-transform">
                        <FileText className="h-5 w-5" />
                      </div>

                      <div>
                        <div className="flex items-center space-x-2">
                          <h4 className="text-sm font-bold font-mono text-slate-100 group-hover:text-cyan-400 transition-colors">
                            {rep.report_id}
                          </h4>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full border uppercase font-mono font-bold ${getRiskBadgeStyle(rep.risk_level)}`}>
                            {rep.risk_level}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 font-mono">
                          Target: <strong className="text-slate-200">{targetFile}</strong> | {new Date(rep.generated_at).toLocaleString()}
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 pl-1 sm:pl-12">
                      <span>Vulnerabilities: <strong className="text-rose-400">{rep.logical_vulnerabilities}</strong></span>
                      <span>Raw Detections: <strong className="text-amber-400">{rep.raw_detections}</strong></span>
                      <span>Score: <strong className="text-cyan-400">{rep.security_score} / 100</strong></span>
                    </div>
                  </div>

                  {/* Score Comparison Badge */}
                  <div className="flex items-center space-x-3 self-end sm:self-center">
                    {comp && (
                      <div className="bg-slate-950 border border-slate-800 px-3 py-2 rounded-xl text-right font-mono text-xs space-y-0.5">
                        <span className="text-[10px] text-slate-500 block uppercase font-semibold">Score Delta</span>
                        <div className="flex items-center space-x-1">
                          <span className="text-slate-400 text-[11px]">{comp.prevScore} &rarr; {comp.currScore}</span>
                          {comp.delta > 0 ? (
                            <span className="text-emerald-400 font-bold flex items-center text-xs">
                              <ArrowUpRight className="h-3.5 w-3.5" />+{comp.delta}
                            </span>
                          ) : comp.delta < 0 ? (
                            <span className="text-rose-400 font-bold flex items-center text-xs">
                              <ArrowDownRight className="h-3.5 w-3.5" />{comp.delta}
                            </span>
                          ) : (
                            <span className="text-slate-400 font-bold flex items-center text-xs">
                              <Minus className="h-3.5 w-3.5" /> 0
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedReport(rep);
                      }}
                      className="px-3.5 py-2 rounded-xl text-xs font-mono font-semibold bg-slate-800 group-hover:bg-cyan-500 group-hover:text-slate-950 text-slate-200 transition-colors"
                    >
                      View Report &rarr;
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Report Modal */}
      {selectedReport && (
        <ReportModal
          report={selectedReport}
          onClose={() => setSelectedReport(null)}
        />
      )}
    </div>
  );
}
