import React, { useState } from 'react';
import { X, FileText, Check, Copy, ShieldAlert, Cpu, AlertTriangle, Lightbulb, BarChart2, Layers } from 'lucide-react';

export default function ReportModal({ report, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!report) return null;

  const exec = report.executive_summary || {};
  const breakdown = report.severity_breakdown || {};
  const remediation = report.remediation_summary || {};
  const scan = report.scan_metadata || {};
  const findings = report.findings || [];

  const handleCopyJson = () => {
    const jsonStr = JSON.stringify(report, null, 2);
    navigator.clipboard.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden my-auto">
        {/* Modal Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-xl text-cyan-400">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-slate-100 flex items-center gap-2">
                <span>{report.report_id}</span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full border uppercase font-mono ${getRiskBadgeStyle(report.risk_level)}`}>
                  {report.risk_level}
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Generated: {new Date(report.generated_at).toUTCString()}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopyJson}
              className="px-3 py-1.5 rounded-xl text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors flex items-center gap-1.5"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-slate-400" />}
              <span>{copied ? 'Copied JSON!' : 'Copy Report JSON'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Section 1: Executive Summary */}
          <div className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl space-y-4">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
              <FileText className="h-4 w-4" />
              1. EXECUTIVE SUMMARY
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Target File</span>
                <span className="text-slate-200 font-bold truncate block">{exec.target_file || scan.filename}</span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Security Score</span>
                <span className="text-cyan-400 font-bold text-base block">{report.security_score} / 100</span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Logical Findings</span>
                <span className="text-rose-400 font-bold text-base block">{report.logical_vulnerabilities}</span>
              </div>
              <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Raw Detections</span>
                <span className="text-amber-400 font-bold text-base block">{report.raw_detections}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-[11px] pt-1">
              <div className="text-slate-300">
                Highest Severity: <strong className="text-rose-400 uppercase">{exec.highest_severity}</strong>
              </div>
              <div className="text-slate-300">
                Primary Risk Category: <strong className="text-cyan-400">{exec.primary_risk_category || 'N/A'}</strong>
              </div>
              <div className="text-slate-300">
                Critical / High Detections: <strong className="text-amber-400">{exec.critical_count} Crit / {exec.high_count} High</strong>
              </div>
            </div>
          </div>

          {/* Section 2: Severity Distribution */}
          <div className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl space-y-3">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
              <BarChart2 className="h-4 w-4" />
              2. SEVERITY DISTRIBUTION & PERCENTAGES
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-center">
              <div className="bg-slate-900 p-3 rounded-lg border border-rose-500/20">
                <span className="text-rose-400 font-bold block text-sm">CRITICAL</span>
                <span className="text-slate-200 font-bold text-base">{breakdown.critical?.count ?? 0}</span>
                <span className="text-[10px] text-slate-500 block">({breakdown.critical?.percentage ?? 0}%)</span>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-orange-500/20">
                <span className="text-orange-400 font-bold block text-sm">HIGH</span>
                <span className="text-slate-200 font-bold text-base">{breakdown.high?.count ?? 0}</span>
                <span className="text-[10px] text-slate-500 block">({breakdown.high?.percentage ?? 0}%)</span>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-amber-500/20">
                <span className="text-amber-400 font-bold block text-sm">MEDIUM</span>
                <span className="text-slate-200 font-bold text-base">{breakdown.medium?.count ?? 0}</span>
                <span className="text-[10px] text-slate-500 block">({breakdown.medium?.percentage ?? 0}%)</span>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-blue-500/20">
                <span className="text-blue-400 font-bold block text-sm">LOW</span>
                <span className="text-slate-200 font-bold text-base">{breakdown.low?.count ?? 0}</span>
                <span className="text-[10px] text-slate-500 block">({breakdown.low?.percentage ?? 0}%)</span>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
                <span className="text-slate-400 font-bold block text-sm">INFO</span>
                <span className="text-slate-200 font-bold text-base">{breakdown.info?.count ?? 0}</span>
                <span className="text-[10px] text-slate-500 block">({breakdown.info?.percentage ?? 0}%)</span>
              </div>
            </div>
          </div>

          {/* Section 3: Remediation Priorities & Top Recommendations */}
          {remediation && (
            <div className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl space-y-4">
              <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
                <Lightbulb className="h-4 w-4 text-cyan-400" />
                3. REMEDIATION PRIORITIES & TOP RECOMMENDATIONS
              </h4>

              {/* Top Recommendations Bullet List */}
              {remediation.top_recommendations && remediation.top_recommendations.length > 0 && (
                <div className="bg-emerald-950/30 border border-emerald-800/40 p-3.5 rounded-xl space-y-2">
                  <span className="text-emerald-400 font-mono font-bold uppercase text-[11px] block">
                    Top Actionable Fixes:
                  </span>
                  <ul className="space-y-1 font-sans text-emerald-200/90 text-xs list-disc list-inside">
                    {remediation.top_recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Categorized Remediation Priorities */}
              {remediation.categories && remediation.categories.length > 0 && (
                <div className="space-y-2">
                  <span className="text-slate-400 font-mono text-[11px] uppercase font-semibold">
                    Categorized Vulnerability Priorities:
                  </span>
                  <div className="space-y-2">
                    {remediation.categories.map((cat, i) => (
                      <div key={i} className="bg-slate-900 border border-slate-800 p-3 rounded-xl space-y-1">
                        <div className="flex items-center justify-between font-mono">
                          <strong className="text-slate-200">{cat.category}</strong>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getRiskBadgeStyle(cat.priority)}`}>
                            Priority: {cat.priority} ({cat.findings_count} finding{cat.findings_count > 1 ? 's' : ''})
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-sans leading-relaxed">
                          {cat.recommendation}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Section 4: Logical Findings Summary List */}
          <div className="bg-slate-950/60 border border-slate-800 p-5 rounded-xl space-y-3">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              4. AUDITED LOGICAL FINDINGS ({findings.length})
            </h4>

            {findings.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono italic">No security findings recorded in this report.</p>
            ) : (
              <div className="space-y-2.5">
                {findings.map((f, idx) => (
                  <div key={f.id || idx} className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getRiskBadgeStyle(f.severity)}`}>
                          {f.severity}
                        </span>
                        <strong className="text-slate-100">{f.title}</strong>
                      </div>
                      <span className="text-slate-500 text-[11px]">Line {f.line_start} | {f.cwe || 'CWE Unmapped'}</span>
                    </div>

                    <p className="text-xs text-slate-300 font-sans">{f.description}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="bg-slate-950 px-6 py-3 border-t border-slate-800 flex justify-between items-center text-xs font-mono text-slate-500">
          <span>Report Storage: <strong className="text-amber-400">In-Memory Session</strong></span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
}
