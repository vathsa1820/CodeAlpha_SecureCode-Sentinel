import React from 'react';
import { X, Code, ShieldAlert, Cpu, FileText, Fingerprint, Layers, AlertTriangle, Lightbulb, CheckCircle2 } from 'lucide-react';
import RemediationPanel from './RemediationPanel';

export default function FindingDetails({ finding, onClose }) {
  if (!finding) return null;

  const detectedBy = finding.detected_by && finding.detected_by.length > 0
    ? finding.detected_by
    : [finding.analyzer];

  const getSeverityBadge = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const getConfidenceBadge = (conf) => {
    switch ((conf || '').toUpperCase()) {
      case 'HIGH':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'MEDIUM':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'LOW':
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const cweDisplay = finding.cwe || "Not mapped";
  const owaspDisplay = finding.owasp || "Not mapped";
  const fingerprintDisplay = finding.fingerprint
    ? `${finding.fingerprint.substring(0, 16)}...`
    : "Not mapped";

  const sourceCtx = finding.source_context;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden my-auto">
        {/* Modal Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-xl text-cyan-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-slate-100">
                Finding Detail Inspection
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {finding.source_file} : Line {finding.line_start}{finding.line_end > finding.line_start ? `-${finding.line_end}` : ''}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Section 1: Overview */}
          <div className="space-y-3 bg-slate-950/60 border border-slate-800 p-4 rounded-xl">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="h-4 w-4" />
              1. OVERVIEW & METADATA
            </h4>

            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className={`px-3 py-1 rounded-full font-mono font-bold border uppercase tracking-wider ${getSeverityBadge(finding.severity)}`}>
                Severity: {finding.severity}
              </span>

              <span className={`px-3 py-1 rounded-full font-mono font-bold border uppercase tracking-wider ${getConfidenceBadge(finding.confidence)}`}>
                Confidence: {finding.confidence}
              </span>

              <span className="bg-slate-900 text-slate-300 border border-slate-800 font-mono px-3 py-1 rounded-lg uppercase">
                Category: {finding.category}
              </span>

              <span className="bg-purple-950/80 text-purple-300 border border-purple-800/60 font-mono px-3 py-1 rounded-lg uppercase font-semibold">
                {cweDisplay}
              </span>

              <span className="bg-blue-950/80 text-blue-300 border border-blue-800/60 font-mono px-3 py-1 rounded-lg uppercase font-semibold">
                OWASP: {owaspDisplay}
              </span>
            </div>

            <div className="space-y-1.5 pt-2">
              <h2 className="text-base font-bold font-mono text-slate-100">
                {finding.title}
              </h2>
              <p className="text-slate-300 leading-relaxed font-sans">
                {finding.description}
              </p>
            </div>

            <div className="pt-2 flex items-center gap-2 text-[11px] font-mono text-slate-500">
              <Fingerprint className="h-3.5 w-3.5 text-slate-400 shrink-0" />
              <span>Fingerprint:</span>
              <code className="text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 select-all">
                {finding.fingerprint || "Not mapped"}
              </code>
            </div>
          </div>

          {/* Section 2: Location & Context */}
          <div className="space-y-3 bg-slate-950/60 border border-slate-800 p-4 rounded-xl">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Code className="h-4 w-4" />
              2. LOCATION & SOURCE CONTEXT
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-slate-400">
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center gap-2">
                <FileText className="h-4 w-4 text-cyan-400 shrink-0" />
                <span>File: <strong className="text-slate-200">{finding.source_file}</strong></span>
              </div>
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center gap-2">
                <Code className="h-4 w-4 text-cyan-400 shrink-0" />
                <span>Lines: <strong className="text-slate-200">{finding.line_start}{finding.line_end > finding.line_start ? `-${finding.line_end}` : ''}</strong></span>
              </div>
            </div>

            {/* Source Context Window */}
            {sourceCtx && (sourceCtx.context_before || sourceCtx.vulnerable_code || sourceCtx.context_after) ? (
              <div className="space-y-1 pt-1">
                <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
                  Source Context Window:
                </span>
                <div className="bg-[#0d1117] border border-slate-800 rounded-xl p-3 font-mono text-xs space-y-1 overflow-x-auto">
                  {sourceCtx.context_before && (
                    <div className="text-slate-600 select-none whitespace-pre">
                      {sourceCtx.context_before}
                    </div>
                  )}
                  {sourceCtx.vulnerable_code && (
                    <div className="bg-rose-950/40 text-rose-300 border-l-2 border-rose-500 pl-2.5 py-1 my-1 font-semibold whitespace-pre">
                      {sourceCtx.vulnerable_code}
                    </div>
                  )}
                  {sourceCtx.context_after && (
                    <div className="text-slate-600 select-none whitespace-pre">
                      {sourceCtx.context_after}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              finding.code && (
                <div className="space-y-1 pt-1">
                  <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
                    Flagged Code Snippet:
                  </span>
                  <div className="bg-[#0d1117] border border-rose-500/30 rounded-xl p-3 font-mono text-xs text-rose-300 whitespace-pre overflow-x-auto">
                    <code>{finding.code}</code>
                  </div>
                </div>
              )
            )}
          </div>

          {/* Section 3: Detection Evidence & Preserved Analyzer Evidence */}
          <div className="space-y-3 bg-slate-950/60 border border-slate-800 p-4 rounded-xl">
            <h4 className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="h-4 w-4" />
              3. DETECTION EVIDENCE & ANALYZERS
            </h4>

            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <span className="text-slate-400 font-mono">Detected by:</span>
                <div className="flex items-center space-x-1.5">
                  {detectedBy.map((tool) => (
                    <span key={tool} className="bg-slate-800 text-slate-200 font-mono px-2.5 py-0.5 rounded text-[11px] font-semibold capitalize border border-slate-700">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              {/* Correlated Analyzer Evidence List */}
              {finding.analyzer_evidence && finding.analyzer_evidence.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
                    Preserved Engine Evidence:
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {finding.analyzer_evidence.map((ev, idx) => (
                      <div key={idx} className="bg-slate-900 border border-slate-800 p-2.5 rounded-lg font-mono text-[11px] space-y-1">
                        <div className="flex justify-between items-center text-slate-300">
                          <strong className="capitalize text-cyan-400">{ev.analyzer}</strong>
                          <span className="text-slate-500">Rule: {ev.rule_id}</span>
                        </div>
                        <div className="flex justify-between text-slate-400 text-[10px]">
                          <span>Confidence: {ev.confidence || 'MEDIUM'}</span>
                          <span>Severity: {ev.severity || 'MEDIUM'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Section 4, 5, 6: Remediation Guidance Panel */}
          {finding.remediation && (
            <RemediationPanel remediation={finding.remediation} />
          )}
        </div>

        {/* Modal Footer */}
        <div className="bg-slate-950 px-6 py-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}
