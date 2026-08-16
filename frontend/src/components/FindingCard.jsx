import React from 'react';
import { AlertCircle, Code, ChevronRight, ShieldAlert, Cpu } from 'lucide-react';

export default function FindingCard({ finding, onSelect }) {
  if (!finding) return null;

  const getSeverityStyle = (sev) => {
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

  const detectedBy = finding.detected_by && finding.detected_by.length > 0
    ? finding.detected_by
    : [finding.analyzer];

  return (
    <div
      onClick={() => onSelect(finding)}
      className="bg-slate-900/90 border border-slate-800/90 hover:border-cyan-500/40 rounded-2xl p-5 cursor-pointer transition-all hover:shadow-xl hover:shadow-cyan-950/20 group relative overflow-hidden flex flex-col justify-between"
    >
      <div className="space-y-3">
        {/* Header Badges */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
            {/* Severity */}
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border uppercase tracking-wider ${getSeverityStyle(finding.severity)}`}>
              {finding.severity}
            </span>

            {/* Category */}
            <span className="bg-slate-950 text-slate-300 border border-slate-800 text-[11px] font-mono px-2.5 py-0.5 rounded-md uppercase">
              {finding.category}
            </span>

            {/* CWE */}
            {finding.cwe && (
              <span className="bg-purple-950/80 text-purple-300 border border-purple-800/60 text-[11px] font-mono px-2.5 py-0.5 rounded-md uppercase font-semibold">
                {finding.cwe}
              </span>
            )}
          </div>

          {/* Line number info */}
          <div className="text-xs font-mono text-cyan-400/90 bg-cyan-950/60 border border-cyan-800/50 px-2.5 py-1 rounded-lg flex items-center gap-1">
            <Code className="h-3.5 w-3.5" />
            <span>Line {finding.line_start}{finding.line_end > finding.line_start ? `-${finding.line_end}` : ''}</span>
          </div>
        </div>

        {/* Vulnerability Title */}
        <h4 className="text-base font-bold text-slate-100 group-hover:text-cyan-400 transition-colors font-mono">
          {finding.title}
        </h4>

        {/* Short Description */}
        <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed font-sans">
          {finding.description}
        </p>

        {/* Code Snippet Preview */}
        {finding.code && (
          <div className="bg-[#0d1117] border border-slate-800/80 rounded-xl p-2.5 font-mono text-xs text-slate-300 overflow-x-auto select-none">
            <code className="text-cyan-300/90">{finding.code}</code>
          </div>
        )}
      </div>

      {/* Footer Meta & Action */}
      <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono text-slate-500">
        <div className="flex items-center space-x-2">
          <Cpu className="h-3.5 w-3.5 text-slate-500" />
          <span>Detected by:</span>
          <div className="flex items-center space-x-1">
            {detectedBy.map((tool) => (
              <span key={tool} className="bg-slate-800 text-slate-300 text-[10px] px-2 py-0.5 rounded capitalize font-medium">
                {tool}
              </span>
            ))}
          </div>
        </div>

        <button className="text-cyan-400 group-hover:text-cyan-300 font-semibold flex items-center gap-1 transition-all">
          <span>View Details</span>
          <ChevronRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
        </button>
      </div>
    </div>
  );
}
