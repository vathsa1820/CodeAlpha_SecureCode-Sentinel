import React from 'react';
import { ShieldCheck, CheckCircle2, AlertTriangle, Lightbulb } from 'lucide-react';

export default function RemediationPanel({ remediation }) {
  if (!remediation) return null;

  return (
    <div className="bg-slate-950/90 border border-cyan-500/30 rounded-2xl p-5 space-y-4 shadow-2xl relative overflow-hidden">
      <div className="flex items-center space-x-2 text-cyan-400 font-mono font-bold text-xs uppercase tracking-wider">
        <ShieldCheck className="h-4 w-4 text-cyan-400" />
        <span>REMEDIATION GUIDANCE</span>
      </div>

      <h4 className="text-base font-bold font-mono text-slate-100">
        {remediation.title}
      </h4>

      {/* Explanation / Why it matters */}
      <div className="space-y-1">
        <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider block">
          Why It Matters:
        </span>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          {remediation.explanation}
        </p>
      </div>

      {/* Potential Impact */}
      {remediation.impact && (
        <div className="bg-rose-950/30 border border-rose-800/40 rounded-xl p-3 space-y-1">
          <span className="text-xs font-mono font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            Potential Impact:
          </span>
          <p className="text-xs text-rose-200/90 leading-relaxed font-sans">
            {remediation.impact}
          </p>
        </div>
      )}

      {/* Recommendation */}
      <div className="space-y-1">
        <span className="text-xs font-mono font-semibold text-cyan-400 uppercase tracking-wider block">
          Recommendation:
        </span>
        <p className="text-xs text-slate-200 leading-relaxed font-sans">
          {remediation.recommendation}
        </p>
      </div>

      {/* Best Practice */}
      {remediation.best_practice && (
        <div className="bg-emerald-950/30 border border-emerald-800/40 rounded-xl p-3 space-y-1">
          <span className="text-xs font-mono font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
            <Lightbulb className="h-3.5 w-3.5" />
            Secure Best Practice:
          </span>
          <p className="text-xs text-emerald-200/90 leading-relaxed font-sans">
            {remediation.best_practice}
          </p>
        </div>
      )}

      {/* Secure Code Example */}
      {remediation.secure_example && (
        <div className="space-y-2 pt-1">
          <span className="text-xs font-mono font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
            <CheckCircle2 className="h-4 w-4" />
            Secure Implementation Example:
          </span>
          <div className="bg-[#0d1117] border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-emerald-300/90 overflow-x-auto whitespace-pre">
            <code>{remediation.secure_example}</code>
          </div>
        </div>
      )}
    </div>
  );
}
