import React from 'react';
import FindingCard from './FindingCard';
import { ShieldCheck } from 'lucide-react';

export default function FindingsList({ findings = [], onSelectFinding }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-8 text-center space-y-3 shadow-xl">
        <div className="bg-emerald-500/10 border border-emerald-500/30 p-3 rounded-full w-12 h-12 mx-auto flex items-center justify-center text-emerald-400">
          <ShieldCheck className="h-6 w-6" />
        </div>
        <h4 className="text-base font-bold font-mono text-slate-200">Zero Vulnerabilities Detected</h4>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Static security analysis completed with clean results. No security issues or rule violations were flagged in the analyzed code.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between px-1">
        <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
          LOGICAL FINDINGS ({findings.length})
        </h3>
        <span className="text-xs font-mono text-slate-500">
          Click any card for full remediation guidance
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {findings.map((finding) => (
          <FindingCard
            key={finding.id || finding.finding_group_id}
            finding={finding}
            onSelect={onSelectFinding}
          />
        ))}
      </div>
    </div>
  );
}
