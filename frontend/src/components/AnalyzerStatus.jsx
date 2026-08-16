import React from 'react';
import { Cpu, CheckCircle2, ShieldCheck, Server } from 'lucide-react';

export default function AnalyzerStatus({ analyzers = [], scan = null }) {
  const activeList = analyzers && analyzers.length > 0 ? analyzers : ['bandit', 'semgrep'];
  const analyzerStatuses = scan?.analyzer_status || [];

  const getExecMode = (name) => {
    const found = analyzerStatuses.find(
      (s) => s.name?.toLowerCase() === name?.toLowerCase()
    );
    return found?.execution_mode || 'local';
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold flex items-center gap-1.5">
          <Cpu className="h-4 w-4 text-cyan-400" />
          ACTIVE ANALYZERS
        </h3>

        {analyzerStatuses.length > 0 && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-slate-700 bg-slate-950 text-slate-300 flex items-center gap-1">
            {analyzerStatuses[0]?.execution_mode === 'docker' ? (
              <>
                <ShieldCheck className="h-3 w-3 text-emerald-400" />
                <span>Docker Sandbox</span>
              </>
            ) : (
              <>
                <Server className="h-3 w-3 text-cyan-400" />
                <span>Local</span>
              </>
            )}
          </span>
        )}
      </div>

      <div className="space-y-2">
        {activeList.map((analyzer) => {
          const mode = getExecMode(analyzer);
          return (
            <div
              key={analyzer}
              className="flex items-center justify-between bg-slate-950/80 border border-slate-800 px-3.5 py-2 rounded-xl text-xs font-mono"
            >
              <div className="flex items-center space-x-2">
                <span className="capitalize text-slate-200 font-semibold">{analyzer}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${
                  mode === 'docker'
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {mode === 'docker' ? 'docker' : 'local'}
                </span>
              </div>
              <span className="text-emerald-400 flex items-center gap-1 font-medium text-[11px]">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Completed
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
