import React from 'react';
import { Shield, Play } from 'lucide-react';

export default function EmptyState({ onAction, title = "Run Your First Security Analysis", message = "No static analysis results available yet. Submit Python source code to analyze security vulnerabilities, calculate risk scores, and view remediation guidance." }) {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-10 text-center space-y-4 shadow-2xl max-w-xl mx-auto my-8">
      <div className="bg-cyan-500/10 border border-cyan-500/30 p-4 rounded-full w-16 h-16 mx-auto flex items-center justify-center text-cyan-400">
        <Shield className="h-8 w-8" />
      </div>

      <div className="space-y-1.5">
        <h3 className="text-lg font-bold font-mono text-slate-100">{title}</h3>
        <p className="text-xs text-slate-400 leading-relaxed font-sans">{message}</p>
      </div>

      {onAction && (
        <button
          onClick={onAction}
          className="px-5 py-2.5 rounded-xl font-mono text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all border border-cyan-400 inline-flex items-center gap-2 mt-2"
        >
          <Play className="h-4 w-4 fill-current" />
          <span>OPEN CODE ANALYZER</span>
        </button>
      )}
    </div>
  );
}
