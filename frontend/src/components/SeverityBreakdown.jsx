import React from 'react';

export default function SeverityBreakdown({ summary }) {
  if (!summary) return null;

  const total = summary.total || 1; // Prevent division by zero

  const items = [
    { label: 'CRITICAL', count: summary.critical || 0, color: 'bg-rose-500', text: 'text-rose-400', border: 'border-rose-500/30' },
    { label: 'HIGH', count: summary.high || 0, color: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30' },
    { label: 'MEDIUM', count: summary.medium || 0, color: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500/30' },
    { label: 'LOW', count: summary.low || 0, color: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500/30' },
    { label: 'INFO', count: summary.info || 0, color: 'bg-slate-500', text: 'text-slate-400', border: 'border-slate-500/30' },
  ];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-col justify-between">
      <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 font-semibold">
        SEVERITY BREAKDOWN
      </h3>

      <div className="space-y-3.5 flex-1 justify-center flex flex-col">
        {items.map((item) => {
          const percentage = Math.round(((item.count || 0) / total) * 100);
          return (
            <div key={item.label} className="space-y-1">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className={`font-bold ${item.text}`}>{item.label}</span>
                <span className="text-slate-400 font-semibold">{item.count}</span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                <div
                  className={`h-full ${item.color} transition-all duration-700 ease-out`}
                  style={{ width: `${item.count > 0 ? Math.max(8, percentage) : 0}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
