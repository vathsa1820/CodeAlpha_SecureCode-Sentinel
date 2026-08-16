import React from 'react';
import { ShieldAlert, Layers, AlertCircle, FolderGit2, FileText } from 'lucide-react';

export default function RiskSummary({ security, findings = [] }) {
  if (!security) return null;

  const logicalCount = security.logical_vulnerabilities ?? findings.length;
  const rawCount = security.raw_detections ?? findings.length;
  const highestSev = security.highest_severity || 'NONE';

  const categoriesSet = new Set(findings.map((f) => f.category).filter(Boolean));
  const filesSet = new Set(findings.map((f) => f.source_file).filter(Boolean));

  const stats = [
    {
      label: 'Logical Vulnerabilities',
      value: logicalCount,
      icon: ShieldAlert,
      color: logicalCount > 0 ? 'text-rose-400' : 'text-emerald-400',
      bg: 'bg-rose-500/10 border-rose-500/20',
    },
    {
      label: 'Raw Detections',
      value: rawCount,
      icon: Layers,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10 border-cyan-500/20',
    },
    {
      label: 'Highest Severity',
      value: highestSev,
      icon: AlertCircle,
      color:
        highestSev === 'CRITICAL'
          ? 'text-rose-400'
          : highestSev === 'HIGH'
          ? 'text-orange-400'
          : highestSev === 'MEDIUM'
          ? 'text-amber-400'
          : highestSev === 'LOW'
          ? 'text-blue-400'
          : 'text-emerald-400',
      bg: 'bg-slate-800/80 border-slate-700/80',
    },
    {
      label: 'Affected Categories',
      value: categoriesSet.size,
      icon: FolderGit2,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10 border-purple-500/20',
    },
    {
      label: 'Affected Files',
      value: filesSet.size > 0 ? filesSet.size : 1,
      icon: FileText,
      color: 'text-indigo-400',
      bg: 'bg-indigo-500/10 border-indigo-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
      {stats.map((stat, i) => {
        const Icon = stat.icon;
        return (
          <div
            key={i}
            className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between shadow-lg hover:border-slate-700 transition-colors"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                {stat.label}
              </span>
              <div className={`p-1.5 rounded-lg border ${stat.bg}`}>
                <Icon className={`h-4 w-4 ${stat.color}`} />
              </div>
            </div>

            <div className={`text-xl font-bold font-mono ${stat.color}`}>
              {stat.value}
            </div>
          </div>
        );
      })}
    </div>
  );
}
