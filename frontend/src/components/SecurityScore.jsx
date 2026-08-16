import React from 'react';

export default function SecurityScore({ score = 100, riskLevel = 'MINIMAL' }) {
  // Determine color theme based on score & risk level
  const getTheme = () => {
    switch (riskLevel.toUpperCase()) {
      case 'CRITICAL':
        return {
          stroke: '#f43f5e', // rose-500
          text: 'text-rose-400',
          bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
          gradient: 'from-rose-500 to-red-600',
        };
      case 'HIGH':
        return {
          stroke: '#f97316', // orange-500
          text: 'text-orange-400',
          bg: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
          gradient: 'from-orange-500 to-amber-600',
        };
      case 'MEDIUM':
        return {
          stroke: '#f59e0b', // amber-500
          text: 'text-amber-400',
          bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
          gradient: 'from-amber-500 to-yellow-600',
        };
      case 'LOW':
        return {
          stroke: '#3b82f6', // blue-500
          text: 'text-blue-400',
          bg: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
          gradient: 'from-blue-500 to-cyan-600',
        };
      case 'MINIMAL':
      default:
        return {
          stroke: '#10b981', // emerald-500
          text: 'text-emerald-400',
          bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
          gradient: 'from-emerald-500 to-teal-600',
        };
    }
  };

  const theme = getTheme();
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 flex flex-col items-center justify-center shadow-xl">
      <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 font-semibold">
        SECURITY SCORE
      </h3>

      {/* Radial Progress Gauge */}
      <div className="relative w-32 h-32 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            className="stroke-slate-800"
            strokeWidth="8"
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            stroke={theme.stroke}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Score Value Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`text-3xl font-bold font-mono tracking-tight ${theme.text}`}>
            {score}
          </span>
          <span className="text-[10px] font-mono text-slate-500 font-medium uppercase">
            OUT OF 100
          </span>
        </div>
      </div>

      {/* Risk Level Badge */}
      <div className="mt-4 flex flex-col items-center">
        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">
          RISK LEVEL
        </span>
        <span
          className={`px-3 py-1 rounded-full text-xs font-mono font-bold border uppercase tracking-wider ${theme.bg}`}
        >
          {riskLevel}
        </span>
      </div>
    </div>
  );
}
