import React from 'react';
import { LayoutDashboard, Code2, ShieldAlert, FileText, ChevronRight } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, desc: 'Overview & security metrics' },
    { id: 'analyzer', label: 'Code Analyzer', icon: Code2, desc: 'Static Python scanner' },
    { id: 'findings', label: 'Findings', icon: ShieldAlert, desc: 'Correlated security issues' },
    { id: 'reports', label: 'Reports', icon: FileText, desc: 'Export & metadata' },
  ];

  return (
    <aside className="hidden md:flex flex-col w-64 bg-slate-950/60 border-r border-slate-800/80 p-4 space-y-6 shrink-0">
      <div className="px-2 pt-1">
        <span className="text-[11px] font-mono tracking-wider text-slate-500 uppercase font-semibold">
          Navigation Menu
        </span>
      </div>

      <nav className="space-y-1.5 flex-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-3 rounded-xl text-sm font-medium transition-all group ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-950/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 border border-transparent'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`h-5 w-5 transition-transform group-hover:scale-110 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <div className="text-left">
                  <div className="font-semibold">{item.label}</div>
                  <div className="text-[10px] text-slate-500 font-normal">{item.desc}</div>
                </div>
              </div>
              <ChevronRight className={`h-4 w-4 transition-transform ${isActive ? 'text-cyan-400 opacity-100 translate-x-0.5' : 'opacity-0 group-hover:opacity-100 text-slate-600'}`} />
            </button>
          );
        })}
      </nav>

      <div className="p-3.5 bg-slate-900/80 border border-slate-800/80 rounded-xl space-y-2 text-xs text-slate-400">
        <div className="font-mono text-cyan-400 font-semibold flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse"></span>
          NO-EXECUTION SAST
        </div>
        <p className="text-[11px] leading-relaxed text-slate-500">
          Source code is analyzed strictly as static text and is never executed or imported.
        </p>
      </div>
    </aside>
  );
}
