import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, CheckCircle2, RefreshCw } from 'lucide-react';
import { checkBackendHealth } from '../services/api';

export default function Header() {
  const [health, setHealth] = useState({ status: 'checking' });
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchHealth = async () => {
    setIsRefreshing(true);
    const result = await checkBackendHealth();
    setHealth(result);
    setTimeout(() => setIsRefreshing(false), 500);
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="bg-slate-950/80 border-b border-slate-800/80 backdrop-blur-md sticky top-0 z-30 px-4 sm:px-6 py-3.5 flex items-center justify-between shadow-xl">
      <div className="flex items-center space-x-3.5">
        <div className="bg-cyan-500/10 border border-cyan-500/30 p-2 rounded-xl text-cyan-400 shadow-inner">
          <Shield className="h-6 w-6" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-bold text-lg sm:text-xl tracking-wider text-slate-100 font-mono uppercase">
              SECURECODE <span className="text-cyan-400">SENTINEL</span>
            </h1>
            <span className="bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 text-[10px] font-mono px-2 py-0.5 rounded-md uppercase font-semibold">
              v0.1.0 SAST
            </span>
          </div>
          <p className="text-xs text-slate-400 font-medium hidden sm:block">
            Static Security Analysis for Safer Code
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-3">
        <button
          onClick={fetchHealth}
          title="Refresh Engine Health"
          className="text-slate-400 hover:text-cyan-400 transition-colors p-1.5 rounded-lg hover:bg-slate-900"
        >
          <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        <div className="flex items-center space-x-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-xl text-xs font-mono">
          <span className="text-slate-400">Backend:</span>
          {health.status === 'checking' && (
            <span className="text-amber-400 flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse"></span>
              Connecting...
            </span>
          )}
          {health.status === 'ok' && (
            <span className="text-emerald-400 flex items-center gap-1.5 font-semibold">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              ONLINE
            </span>
          )}
          {(health.status === 'error' || health.status === 'offline') && (
            <span className="text-rose-400 flex items-center gap-1.5 font-semibold">
              <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
              OFFLINE
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
