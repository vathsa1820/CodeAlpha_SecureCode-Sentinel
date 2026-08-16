import React, { useState, useMemo } from 'react';
import FindingsList from '../components/FindingsList';
import FindingDetails from '../components/FindingDetails';
import EmptyState from '../components/EmptyState';
import { Filter, ArrowUpDown, ShieldAlert } from 'lucide-react';

export default function FindingsPage({ analysisResult, onNavigate }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [analyzerFilter, setAnalyzerFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('severity');
  const [selectedFinding, setSelectedFinding] = useState(null);

  const findings = analysisResult?.findings || [];

  // Extract unique categories for filter dropdown
  const uniqueCategories = useMemo(() => {
    const cats = new Set(findings.map((f) => f.category).filter(Boolean));
    return Array.from(cats);
  }, [findings]);

  // Filter & Sort Logic
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (severityFilter !== 'ALL' && (f.severity || '').toUpperCase() !== severityFilter) return false;
        if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
        if (analyzerFilter !== 'ALL') {
          const tools = f.detected_by || [f.analyzer];
          if (!tools.includes(analyzerFilter)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'severity') {
          const weights = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
          const wA = weights[(a.severity || '').toUpperCase()] || 0;
          const wB = weights[(b.severity || '').toUpperCase()] || 0;
          return wB - wA;
        }
        if (sortBy === 'line') {
          return (a.line_start || 0) - (b.line_start || 0);
        }
        if (sortBy === 'category') {
          return (a.category || '').localeCompare(b.category || '');
        }
        return 0;
      });
  }, [findings, severityFilter, categoryFilter, analyzerFilter, sortBy]);

  if (!analysisResult) {
    return (
      <div className="space-y-6">
        <div className="border-b border-slate-800 pb-4">
          <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
            SECURITY FINDINGS EXPLORER
          </h2>
          <p className="text-xs text-slate-400">
            View, filter, and inspect correlated static analysis findings
          </p>
        </div>

        <EmptyState onAction={() => onNavigate('analyzer')} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
          SECURITY FINDINGS EXPLORER
        </h2>
        <p className="text-xs text-slate-400">
          Showing {filteredFindings.length} of {findings.length} deduplicated logical security findings
        </p>
      </div>

      {/* Controls: Filter & Sort Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xl text-xs font-mono">
        <div className="flex items-center space-x-3 flex-wrap gap-y-2">
          <div className="flex items-center space-x-1.5 text-slate-400">
            <Filter className="h-4 w-4 text-cyan-400" />
            <span className="font-semibold uppercase">Filters:</span>
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            {uniqueCategories.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>

          {/* Analyzer Filter */}
          <select
            value={analyzerFilter}
            onChange={(e) => setAnalyzerFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Analyzers</option>
            <option value="bandit">Bandit</option>
            <option value="semgrep">Semgrep</option>
          </select>
        </div>

        {/* Sort Controls */}
        <div className="flex items-center space-x-2">
          <ArrowUpDown className="h-3.5 w-3.5 text-slate-400" />
          <span className="text-slate-400 font-semibold uppercase">Sort:</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="severity">Highest Severity</option>
            <option value="line">Source Line</option>
            <option value="category">Category</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <FindingsList
        findings={filteredFindings}
        onSelectFinding={setSelectedFinding}
      />

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <FindingDetails
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
