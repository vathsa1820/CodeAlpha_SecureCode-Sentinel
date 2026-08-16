import React, { useState } from 'react';
import CodeEditor from '../components/CodeEditor';
import SecurityScore from '../components/SecurityScore';
import RiskSummary from '../components/RiskSummary';
import SeverityBreakdown from '../components/SeverityBreakdown';
import AnalyzerStatus from '../components/AnalyzerStatus';
import FindingsList from '../components/FindingsList';
import FindingDetails from '../components/FindingDetails';
import ReportModal from '../components/ReportModal';
import { analyzeCode, createReport } from '../services/api';
import { AlertTriangle, CheckCircle2, FileText, RefreshCw, Info } from 'lucide-react';
import { VULNERABLE_SAMPLE_CODE } from '../services/sampleData';

export default function CodeAnalyzerPage({ analysisResult, setAnalysisResult, onAddReportToHistory }) {
  const [code, setCode] = useState(VULNERABLE_SAMPLE_CODE);
  const [filename, setFilename] = useState('vulnerable_sample.py');
  const [lastScannedCode, setLastScannedCode] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [fileError, setFileError] = useState(null);
  const [reportSuccess, setReportSuccess] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeReportModal, setActiveReportModal] = useState(null);

  const isStale = analysisResult && lastScannedCode !== null && lastScannedCode !== code;

  const handleRunAnalysis = async () => {
    if (!code || !code.trim()) return;

    setApiError(null);
    setFileError(null);
    setReportSuccess(null);
    setIsAnalyzing(true);

    const result = await analyzeCode(code, filename);

    setIsAnalyzing(false);

    if (result.success) {
      setAnalysisResult(result.data);
      setLastScannedCode(code);
    } else {
      setApiError(result.error);
    }
  };

  const handleGenerateReport = async () => {
    if (!analysisResult) return;

    setIsGeneratingReport(true);
    setApiError(null);

    const res = await createReport(analysisResult);

    setIsGeneratingReport(false);

    if (res.success && res.data) {
      const generatedReport = res.data.report || res.data;
      setReportSuccess(generatedReport);
      if (onAddReportToHistory) {
        onAddReportToHistory(generatedReport);
      }
    } else {
      setApiError(res.error || 'Failed to generate report.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Title */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wider">
          PYTHON CODE ANALYZER
        </h2>
        <p className="text-xs text-slate-400">
          Paste Python code or upload a .py file for static security review & vulnerability scanning
        </p>
      </div>

      {/* API Error Alert */}
      {apiError && (
        <div className="bg-rose-950/70 border border-rose-800 rounded-2xl p-4 text-xs text-rose-200 flex items-start gap-3 shadow-xl">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-bold font-mono text-rose-300">Request Error</h4>
            <p className="leading-relaxed font-sans">{apiError}</p>
          </div>
        </div>
      )}

      {/* Report Generation Success Alert */}
      {reportSuccess && (
        <div className="bg-emerald-950/70 border border-emerald-800 rounded-2xl p-4 text-xs text-emerald-200 flex items-center justify-between shadow-xl">
          <div className="flex items-center space-x-2 font-mono">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
            <span>Security Review Report <strong>{reportSuccess.report_id}</strong> generated successfully!</span>
          </div>
          <button
            onClick={() => setActiveReportModal(reportSuccess)}
            className="px-3 py-1.5 rounded-xl font-mono text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-colors flex items-center gap-1.5"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>VIEW REPORT</span>
          </button>
        </div>
      )}

      {/* Code Editor Container */}
      <CodeEditor
        code={code}
        setCode={setCode}
        filename={filename}
        setFilename={setFilename}
        onAnalyze={handleRunAnalysis}
        isAnalyzing={isAnalyzing}
        fileError={fileError}
        setFileError={setFileError}
      />

      {/* Stale Analysis Results Warning Banner */}
      {isStale && (
        <div className="bg-amber-950/60 border border-amber-800/80 rounded-2xl p-3.5 text-xs text-amber-200 flex items-center justify-between shadow-lg">
          <div className="flex items-center space-x-2 font-mono">
            <Info className="h-4 w-4 text-amber-400 shrink-0" />
            <span><strong>Notice:</strong> Source code has modified since last scan. Displayed results correspond to previous code state.</span>
          </div>
          <button
            onClick={handleRunAnalysis}
            className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors"
          >
            RE-RUN SCAN
          </button>
        </div>
      )}

      {/* Live Analysis Results Display & Generate Report Action */}
      {analysisResult && (
        <div className="space-y-6 pt-4 border-t border-slate-800/80 animate-fadeIn">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 p-4 rounded-2xl">
            <div>
              <h3 className="text-sm font-mono text-cyan-400 uppercase tracking-wider font-bold flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                ANALYSIS COMPLETE FOR {filename.toUpperCase()}
              </h3>
              <p className="text-xs text-slate-400">
                Score: <strong className="text-slate-200">{analysisResult.security?.score}</strong> | Risk Level: <strong className="text-rose-400 uppercase">{analysisResult.security?.risk_level}</strong>
              </p>
            </div>

            <button
              onClick={handleGenerateReport}
              disabled={isGeneratingReport || isStale}
              title={isStale ? "Run new scan before generating report" : "Generate security report"}
              className={`px-4 py-2.5 rounded-xl text-xs font-mono font-bold flex items-center gap-2 shadow-lg transition-all ${
                isGeneratingReport || isStale
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-800'
                  : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-emerald-500/20 border border-emerald-400'
              }`}
            >
              {isGeneratingReport ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  <span>GENERATING REPORT...</span>
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4" />
                  <span>GENERATE SECURITY REPORT</span>
                </>
              )}
            </button>
          </div>

          {/* Metrics & Score Grid */}
          <RiskSummary
            security={analysisResult.security}
            findings={analysisResult.findings}
          />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <SecurityScore
              score={analysisResult.security?.score ?? 100}
              riskLevel={analysisResult.security?.risk_level ?? 'MINIMAL'}
            />

            <SeverityBreakdown summary={analysisResult.summary} />

            <AnalyzerStatus
              analyzers={analysisResult.analyzers}
              scan={analysisResult.scan}
            />
          </div>

          {/* Correlated Findings List */}
          <FindingsList
            findings={analysisResult.findings}
            onSelectFinding={setSelectedFinding}
          />
        </div>
      )}

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <FindingDetails
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}

      {/* Security Report Modal */}
      {activeReportModal && (
        <ReportModal
          report={activeReportModal}
          onClose={() => setActiveReportModal(null)}
        />
      )}
    </div>
  );
}
