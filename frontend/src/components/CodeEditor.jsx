import React, { useRef } from 'react';
import { Upload, FileCode, Play, AlertCircle, FileCheck, RefreshCw } from 'lucide-react';
import { VULNERABLE_SAMPLE_CODE, SECURE_SAMPLE_CODE } from '../services/sampleData';

export default function CodeEditor({
  code,
  setCode,
  filename,
  setFilename,
  onAnalyze,
  isAnalyzing,
  fileError,
  setFileError,
}) {
  const fileInputRef = useRef(null);

  const lineCount = Math.max(1, code.split('\n').length);
  const lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1);

  const handleFileUpload = (e) => {
    setFileError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.py')) {
      setFileError('Invalid file type. Only Python source files (.py) are supported.');
      return;
    }

    if (file.size > 500 * 1024) {
      setFileError('File exceeds maximum size limit of 500 KB.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result;
      if (typeof text === 'string') {
        setCode(text);
        setFilename(file.name);
      }
    };
    reader.onerror = () => {
      setFileError('Failed to read selected file.');
    };
    reader.readAsText(file);
  };

  const handleLoadVulnerableSample = () => {
    setFileError(null);
    setCode(VULNERABLE_SAMPLE_CODE);
    setFilename('vulnerable_sample.py');
  };

  const handleLoadSecureSample = () => {
    setFileError(null);
    setCode(SECURE_SAMPLE_CODE);
    setFilename('secure_sample.py');
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
      {/* Editor Top Bar */}
      <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3 min-w-[200px]">
          <FileCode className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-mono text-slate-400">Filename:</span>
          <input
            type="text"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50 w-44"
            placeholder="target_file.py"
          />
        </div>

        {/* Sample Load Buttons & File Upload */}
        <div className="flex items-center space-x-2 flex-wrap gap-y-2">
          <button
            type="button"
            onClick={handleLoadVulnerableSample}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors flex items-center gap-1.5"
          >
            <AlertCircle className="h-3.5 w-3.5" />
            Load Vulnerable Sample
          </button>

          <button
            type="button"
            onClick={handleLoadSecureSample}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 transition-colors flex items-center gap-1.5"
          >
            <FileCheck className="h-3.5 w-3.5" />
            Load Secure Sample
          </button>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".py"
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <Upload className="h-3.5 w-3.5" />
            Upload .py File
          </button>
        </div>
      </div>

      {/* File Upload Error Alert */}
      {fileError && (
        <div className="bg-rose-950/60 border-b border-rose-800/80 px-4 py-2 text-xs font-medium text-rose-300 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
          <span>{fileError}</span>
        </div>
      )}

      {/* Code Textarea Area with Monospace & Line Numbers */}
      <div className="relative flex flex-1 min-h-[360px] max-h-[500px] bg-[#0d1117] font-mono text-xs overflow-hidden">
        {/* Line Numbers Sidebar */}
        <div className="w-12 py-3 bg-[#0a0d14] border-r border-slate-800/80 text-slate-600 text-right pr-3 select-none overflow-hidden shrink-0">
          {lineNumbers.map((num) => (
            <div key={num} className="leading-6">
              {num}
            </div>
          ))}
        </div>

        {/* Text Area */}
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="# Paste your Python source code here for static security analysis..."
          spellCheck={false}
          className="flex-1 p-3 bg-transparent text-slate-200 resize-none focus:outline-none leading-6 font-mono overflow-auto whitespace-pre tab-4"
        />
      </div>

      {/* Action Footer */}
      <div className="bg-slate-950 px-4 py-3 border-t border-slate-800 flex items-center justify-between">
        <div className="text-xs text-slate-500 font-mono">
          {code.length} characters | {lineCount} lines
        </div>

        <button
          type="button"
          onClick={onAnalyze}
          disabled={isAnalyzing || !code.trim()}
          className={`px-5 py-2.5 rounded-xl font-medium text-xs font-mono flex items-center gap-2 shadow-lg transition-all ${
            isAnalyzing || !code.trim()
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-800'
              : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold shadow-cyan-500/20 border border-cyan-400 hover:scale-[1.02] active:scale-[0.98]'
          }`}
        >
          {isAnalyzing ? (
            <>
              <RefreshCw className="h-4 w-4 animate-spin" />
              <span>ANALYZING CODE...</span>
            </>
          ) : (
            <>
              <Play className="h-4 w-4 fill-current" />
              <span>ANALYZE CODE</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
