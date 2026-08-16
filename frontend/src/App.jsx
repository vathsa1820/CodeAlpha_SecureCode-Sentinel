import React, { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardPage from './pages/DashboardPage';
import CodeAnalyzerPage from './pages/CodeAnalyzerPage';
import FindingsPage from './pages/FindingsPage';
import ReportsPage from './pages/ReportsPage';
import { LayoutDashboard, Code2, ShieldAlert, FileText } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [reportHistory, setReportHistory] = useState([]);

  const handleAddReportToHistory = (newReport) => {
    setReportHistory((prev) => {
      const exists = prev.some((r) => r.report_id === newReport.report_id);
      if (exists) return prev;
      return [newReport, ...prev];
    });
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardPage
            analysisResult={analysisResult}
            onNavigate={setActiveTab}
          />
        );
      case 'analyzer':
        return (
          <CodeAnalyzerPage
            analysisResult={analysisResult}
            setAnalysisResult={setAnalysisResult}
            onAddReportToHistory={handleAddReportToHistory}
          />
        );
      case 'findings':
        return (
          <FindingsPage
            analysisResult={analysisResult}
            onNavigate={setActiveTab}
          />
        );
      case 'reports':
        return (
          <ReportsPage
            reportHistory={reportHistory}
            setReportHistory={setReportHistory}
            onNavigate={setActiveTab}
          />
        );
      default:
        return (
          <DashboardPage
            analysisResult={analysisResult}
            onNavigate={setActiveTab}
          />
        );
    }
  };

  const mobileNavItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyzer', label: 'Analyzer', icon: Code2 },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* Top Application Header */}
      <Header />

      {/* Main Container Shell */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full pb-20 md:pb-8">
          {renderActiveView()}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 bg-slate-950/95 border-t border-slate-800 backdrop-blur-md z-40 px-2 py-2 flex justify-around items-center">
        {mobileNavItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex flex-col items-center py-1 px-3 rounded-lg text-[11px] font-medium transition-colors ${
                isActive ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="h-5 w-5 mb-0.5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
}
