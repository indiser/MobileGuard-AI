import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Activity, Server, Clock, Cpu } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import UploadZone from './components/UploadZone';
import ProgressTracker from './components/ProgressTracker';
import RiskGauge from './components/RiskGauge';
import DimensionChart from './components/DimensionChart';
import ShapExplainer from './components/ShapExplainer';
import ThreatReport from './components/ThreatReport';
import ActionBanner from './components/ActionBanner';
import AuditLog from './components/AuditLog';
import { uploadAPK, fetchHealth } from './api/client';

function App() {
  const [health, setHealth] = useState({ status: 'unknown' });
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [isUploading, setIsUploading] = useState(false);

  // Mock initial logs
  const [logs, setLogs] = useState([
    {
      timestamp: new Date().toISOString(),
      filename: "test_sample_1.apk",
      score: 22,
      action: "APPROVE",
      duration: 1200
    }
  ]);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'offline' }));
  }, []);

  const handleUpload = useCallback(async (file) => {
    if (!file) return;
    setIsUploading(true);
    setEvents([]);
    setError(null);
    setResult(null);

    try {
      await uploadAPK(file, (event) => {
        setEvents(prev => [...prev.filter(e => e.stage !== event.stage), event]);

        if (event.stage === 'error') {
          setError(event.error);
          setIsUploading(false);
        }

        if (event.stage === 'complete' && event.result) {
          setResult(event.result);
          setIsUploading(false);
          setLogs(prev => [
            {
              timestamp: new Date().toISOString(),
              filename: event.result.filename,
              score: event.result.score.composite_score,
              action: event.result.score.action,
              duration: event.result.total_duration_ms
            },
            ...prev
          ]);
        }
      });
    } catch (err) {
      setError(err.message ?? 'Unexpected error during upload.');
      setIsUploading(false);
    }
  }, []);

  return (
    <div className="min-h-screen bg-background text-textPrimary font-sans overflow-x-hidden relative">
      {/* Animated Background Glows */}
      <div className="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-accent/10 blur-[150px] rounded-full pointer-events-none" />
      <div className="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-indigo-500/10 blur-[150px] rounded-full pointer-events-none" />

      <div className="relative z-10 max-w-[1440px] mx-auto p-6 md:p-12">
        {/* HERO SECTION */}
        <motion.header 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="mb-12 grid grid-cols-1 lg:grid-cols-2 gap-8 items-center"
        >
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-gradient-to-br from-cyan-500 via-blue-500 to-indigo-500 rounded-2xl flex items-center justify-center shadow-lg shadow-accent/20">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-white">MobileGuard AI</h1>
            </div>
            <p className="text-xl text-textSecondary max-w-xl">
              Advanced AI-Powered Mobile Threat Intelligence Platform
            </p>
            <p className="text-muted text-sm max-w-xl">
              Analyze Android applications using multi-stage AI security assessment.
            </p>
          </div>

          <div className="bg-card backdrop-blur-xl border border-white/5 rounded-2xl p-6 shadow-2xl flex flex-col gap-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted mb-2">System Status</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center bg-white/5 ${health.status === 'ok' ? 'text-success' : 'text-danger'}`}>
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs text-muted">API Health</div>
                  <div className="text-sm font-medium text-white">{health.status === 'ok' ? 'Online' : 'Offline'}</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-white/5 text-accent">
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs text-muted">Analysis Engine</div>
                  <div className="text-sm font-medium text-white">Active</div>
                </div>
              </div>
              <div className="flex items-center gap-3 col-span-2">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-white/5 text-warning">
                  <Clock className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs text-muted">Last System Scan</div>
                  <div className="text-sm font-medium text-white">{new Date().toLocaleTimeString()}</div>
                </div>
              </div>
            </div>
          </div>
        </motion.header>

        <main className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* Left Panel - 4 columns */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="lg:col-span-4 flex flex-col gap-8"
          >
            <UploadZone onUpload={handleUpload} disabled={isUploading} />
            <ProgressTracker events={events} error={error} isUploading={isUploading} />
          </motion.div>

          {/* Right Panel - 8 columns */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="lg:col-span-8 flex flex-col gap-8"
          >
            <AnimatePresence mode="wait">
              {result ? (
                <motion.div
                  key="results"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="flex flex-col gap-8"
                >
                  <ActionBanner action={result.score?.action} score={result.score?.composite_score} />
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <RiskGauge score={result.score?.composite_score} action={result.score?.action} />
                    <DimensionChart scores={result.score?.dimension_scores} />
                  </div>

                  {result.score?.shap_top_features && (
                    <ShapExplainer 
                      topFeatures={result.score.shap_top_features} 
                      explanation={result.score.shap_explanation} 
                    />
                  )}

                  {result.report && (
                    <ThreatReport report={result.report} />
                  )}
                </motion.div>
              ) : (
                <motion.div 
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="bg-card backdrop-blur-xl border border-white/5 border-dashed rounded-2xl h-64 flex flex-col items-center justify-center text-muted"
                >
                  <Activity className="w-12 h-12 mb-4 opacity-30" />
                  <p className="text-lg">Upload an APK to view threat intelligence analysis</p>
                </motion.div>
              )}
            </AnimatePresence>

            <AuditLog logs={logs} />
          </motion.div>

        </main>
      </div>
    </div>
  );
}

export default App;
