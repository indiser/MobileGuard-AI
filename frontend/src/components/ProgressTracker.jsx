import React from 'react';
import { CheckCircle2, XCircle, Loader2, Circle, AlertCircle, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const STAGES = [
  { id: 'static_analysis', label: 'Static Analysis', desc: 'Decompiling and extracting manifest' },
  { id: 'dynamic_analysis', label: 'Sandbox Execution', desc: 'Running in secure environment' },
  { id: 'llm_analysis', label: 'AI Threat Assessment', desc: 'Evaluating behaviors via LLM' },
  { id: 'risk_scoring', label: 'Risk Scoring', desc: 'Computing threat severity' },
  { id: 'report_generation', label: 'Report Generation', desc: 'Compiling final intelligence' }
];

export default function ProgressTracker({ events, error, isUploading }) {
  if (events.length === 0 && !error && !isUploading) return null;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-card backdrop-blur-xl p-6 rounded-2xl border border-white/5 flex flex-col gap-6 shadow-xl relative overflow-hidden"
    >
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 opacity-50"></div>
      
      <div className="flex items-center gap-3 border-b border-white/5 pb-4">
        <div className="w-10 h-10 rounded-xl bg-accent/10 flex items-center justify-center text-accent">
          {error ? <AlertCircle className="w-5 h-5 text-danger" /> : <Activity className="w-5 h-5 animate-pulse" />}
        </div>
        <h3 className="font-bold text-lg text-white">AI Analysis Pipeline</h3>
      </div>
      
      <div className="flex flex-col relative pl-2 mt-2">
        {/* Timeline Line */}
        <div className="absolute left-[19px] top-6 bottom-10 w-px bg-white/10" />

        {STAGES.map((stage, idx) => {
          const eventIndex = events.findIndex(e => e.stage === stage.id);
          const hasPassed = eventIndex !== -1;
          const event = events[eventIndex];
          
          const isComplete = events.some(e => e.stage === 'complete') || 
                             (eventIndex !== -1 && eventIndex < events.length - 1);
          
          const isRunning = event && event.status === 'running' && !isComplete && !error;
          const isError = error && event && event.status === 'running';

          let icon = <Circle className="w-3 h-3 text-white/20" />;
          let textClass = "text-muted";
          let descClass = "text-white/20";
          let containerClass = "opacity-50";

          if (isComplete) {
            icon = <CheckCircle2 className="w-6 h-6 text-success" fill="currentColor" />;
            textClass = "text-white font-medium";
            descClass = "text-muted";
            containerClass = "opacity-100";
          } else if (isRunning) {
            icon = <div className="w-4 h-4 rounded-full bg-accent shadow-[0_0_15px_rgba(59,130,246,0.8)]" />;
            textClass = "text-accent font-bold";
            descClass = "text-accent/80";
            containerClass = "opacity-100 scale-[1.02] origin-left transition-transform";
          } else if (isError) {
            icon = <XCircle className="w-6 h-6 text-danger" fill="currentColor" />;
            textClass = "text-danger font-bold";
            descClass = "text-danger/80";
            containerClass = "opacity-100";
          } else if (hasPassed) {
            icon = <CheckCircle2 className="w-6 h-6 text-success" fill="currentColor" />;
            textClass = "text-white font-medium";
            descClass = "text-muted";
            containerClass = "opacity-100";
          }

          return (
            <div key={stage.id} className={`flex items-start gap-6 relative py-4 ${containerClass}`}>
              <div className="flex items-center justify-center w-6 h-6 mt-1 bg-background rounded-full z-10 border-[6px] border-background">
                {icon}
              </div>
              <div className="flex flex-col z-20">
                <span className={`text-[15px] tracking-wide ${textClass}`}>{stage.label}</span>
                <span className={`text-xs mt-1 ${descClass}`}>{stage.desc}</span>
              </div>
              
              {isRunning && (
                <motion.div 
                  layoutId="activeStage"
                  className="absolute left-8 -right-4 top-2 bottom-2 bg-accent/5 rounded-xl border border-accent/10"
                />
              )}
            </div>
          );
        })}
      </div>
      
      <AnimatePresence>
        {error && (
          <motion.div 
            initial={{ opacity: 0, height: 0, marginTop: 0 }}
            animate={{ opacity: 1, height: 'auto', marginTop: 16 }}
            exit={{ opacity: 0, height: 0, marginTop: 0 }}
            className="p-4 bg-danger/10 border border-danger/20 rounded-xl text-danger text-sm flex gap-3 items-start overflow-hidden"
          >
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
            <p className="leading-relaxed">{error}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
