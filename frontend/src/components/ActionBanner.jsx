import React from 'react';
import { ShieldCheck, Eye, AlertTriangle, XOctagon, Target } from 'lucide-react';
import { motion } from 'framer-motion';

export default function ActionBanner({ action, score }) {
  if (!action) return null;

  const configs = {
    APPROVE: {
      gradient: 'from-green-500/20 via-emerald-500/10 to-transparent',
      borderColor: 'border-green-500/30',
      iconColor: 'text-green-500',
      icon: ShieldCheck,
      title: 'APPROVE',
      level: 'Low Risk',
      subtitle: 'Application appears safe for general use.',
      confidence: '98%'
    },
    MONITOR: {
      gradient: 'from-amber-500/20 via-yellow-500/10 to-transparent',
      borderColor: 'border-amber-500/30',
      iconColor: 'text-amber-500',
      icon: Eye,
      title: 'MONITOR',
      level: 'Moderate Risk',
      subtitle: 'Allow execution but monitor network activity.',
      confidence: '85%'
    },
    ESCALATE: {
      gradient: 'from-orange-500/20 via-red-500/10 to-transparent',
      borderColor: 'border-orange-500/30',
      iconColor: 'text-orange-500',
      icon: AlertTriangle,
      title: 'ESCALATE',
      level: 'High Risk',
      subtitle: 'Quarantine application pending manual analysis.',
      confidence: '92%'
    },
    BLOCK: {
      gradient: 'from-red-600/20 via-rose-500/10 to-transparent',
      borderColor: 'border-red-500/30',
      iconColor: 'text-red-500',
      icon: XOctagon,
      title: 'BLOCK',
      level: 'Critical Threat',
      subtitle: 'Critical threat. Block immediately and file CERT-In report.',
      confidence: '99%'
    }
  };

  const config = configs[action] || configs['APPROVE'];
  const Icon = config.icon;

  // Derive confidence roughly from score if needed, or use static for design
  const calculatedConfidence = score ? `${Math.min(99, Math.max(75, Math.abs(score - 50) * 1.5 + 50)).toFixed(1)}%` : config.confidence;

  return (
    <motion.div 
      initial={{ scale: 0.95, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', damping: 20, stiffness: 200 }}
      className={`relative w-full p-8 rounded-2xl border bg-card backdrop-blur-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 overflow-hidden ${config.borderColor}`}
    >
      {/* Background Gradient */}
      <div className={`absolute inset-0 bg-gradient-to-r ${config.gradient} pointer-events-none`} />

      <div className="relative flex items-center gap-6 z-10">
        <div className={`w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center shadow-2xl ${config.iconColor}`}>
          <Icon className="w-8 h-8" />
        </div>
        
        <div className="flex flex-col">
          <span className="text-xs font-bold uppercase tracking-widest text-muted mb-1">Recommended Action</span>
          <div className="flex items-center gap-3">
            <span className={`font-bold text-3xl tracking-tight ${config.iconColor}`}>{config.title}</span>
            <div className={`px-3 py-1 rounded-full text-xs font-bold border ${config.borderColor} ${config.iconColor} bg-white/5`}>
              {config.level}
            </div>
          </div>
          <span className="text-sm text-textSecondary mt-2 max-w-md">{config.subtitle}</span>
        </div>
      </div>

      <div className="relative z-10 flex items-center gap-8 md:border-l border-white/10 md:pl-8">
        <div className="flex flex-col">
          <span className="text-xs text-muted font-medium mb-1 flex items-center gap-1">
            <Target className="w-3 h-3" /> AI Confidence
          </span>
          <span className="text-2xl font-bold text-white">{calculatedConfidence}</span>
        </div>
      </div>
    </motion.div>
  );
}
