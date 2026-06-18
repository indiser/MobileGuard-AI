import React from 'react';
import { motion } from 'framer-motion';

export default function DimensionChart({ scores }) {
  if (!scores) return null;

  const data = [
    { name: 'Permissions', value: scores.permission_abuse || scores.permission_abuse_score || 0 },
    { name: 'Behavior', value: scores.behavioral_anomaly || scores.behavioral_anomaly_score || 0 },
    { name: 'Obfuscation', value: scores.obfuscation || scores.obfuscation_score || 0 },
    { name: 'ML/Static', value: scores.ml_malware || scores.ml_malware_score || 0 },
    { name: 'Trust', value: scores.developer_trust || scores.developer_trust_score || 0 },
    { name: 'AI Severity', value: scores.llm_severity || scores.llm_severity_score || 0 }
  ];

  const getColor = (val) => {
    if (val <= 25) return "from-green-500 to-emerald-400 shadow-[0_0_10px_rgba(34,197,94,0.3)]";
    if (val <= 50) return "from-amber-500 to-yellow-400 shadow-[0_0_10px_rgba(245,158,11,0.3)]";
    if (val <= 75) return "from-orange-500 to-amber-500 shadow-[0_0_10px_rgba(249,115,22,0.3)]";
    return "from-red-600 to-rose-400 shadow-[0_0_10px_rgba(239,68,68,0.3)]";
  };

  return (
    <div className="bg-card backdrop-blur-xl p-8 rounded-2xl border border-white/5 flex flex-col shadow-xl">
      <div className="mb-8">
        <h3 className="font-bold text-lg text-white">Risk Dimensions</h3>
        <p className="text-xs text-muted">Vectorized analysis breakdown</p>
      </div>
      
      <div className="flex flex-col gap-5 justify-center flex-1">
        {data.map((item, idx) => (
          <div key={item.name} className="flex flex-col gap-2 group">
            <div className="flex justify-between items-center">
              <span className="text-sm font-medium text-textSecondary group-hover:text-white transition-colors">{item.name}</span>
              <span className="text-xs font-bold text-white/50">{Math.round(item.value)} / 100</span>
            </div>
            <div className="w-full h-2.5 bg-black/40 rounded-full overflow-hidden border border-white/5 relative">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${Math.max(1, item.value)}%` }}
                transition={{ duration: 1.2, delay: idx * 0.1, ease: "easeOut" }}
                className={`absolute top-0 left-0 h-full rounded-full bg-gradient-to-r ${getColor(item.value)}`}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
