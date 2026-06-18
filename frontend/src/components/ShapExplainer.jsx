import React from 'react';
import { Brain, ArrowUpRight, ArrowDownRight } from 'lucide-react';
import { motion } from 'framer-motion';

export default function ShapExplainer({ topFeatures, explanation }) {
  if (!topFeatures || topFeatures.length === 0) return null;

  const data = topFeatures.map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value: parseFloat(value.toFixed(2))
  }));

  const maxAbsValue = Math.max(...data.map(d => Math.abs(d.value))) || 1;

  return (
    <div className="bg-card backdrop-blur-xl p-8 rounded-2xl border border-white/5 flex flex-col shadow-xl">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-indigo-500/20 rounded-lg">
          <Brain className="w-6 h-6 text-indigo-400" />
        </div>
        <div>
          <h3 className="font-bold text-lg text-white">AI Insights</h3>
          <p className="text-xs text-muted">Feature importance and model drivers</p>
        </div>
      </div>

      {explanation && (
        <div className="bg-white/5 border border-white/10 p-5 rounded-xl mb-8 relative overflow-hidden">
          <div className="absolute left-0 top-0 bottom-0 w-1 bg-indigo-500 rounded-l-xl"></div>
          <p className="text-sm text-textSecondary leading-relaxed">{explanation}</p>
        </div>
      )}

      <div className="flex flex-col gap-5">
        {data.map((item, idx) => {
          // Negative value usually pushes toward safe (BENIGN), Positive toward threat (MALWARE)
          const isNegative = item.value <= 0; 
          const widthPercent = (Math.abs(item.value) / maxAbsValue) * 100;
          const colorClass = isNegative 
            ? 'from-green-500 to-emerald-400 shadow-[0_0_10px_rgba(34,197,94,0.3)]' 
            : 'from-red-500 to-rose-400 shadow-[0_0_10px_rgba(239,68,68,0.3)]';
          const Icon = isNegative ? ArrowDownRight : ArrowUpRight;
          const iconColor = isNegative ? 'text-green-400' : 'text-red-400';

          return (
            <div key={item.name} className="flex flex-col gap-2 group">
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${iconColor}`} />
                  <span className="text-sm font-medium text-textSecondary group-hover:text-white transition-colors capitalize">{item.name}</span>
                </div>
                <span className={`text-xs font-bold ${iconColor}`}>{item.value > 0 ? '+' : ''}{item.value}</span>
              </div>
              <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden border border-white/5 flex">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.max(2, widthPercent)}%` }}
                  transition={{ duration: 1, delay: idx * 0.1, ease: "easeOut" }}
                  className={`h-full rounded-full bg-gradient-to-r ${colorClass}`}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
