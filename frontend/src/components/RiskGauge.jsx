import React, { useEffect, useState } from 'react';
import { motion, animate } from 'framer-motion';

export default function RiskGauge({ score = 0, action }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const controls = animate(0, score, {
      duration: 1.5,
      ease: "easeOut",
      onUpdate: (v) => setAnimatedScore(Math.round(v))
    });
    return () => controls.stop();
  }, [score]);

  // Circumference for a circle of radius 80 = 2 * PI * 80 ~= 502.6
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  // Let's create a gauge that goes from 210 degrees to -30 degrees (240 degree sweep)
  // Which is 2/3 of a full circle.
  const sweepAngle = 240;
  const sweepFraction = sweepAngle / 360;
  const strokeDasharray = `${circumference * sweepFraction} ${circumference}`;
  const strokeDashoffset = (circumference * sweepFraction) - ((score / 100) * (circumference * sweepFraction));

  const getColor = (s) => {
    if (s <= 25) return "#22c55e"; // success
    if (s <= 50) return "#f59e0b"; // warning
    if (s <= 75) return "#f97316"; // orange
    return "#ef4444"; // danger
  };

  const getLabel = (s) => {
    if (s <= 25) return "LOW RISK";
    if (s <= 50) return "MODERATE";
    if (s <= 75) return "ELEVATED";
    return "CRITICAL";
  };

  const color = getColor(score);

  return (
    <div className="bg-card backdrop-blur-xl p-8 rounded-2xl border border-white/5 flex flex-col items-center justify-center relative shadow-xl">
      <div className="absolute top-6 left-6">
        <h3 className="font-bold text-lg text-white">Threat Severity</h3>
        <p className="text-xs text-muted">AI computed risk index</p>
      </div>

      <div className="relative flex items-center justify-center w-64 h-64 mt-12">
        {/* Background glow */}
        <div 
          className="absolute inset-0 rounded-full blur-[60px] opacity-20"
          style={{ backgroundColor: color }}
        />

        {/* SVG Circle */}
        <svg className="w-full h-full drop-shadow-2xl" viewBox="0 0 200 200">
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            transform="rotate(150 100 100)"
          />
          <motion.circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke={color}
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            initial={{ strokeDashoffset: (circumference * sweepFraction) }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.5, ease: "easeOut" }}
            transform="rotate(150 100 100)"
            style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
          />
        </svg>

        {/* Score Display inside circle */}
        <div className="absolute inset-0 flex flex-col items-center justify-center mt-4">
          <motion.span 
            className="text-6xl font-black tracking-tighter"
            style={{ color }}
          >
            {animatedScore}
          </motion.span>
          <span className="text-sm font-bold uppercase tracking-widest mt-1" style={{ color }}>
            {getLabel(animatedScore)}
          </span>
        </div>
      </div>
    </div>
  );
}
