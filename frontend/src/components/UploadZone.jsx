import React, { useCallback, useState } from 'react';
import { Upload, File, Hash, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function UploadZone({ onUpload, disabled }) {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState(null);
  const [hash, setHash] = useState(null);

  const computeHash = async (fileObj) => {
    const buffer = await fileObj.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const handleFile = useCallback(async (selectedFile) => {
    if (!selectedFile) return;
    if (!selectedFile.name.endsWith('.apk')) {
      alert("Only .apk files are allowed");
      return;
    }
    setFile(selectedFile);
    const fileHash = await computeHash(selectedFile);
    setHash(fileHash);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  }, [handleFile]);

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div className="w-full flex flex-col gap-6">
      <motion.div 
        onDragEnter={() => setDragActive(true)}
        onDragLeave={() => setDragActive(false)}
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        animate={{ 
          scale: dragActive ? 1.02 : 1,
          borderColor: dragActive ? '#3B82F6' : 'rgba(255,255,255,0.1)',
          backgroundColor: dragActive ? 'rgba(59,130,246,0.05)' : 'rgba(255,255,255,0.02)'
        }}
        transition={{ type: 'spring', stiffness: 300, damping: 20 }}
        className="relative w-full h-72 border-2 border-dashed rounded-2xl flex flex-col items-center justify-center p-6 backdrop-blur-xl transition-shadow"
        style={{
          boxShadow: dragActive ? '0 0 40px rgba(59,130,246,0.2)' : 'none'
        }}
      >
        <input 
          type="file" 
          accept=".apk"
          onChange={handleChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
          disabled={disabled}
        />
        
        <AnimatePresence mode="wait">
          {!file ? (
            <motion.div 
              key="empty"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="flex flex-col items-center pointer-events-none"
            >
              <div className="relative mb-6">
                <div className="absolute inset-0 bg-accent/20 blur-xl rounded-full animate-pulse-slow"></div>
                <div className="relative bg-card border border-white/10 w-20 h-20 rounded-2xl flex items-center justify-center shadow-2xl">
                  <Upload className="w-10 h-10 text-accent" />
                </div>
              </div>
              <p className="text-xl font-bold text-white mb-2">Upload Application Package</p>
              <p className="text-sm text-muted">Drag & drop APK here or click to browse</p>
            </motion.div>
          ) : (
            <motion.div 
              key="file"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex flex-col items-center gap-4 w-full max-w-md pointer-events-none z-20"
            >
              <div className="bg-secondary/80 backdrop-blur-md p-5 rounded-2xl w-full flex items-center gap-4 border border-white/10 shadow-xl">
                <div className="bg-accent/10 p-3 rounded-xl border border-accent/20">
                  <File className="w-8 h-8 text-accent" />
                </div>
                <div className="flex flex-col overflow-hidden flex-1">
                  <span className="font-semibold text-white truncate" title={file.name}>{file.name}</span>
                  <span className="text-sm text-muted">{(file.size / (1024 * 1024)).toFixed(2)} MB</span>
                </div>
                <ShieldCheck className="w-6 h-6 text-success opacity-80" />
              </div>
              
              {hash && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-[#050B14] p-3 rounded-xl w-full flex items-center gap-3 border border-white/5"
                >
                  <Hash className="w-4 h-4 text-muted shrink-0" />
                  <span className="text-xs text-muted font-mono truncate select-all" title={hash}>{hash}</span>
                </motion.div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <motion.button
        whileHover={!disabled && file ? { scale: 1.02 } : {}}
        whileTap={!disabled && file ? { scale: 0.98 } : {}}
        onClick={() => onUpload(file)}
        disabled={!file || disabled}
        className={`relative w-full py-4 rounded-xl font-bold text-lg transition-all flex justify-center items-center overflow-hidden
          ${!file || disabled ? 'bg-secondary text-muted cursor-not-allowed' : 'text-white shadow-lg shadow-accent/20'}
        `}
      >
        {(!file || disabled) ? null : (
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 opacity-90 hover:opacity-100 transition-opacity" />
        )}
        
        <div className="relative flex items-center gap-2">
          {disabled ? (
            <>
              <div className="w-5 h-5 border-2 border-t-transparent border-accent rounded-full animate-spin"></div>
              <span className="text-accent">Processing Analysis...</span>
            </>
          ) : (
            <span>Initiate AI Security Scan</span>
          )}
        </div>
      </motion.button>
    </div>
  );
}
