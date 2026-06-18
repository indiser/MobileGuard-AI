import React, { useState } from 'react';
import { Download, Search, Filter, ChevronLeft, ChevronRight, List } from 'lucide-react';
import { motion } from 'framer-motion';

function exportCSV(logs) {
  const headers = ['Timestamp', 'Filename', 'Score', 'Action', 'Duration (ms)'];
  const rows = logs.map(log => [
    log.timestamp || log.analyzed_at || '',
    log.filename || '',
    log.score ?? log.composite_score ?? 0,
    log.action || '',
    log.duration ?? log.pipeline_duration_ms ?? ''
  ]);

  const escape = (val) => `"${String(val).replace(/"/g, '""')}"`;
  const csv = [headers, ...rows].map(row => row.map(escape).join(',')).join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `mobileguard_audit_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AuditLog({ logs }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;

  if (!logs || logs.length === 0) return null;

  const filteredLogs = logs.filter(log => 
    (log.filename || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (log.action || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / itemsPerPage));
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedLogs = filteredLogs.slice(startIndex, startIndex + itemsPerPage);

  const handlePrev = () => setCurrentPage(p => Math.max(1, p - 1));
  const handleNext = () => setCurrentPage(p => Math.min(totalPages, p + 1));

  return (
    <div className="bg-card backdrop-blur-xl rounded-2xl border border-white/5 flex flex-col shadow-xl overflow-hidden mt-8">
      {/* Header */}
      <div className="p-6 border-b border-white/5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-white/[0.02]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/20 rounded-lg">
            <List className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h3 className="font-bold text-lg text-white">Analysis Audit Log</h3>
            <p className="text-xs text-muted">Historical security assessments</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input 
              type="text" 
              placeholder="Search files or actions..." 
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              className="w-full bg-black/40 border border-white/10 rounded-xl py-2 pl-9 pr-4 text-sm text-white placeholder:text-muted focus:outline-none focus:border-accent transition-colors"
            />
          </div>
          <button
            onClick={() => exportCSV(logs)}
            className="flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 border border-white/5 rounded-xl transition-all text-sm font-medium whitespace-nowrap"
          >
            <Download className="w-4 h-4" /> Export
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto w-full">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-muted uppercase tracking-wider bg-black/20 border-b border-white/5 sticky top-0 z-10">
            <tr>
              <th className="px-6 py-4 font-semibold">Timestamp</th>
              <th className="px-6 py-4 font-semibold">Filename</th>
              <th className="px-6 py-4 font-semibold">Score</th>
              <th className="px-6 py-4 font-semibold">Action</th>
              <th className="px-6 py-4 font-semibold">Duration (ms)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 relative">
            {paginatedLogs.length > 0 ? paginatedLogs.map((log, i) => (
              <motion.tr 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: i * 0.05 }}
                key={startIndex + i} 
                className="hover:bg-white/[0.02] transition-colors cursor-default group"
              >
                <td className="px-6 py-4 whitespace-nowrap text-textSecondary font-medium">
                  {new Date(log.timestamp || log.analyzed_at).toLocaleString()}
                </td>
                <td className="px-6 py-4 truncate max-w-[200px] text-white font-medium group-hover:text-accent transition-colors" title={log.filename}>
                  {log.filename}
                </td>
                <td className="px-6 py-4 font-mono text-muted">
                  <span className="text-white">{log.score || log.composite_score || 0}</span>/100
                </td>
                <td className="px-6 py-4">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold border
                    ${log.action === 'BLOCK' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                      log.action === 'ESCALATE' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' : 
                      log.action === 'MONITOR' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' : 
                      'bg-green-500/10 border-green-500/20 text-green-400'}`}>
                    {log.action}
                  </span>
                </td>
                <td className="px-6 py-4 text-muted font-mono">
                  {log.duration || log.pipeline_duration_ms || '-'}
                </td>
              </motion.tr>
            )) : (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-muted">
                  No analysis records found matching your search.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="p-4 border-t border-white/5 flex justify-between items-center bg-black/20 text-sm">
        <span className="text-muted">
          Showing <span className="text-white font-medium">{Math.min(startIndex + 1, filteredLogs.length)}</span> to <span className="text-white font-medium">{Math.min(startIndex + itemsPerPage, filteredLogs.length)}</span> of <span className="text-white font-medium">{filteredLogs.length}</span> records
        </span>
        <div className="flex items-center gap-2">
          <button 
            onClick={handlePrev} 
            disabled={currentPage === 1}
            className="p-1.5 rounded-lg border border-white/10 hover:bg-white/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button 
            onClick={handleNext} 
            disabled={currentPage === totalPages || totalPages === 0}
            className="p-1.5 rounded-lg border border-white/10 hover:bg-white/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
