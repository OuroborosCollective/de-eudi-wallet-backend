import { apiFetch } from "../lib/api";
import React, { useEffect, useState } from 'react';
import { Activity, RefreshCw, Shield, Eye, EyeOff, ChevronDown, ChevronRight, Lock } from 'lucide-react';
import { maskString, maskSensitiveObject } from '../utils/maskSensitiveData';

export const LogViewer: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [redactSensitive, setRedactSensitive] = useState<boolean>(true);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/api/system/logs');
      const data = await res.json();
      if (data.logs) setLogs(data.logs);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedLogId(expandedLogId === id ? null : id);
  };

  return (
    <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 space-y-4 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-3">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-blue-400" />
          <h3 className="font-bold text-white text-base">Live Backend Activity Stream</h3>
          <span className="text-xs text-slate-500 font-mono">Auto-refresh (3s)</span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Sensitive Data Redaction Toggle */}
          <button
            onClick={() => setRedactSensitive(!redactSensitive)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
              redactSensitive
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
            title="Redacts JWTs, cryptographic keys, revocation codes, and PII before browser display"
          >
            {redactSensitive ? (
              <>
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>Mask PII & Keys: Active</span>
              </>
            ) : (
              <>
                <Eye className="w-3.5 h-3.5 text-amber-400" />
                <span>Raw Stream (Unmasked)</span>
              </>
            )}
          </button>

          <button
            onClick={fetchLogs}
            disabled={loading}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-blue-400' : ''}`} />
          </button>
        </div>
      </div>

      <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
        {logs.length === 0 ? (
          <div className="text-xs text-slate-500 italic text-center py-8">
            No live request traffic captured yet. Test API endpoints above to generate logs.
          </div>
        ) : (
          logs.map((log) => {
            const isSuccess = log.status >= 200 && log.status < 300;
            const isSecurity = log.service === 'SECURITY';
            const isExpanded = expandedLogId === log.id;

            // Apply sensitive masking utility
            const displayMessage = redactSensitive ? maskString(log.message) : log.message;
            const displayDetails = redactSensitive ? maskSensitiveObject(log.details) : log.details;
            const hasDetails = log.details && Object.keys(log.details).length > 0;

            return (
              <div
                key={log.id}
                className={`bg-slate-950 rounded-xl border transition ${
                  isSecurity
                    ? 'border-amber-500/40 bg-amber-950/10'
                    : 'border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div
                  onClick={() => hasDetails && toggleExpand(log.id)}
                  className={`p-2.5 flex items-center justify-between text-xs font-mono ${
                    hasDetails ? 'cursor-pointer select-none' : ''
                  }`}
                >
                  <div className="flex items-center space-x-3 overflow-hidden">
                    {hasDetails && (
                      <span className="text-slate-500">
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </span>
                    )}
                    <span
                      className={`px-2 py-0.5 text-[10px] font-bold rounded shrink-0 ${
                        isSuccess
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : log.status === 429
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      {log.status}
                    </span>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-bold rounded shrink-0 ${
                        isSecurity
                          ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                          : 'bg-blue-500/10 text-blue-400'
                      }`}
                    >
                      {log.service}
                    </span>
                    <span className="text-slate-300 font-semibold truncate">{displayMessage}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 shrink-0 ml-2 flex items-center gap-2">
                    {redactSensitive && (
                      <span className="text-[10px] text-emerald-400/80 bg-emerald-500/5 px-1.5 py-0.5 rounded border border-emerald-500/20 hidden sm:inline-flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5" /> Redacted
                      </span>
                    )}
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>

                {/* Expanded Details JSON viewer */}
                {isExpanded && hasDetails && (
                  <div className="px-3 pb-3 pt-1 border-t border-slate-900 font-mono text-[11px]">
                    <div className="bg-slate-900 p-3 rounded-lg text-slate-300 border border-slate-800 overflow-x-auto">
                      <div className="text-[10px] text-slate-500 mb-1 flex items-center justify-between">
                        <span>Payload & Diagnostics</span>
                        {redactSensitive && <span className="text-emerald-400">Keys & Nonces Redacted</span>}
                      </div>
                      <pre className="whitespace-pre-wrap">{JSON.stringify(displayDetails, null, 2)}</pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
