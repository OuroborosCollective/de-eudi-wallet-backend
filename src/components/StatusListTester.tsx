import { apiFetch } from "../lib/api";
import React, { useState } from 'react';
import { FileText, Play, RefreshCw, ExternalLink } from 'lucide-react';

export const StatusListTester: React.FC = () => {
  const [segment, setSegment] = useState<string>('eudi');
  const [poolId, setPoolId] = useState<string>('wpb-wia');
  const [listId, setListId] = useState<string>('00000000-0000-0000-0000-000000000001');

  const [loading, setLoading] = useState<boolean>(false);
  const [statusListJwt, setStatusListJwt] = useState<string | null>(null);
  const [aggregationData, setAggregationData] = useState<any>(null);
  const [headers, setHeaders] = useState<any>(null);

  const fetchStatusList = async () => {
    setLoading(true);
    try {
      const res = await apiFetch(`/status-lists/${segment}/${poolId}/${listId}`, {
        headers: {
          'Accept': 'application/statuslist+jwt'
        }
      });
      const jwt = await res.text();
      setStatusListJwt(jwt);
      setHeaders({
        status: res.status,
        contentType: res.headers.get('content-type'),
        etag: res.headers.get('etag'),
        cacheControl: res.headers.get('cache-control')
      });
    } catch (err: any) {
      setStatusListJwt(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const fetchAggregation = async () => {
    setLoading(true);
    try {
      const res = await apiFetch(`/status-lists/${segment}/${poolId}/aggregation`);
      const data = await res.json();
      setAggregationData(data);
    } catch (err: any) {
      setAggregationData({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-emerald-400" /> Token Status Lists API
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Public unauthenticated read interface for Status List Tokens (RFC / OID4VCI statuslist+jwt format). Consumed by PID Providers & Verifiers.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Status List Parameters</span>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Segment:</label>
                <input
                  type="text"
                  value={segment}
                  onChange={(e) => setSegment(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Pool ID:</label>
                <input
                  type="text"
                  value={poolId}
                  onChange={(e) => setPoolId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">List UUID:</label>
                <input
                  type="text"
                  value={listId}
                  onChange={(e) => setListId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-white font-mono"
                />
              </div>
            </div>

            <div className="flex gap-2 pt-2">
              <button
                onClick={fetchStatusList}
                disabled={loading}
                className="flex-1 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Fetch Status List JWT</span>
              </button>
              <button
                onClick={fetchAggregation}
                disabled={loading}
                className="flex-1 px-3.5 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Get Aggregation URIs</span>
              </button>
            </div>
          </div>

          {headers && (
            <div className="bg-slate-800/80 rounded-xl p-4 border border-slate-700 space-y-2 text-xs">
              <span className="font-bold text-slate-300 uppercase tracking-wider block mb-1">Response Headers</span>
              <div className="text-slate-400">HTTP Status: <span className="text-emerald-400 font-mono font-bold">{headers.status}</span></div>
              <div className="text-slate-400">Content-Type: <span className="text-slate-200 font-mono">{headers.contentType}</span></div>
              <div className="text-slate-400">ETag: <span className="text-amber-400 font-mono">{headers.etag}</span></div>
              <div className="text-slate-400">Cache-Control: <span className="text-slate-200 font-mono">{headers.cacheControl}</span></div>
            </div>
          )}
        </div>

        <div className="bg-slate-900 rounded-xl p-4 border border-slate-800 flex flex-col justify-between min-h-[350px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Status List JWT / Payload</span>
              {loading && <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />}
            </div>

            {statusListJwt && (
              <div className="space-y-3">
                <div className="text-[11px] font-semibold text-emerald-400">Raw statuslist+jwt token:</div>
                <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto max-h-[160px] break-all border border-slate-800">
                  {statusListJwt}
                </pre>
              </div>
            )}

            {aggregationData && (
              <div className="space-y-2 mt-4">
                <div className="text-[11px] font-semibold text-blue-400">Pool Aggregation URIs:</div>
                <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-blue-300 overflow-x-auto max-h-[160px] border border-slate-800">
                  {JSON.stringify(aggregationData, null, 2)}
                </pre>
              </div>
            )}

            {!statusListJwt && !aggregationData && (
              <div className="text-xs text-slate-500 italic py-12 text-center">
                Click above to fetch status list JWT tokens or aggregation endpoints.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
