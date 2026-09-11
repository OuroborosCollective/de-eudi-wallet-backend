import { apiFetch } from "../lib/api";
import React, { useState } from 'react';
import { Bell, Play, RefreshCw, Trash2 } from 'lucide-react';

export const PnsTester: React.FC = () => {
  const [mppToken, setMppToken] = useState<string>('mpp_fcm_token_sample_891273918273');
  const [loading, setLoading] = useState<boolean>(false);
  const [responseLog, setResponseLog] = useState<any>(null);

  const fetchChallenge = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/pns/challenge', { method: 'POST' });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const registerPushToken = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/pns/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': 'sample-pns-challenge',
          'Mdvm-Token': 'mock-mdvm-token'
        },
        body: JSON.stringify({ mpp_registration_token: mppToken })
      });
      const text = await res.text();
      const data = text ? JSON.parse(text) : { message: '204 No Content - Push Token Registered Successfully' };
      setResponseLog({ status: res.status, data });
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const deletePushToken = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/pns/delete', {
        method: 'DELETE',
        headers: {
          'Auth-Challenge': 'sample-pns-challenge',
          'Mdvm-Token': 'mock-mdvm-token'
        }
      });
      const text = await res.text();
      const data = text ? JSON.parse(text) : { message: '204 No Content - Registration Deleted' };
      setResponseLog({ status: res.status, data });
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Bell className="w-6 h-6 text-pink-400" /> Push Notifications Service (PNS)
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Registers Mobile Platform Provider (MPP / FCM) push tokens for receiving instant revocation and status update notifications.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-pink-400 uppercase tracking-wider">1. PNS Challenge</span>
            <button
              onClick={fetchChallenge}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-pink-600 hover:bg-pink-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Request Challenge</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">2. Register Push Token</span>
            <div className="space-y-2">
              <label className="text-[11px] font-medium text-slate-400">MPP Registration Token:</label>
              <input
                type="text"
                value={mppToken}
                onChange={(e) => setMppToken(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
              />
            </div>
            <button
              onClick={registerPushToken}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Register Token</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-rose-400 uppercase tracking-wider">3. Delete Registration</span>
            <button
              onClick={deletePushToken}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Delete Push Registration</span>
            </button>
          </div>
        </div>

        <div className="bg-slate-900 rounded-xl p-4 border border-slate-800 flex flex-col justify-between min-h-[350px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">PNS Response Log</span>
              {loading && <RefreshCw className="w-4 h-4 text-pink-400 animate-spin" />}
            </div>
            {responseLog ? (
              <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-pink-300 overflow-x-auto max-h-[380px] whitespace-pre-wrap border border-slate-800">
                {JSON.stringify(responseLog, null, 2)}
              </pre>
            ) : (
              <div className="text-xs text-slate-500 italic py-12 text-center">
                Perform push registration operations above.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
