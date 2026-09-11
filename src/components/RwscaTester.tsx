import { apiFetch } from "../lib/api";
import React, { useState } from 'react';
import { Key, Play, RefreshCw } from 'lucide-react';

export const RwscaTester: React.FC = () => {
  const [challengeToken, setChallengeToken] = useState<string>('');
  const [rwscaAccountId, setRwscaAccountId] = useState<string>('');
  const [pinSessionToken, setPinSessionToken] = useState<string>('');
  const [wrappedKey, setWrappedKey] = useState<string>('');
  const [numberOfKeys, setNumberOfKeys] = useState<number>(2);

  const [loading, setLoading] = useState<boolean>(false);
  const [responseLog, setResponseLog] = useState<any>(null);

  const fetchChallenge = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/rwsca/challenge', { method: 'POST' });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.rwsca_auth_challenge) setChallengeToken(data.rwsca_auth_challenge);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const registerAccount = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/rwsca/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge',
          'Mdvm-Token': 'mock-mdvm-token'
        }
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.rwsca_account_id) setRwscaAccountId(data.rwsca_account_id);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const initPinAndStartSession = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/rwsca/initializePinAndStartPinSession', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge',
          'Mdvm-Token': 'mock-mdvm-token',
          'Rwsca-Account-Id': rwscaAccountId || '00000000-0000-0000-0000-000000000001'
        },
        body: JSON.stringify({
          wi_rwsca_pin_pubk: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'
        })
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.rwsca_pin_session_token) setPinSessionToken(data.rwsca_pin_session_token);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const createKeys = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/rwsca/createKeys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge',
          'Mdvm-Token': 'mock-mdvm-token',
          'Rwsca-Account-Id': rwscaAccountId || '00000000-0000-0000-0000-000000000001'
        },
        body: JSON.stringify({
          number_of_keys: numberOfKeys,
          pp_c_nonce: 'sample-issuer-nonce-b64'
        })
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.rwsca_wi_keys && data.rwsca_wi_keys.length > 0) {
        setWrappedKey(data.rwsca_wi_keys[0].rwsca_wi_wrapped_prvk);
      }
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const signData = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/rwsca/signData', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge',
          'Mdvm-Token': 'mock-mdvm-token',
          'Rwsca-Account-Id': rwscaAccountId || '00000000-0000-0000-0000-000000000001',
          'Rwsca-Pin-Session-Token': pinSessionToken || 'pin-sess-789'
        },
        body: JSON.stringify({
          rwsca_wi_wrapped_prvk: wrappedKey || 'sample-wrapped-key',
          wi_key_binding_data_hash: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        })
      });
      const data = await res.json();
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
            <Key className="w-6 h-6 text-indigo-400" /> Remote WSCA (RWSCA) Cryptographic API Tester
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Tests PIN session initialization, remote key generation (HSM wrapped keys), Wallet Trust Evidence (WTE) and key binding signature generation.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-indigo-400 uppercase tracking-wider">1. RWSCA Challenge</span>
            <button
              onClick={fetchChallenge}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Fetch RWSCA Challenge</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">2. Register RWSCA Account</span>
            <button
              onClick={registerAccount}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Register Account</span>
            </button>
            {rwscaAccountId && <div className="text-xs text-slate-400">Account ID: <span className="font-mono text-emerald-400">{rwscaAccountId}</span></div>}
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">3. Init PIN & Start Session</span>
            <button
              onClick={initPinAndStartSession}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Start PIN Session</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">4. Create Wrapped Keys</span>
              <div className="flex items-center space-x-2 text-xs">
                <span className="text-slate-400">Keys:</span>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={numberOfKeys}
                  onChange={(e) => setNumberOfKeys(parseInt(e.target.value) || 1)}
                  className="w-12 bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-center font-mono text-white text-xs"
                />
              </div>
            </div>
            <button
              onClick={createKeys}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Generate Wrapped Keys & WTE</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">5. Remote Sign Data</span>
            <button
              onClick={signData}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Sign Data Hash</span>
            </button>
          </div>
        </div>

        <div className="bg-slate-900 rounded-xl p-4 border border-slate-800 flex flex-col justify-between min-h-[400px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Response Output</span>
              {loading && <RefreshCw className="w-4 h-4 text-indigo-400 animate-spin" />}
            </div>
            {responseLog ? (
              <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-indigo-300 overflow-x-auto max-h-[450px] whitespace-pre-wrap border border-slate-800">
                {JSON.stringify(responseLog, null, 2)}
              </pre>
            ) : (
              <div className="text-xs text-slate-500 italic py-12 text-center">
                Execute RWSCA cryptographic commands to test output.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
