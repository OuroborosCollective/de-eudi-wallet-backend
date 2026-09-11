import { apiFetch } from "../lib/api";
import React, { useState } from 'react';
import { Shield, Play, Copy, Check, RefreshCw } from 'lucide-react';

export const WpbTester: React.FC = () => {
  const [challengeToken, setChallengeToken] = useState<string>('');
  const [mdvmToken, setMdvmToken] = useState<string>('mdvm-t-e123');
  const [registeredAccountId, setRegisteredAccountId] = useState<string>('');
  const [revocationCode, setRevocationCode] = useState<string>('');
  const [clientInstanceId, setClientInstanceId] = useState<string>('');
  const [attestationJwt, setAttestationJwt] = useState<string>('');

  const [loading, setLoading] = useState<boolean>(false);
  const [responseLog, setResponseLog] = useState<any>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchChallenge = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/wpb/challenge', { method: 'POST' });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.wpb_auth_challenge) {
        setChallengeToken(data.wpb_auth_challenge);
      }
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const registerAccount = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/wpb/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge-jwt',
          'Mdvm-Token': mdvmToken
        },
        body: JSON.stringify({
          pubKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE123...'
        })
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.wpb_wi_id) setRegisteredAccountId(data.wpb_wi_id);
      if (data.wpb_wi_revocation_code) setRevocationCode(data.wpb_wi_revocation_code);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const requestAttestation = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/wpb/attestation', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': challengeToken || 'sample-challenge-jwt',
          'Mdvm-Token': mdvmToken,
          'Wpb-Wi-Id': registeredAccountId || '00000000-0000-0000-0000-000000000001'
        },
        body: JSON.stringify({
          wi_wia_pubk: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...',
          wpb_client_instance_id: clientInstanceId || null
        })
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.wpb_wia) setAttestationJwt(data.wpb_wia);
      if (data.wpb_client_instance_id) setClientInstanceId(data.wpb_client_instance_id);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const revokeInstance = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/wpb/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wpb_wi_revocation_code: revocationCode || 'rev_bech32_sample'
        })
      });
      const text = await res.text();
      let data = text ? JSON.parse(text) : { message: '202 Accepted (Revocation Published)' };
      setResponseLog({ status: res.status, data });
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" /> Wallet Provider Backend (WPB) API Tester
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Tests authentication challenges, Wallet Instance registration, Wallet Instance Attestation (WIA) issuing, and revocation.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Controls & Endpoints */}
        <div className="space-y-4">
          {/* Step 1: Challenge */}
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">Step 1: Challenge</span>
              <span className="text-xs font-mono text-slate-400">POST /v1/wpb/challenge</span>
            </div>
            <p className="text-xs text-slate-300">Generate an authentication challenge JWT for WPB registration or attestation requests.</p>
            <button
              onClick={fetchChallenge}
              disabled={loading}
              className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Fetch Challenge JWT</span>
            </button>
            {challengeToken && (
              <div className="bg-slate-900 rounded-lg p-2.5 text-xs font-mono text-slate-300 break-all border border-slate-800 flex justify-between items-start gap-2">
                <span className="line-clamp-2">{challengeToken}</span>
                <button onClick={() => copyToClipboard(challengeToken)} className="text-slate-400 hover:text-white">
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            )}
          </div>

          {/* Step 2: Register */}
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Step 2: Register Account</span>
              <span className="text-xs font-mono text-slate-400">POST /v1/wpb/register</span>
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-medium text-slate-400">MDVM Token Header:</label>
              <input
                type="text"
                value={mdvmToken}
                onChange={(e) => setMdvmToken(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
              />
            </div>
            <button
              onClick={registerAccount}
              disabled={loading}
              className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Register WPB Account</span>
            </button>
            {registeredAccountId && (
              <div className="space-y-1 text-xs">
                <div className="text-slate-400">WPB Account ID: <span className="text-emerald-400 font-mono font-semibold">{registeredAccountId}</span></div>
                <div className="text-slate-400">Revocation Code: <span className="text-amber-400 font-mono font-semibold">{revocationCode}</span></div>
              </div>
            )}
          </div>

          {/* Step 3: Issue Attestation */}
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">Step 3: Issue Attestation (WIA)</span>
              <span className="text-xs font-mono text-slate-400">POST /v1/wpb/attestation</span>
            </div>
            <button
              onClick={requestAttestation}
              disabled={loading}
              className="px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Request WIA Attestation JWT</span>
            </button>
          </div>

          {/* Step 4: Revoke */}
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">Step 4: Revoke Wallet Instance</span>
              <span className="text-xs font-mono text-slate-400">POST /v1/wpb/revoke</span>
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-medium text-slate-400">Revocation Code:</label>
              <input
                type="text"
                value={revocationCode}
                onChange={(e) => setRevocationCode(e.target.value)}
                placeholder="rev_bech32_..."
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono"
              />
            </div>
            <button
              onClick={revokeInstance}
              disabled={loading}
              className="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Publish Revocation Event</span>
            </button>
          </div>
        </div>

        {/* Live Response Panel */}
        <div className="bg-slate-900 rounded-xl p-4 border border-slate-800 flex flex-col justify-between h-full min-h-[400px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Response Inspector</span>
              {loading && <RefreshCw className="w-4 h-4 text-blue-400 animate-spin" />}
            </div>
            {responseLog ? (
              <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto max-h-[420px] whitespace-pre-wrap border border-slate-800">
                {JSON.stringify(responseLog, null, 2)}
              </pre>
            ) : (
              <div className="text-xs text-slate-500 italic py-12 text-center">
                Execute an operation above to inspect the API request/response.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
