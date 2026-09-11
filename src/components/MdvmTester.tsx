import { apiFetch } from "../lib/api";
import React, { useState } from 'react';
import { Smartphone, Play, RefreshCw, CheckCircle2 } from 'lucide-react';

export const MdvmTester: React.FC = () => {
  const [devicePlatform, setDevicePlatform] = useState<'ANDROID' | 'IOS'>('ANDROID');
  const [mdvmWiId, setMdvmWiId] = useState<string>('');
  const [mdvmToken, setMdvmToken] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [responseLog, setResponseLog] = useState<any>(null);

  const fetchChallenge = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/v1/mdvm/challenge', { method: 'POST' });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const registerDevice = async () => {
    setLoading(true);
    const endpoint = devicePlatform === 'ANDROID' ? '/v1/mdvm/android/register' : '/v1/mdvm/ios/register';
    const body = devicePlatform === 'ANDROID'
      ? {
          wi_mdvm_auth_pubk: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...',
          wi_device_class: { model: 'Pixel 8 Pro', os_version: 'Android 14', security_patch: '2026-08-01' },
          wi_android_key_attestation: ['MIICXzCCAgWgAwIBAgIBAjAKBggqhkjOPQQDAjAz...']
        }
      : {
          wi_mdvm_auth_pubk: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...',
          wi_device_class: { model: 'iPhone 15 Pro', os_version: 'iOS 18.0' },
          pap_devicecheck_attestation: 'base64-devicecheck-attestation',
          pap_devicecheck_assertion: 'base64-devicecheck-assertion'
        };

    try {
      const res = await apiFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Auth-Challenge': 'sample-mdvm-challenge'
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.mdvm_wi_id) setMdvmWiId(data.mdvm_wi_id);
      if (data.mdvm_token) setMdvmToken(data.mdvm_token);
    } catch (err: any) {
      setResponseLog({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const renewToken = async () => {
    setLoading(true);
    const endpoint = devicePlatform === 'ANDROID' ? '/v1/mdvm/android/renewal' : '/v1/mdvm/ios/renewal';
    const body = devicePlatform === 'ANDROID'
      ? {
          wi_device_class: { model: 'Pixel 8 Pro', os_version: 'Android 14' },
          wi_android_key_attestation: ['MIICXzCCAgWgAwIBAgIBAjAKBggqhkjOPQQDAjAz...']
        }
      : {
          wi_device_class: { model: 'iPhone 15 Pro', os_version: 'iOS 18.0' },
          pap_devicecheck_assertion: 'base64-devicecheck-assertion'
        };

    try {
      const res = await apiFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mdvm-Wi-Id': mdvmWiId || '00000000-0000-0000-0000-000000000001',
          'Auth-Challenge': 'sample-mdvm-challenge'
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setResponseLog({ status: res.status, data });
      if (data.mdvm_token) setMdvmToken(data.mdvm_token);
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
            <Smartphone className="w-6 h-6 text-cyan-400" /> Mobile Device Verification Management (MDVM)
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Verifies platform integrity using Android Key Attestation certificate chains or iOS Apple DeviceCheck attestations.
          </p>
        </div>

        <div className="flex bg-slate-800 p-1 rounded-xl border border-slate-700">
          <button
            onClick={() => setDevicePlatform('ANDROID')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              devicePlatform === 'ANDROID' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            Android Key Attestation
          </button>
          <button
            onClick={() => setDevicePlatform('IOS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              devicePlatform === 'IOS' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
            }`}
          >
            iOS DeviceCheck
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">1. MDVM Challenge</span>
            <button
              onClick={fetchChallenge}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Request Auth Challenge</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">
              2. Register {devicePlatform} Device
            </span>
            <p className="text-xs text-slate-300">
              Submits device class details and hardware attestation payloads to obtain a verified MDVM JWT token.
            </p>
            <button
              onClick={registerDevice}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Verify & Register Device</span>
            </button>
          </div>

          <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">
              3. Renew MDVM Token
            </span>
            <button
              onClick={renewToken}
              disabled={loading}
              className="w-full px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Renew Token</span>
            </button>
          </div>

          {mdvmWiId && (
            <div className="bg-slate-800/80 rounded-xl p-3 border border-slate-700 text-xs space-y-1">
              <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                <CheckCircle2 className="w-4 h-4" /> Device Registered & Integrity Verified
              </div>
              <div className="text-slate-400 font-mono">MDVM WI ID: {mdvmWiId}</div>
            </div>
          )}
        </div>

        <div className="bg-slate-900 rounded-xl p-4 border border-slate-800 flex flex-col justify-between min-h-[380px]">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">MDVM Response</span>
              {loading && <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />}
            </div>
            {responseLog ? (
              <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto max-h-[420px] whitespace-pre-wrap border border-slate-800">
                {JSON.stringify(responseLog, null, 2)}
              </pre>
            ) : (
              <div className="text-xs text-slate-500 italic py-12 text-center">
                Select platform and execute device attestation registration.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
