import React from 'react';
import { Shield, Key, Smartphone, Bell, FileText, CheckCircle2, Cpu, Server, Activity, ShieldCheck, Lock } from 'lucide-react';

interface OverviewProps {
  statusData: any;
  onRefresh: () => void;
}

export const Overview: React.FC<OverviewProps> = ({ statusData, onRefresh }) => {
  const counts = statusData?.counts || {};
  const metrics = statusData?.metrics || {};

  const services = [
    {
      name: 'Cyber-Hardened Core',
      desc: 'Active Helmet security headers, constant-time comparisons, anti-replay nonces, and multi-tier rate limiting.',
      icon: ShieldCheck,
      color: 'from-blue-600 to-indigo-700',
      countLabel: 'Blocked Violations',
      count: metrics.securityViolationsBlocked ?? 0,
      metricLabel: 'Defense Shields',
      metric: '6 Active',
    },
    {
      name: 'WPB (Wallet Provider Backend)',
      desc: 'Handles Wallet Instance Attestations (WIA), account registration & revocation workflows.',
      icon: Shield,
      color: 'from-blue-500 to-indigo-600',
      countLabel: 'Active Accounts',
      count: counts.wpbAccounts ?? 0,
      metricLabel: 'Attestations Issued',
      metric: metrics.attestationsIssued ?? 0,
    },
    {
      name: 'RWSCA (Remote WSCA)',
      desc: 'Remote Wallet Secure Cryptographic Application for PIN sessions, remote signing & WTE evidence.',
      icon: Key,
      color: 'from-indigo-500 to-purple-600',
      countLabel: 'Key Containers',
      count: counts.rwscaAccounts ?? 0,
      metricLabel: 'Data Signatures',
      metric: metrics.signaturesGenerated ?? 0,
    },
    {
      name: 'MDVM (Device Verification)',
      desc: 'Mobile Device Verification Management for Android Key Attestation & iOS Apple DeviceCheck.',
      icon: Smartphone,
      color: 'from-cyan-500 to-blue-600',
      countLabel: 'Verified Devices',
      count: counts.mdvmAccounts ?? 0,
      metricLabel: 'Tokens Issued',
      metric: metrics.mdvmTokensCreated ?? 0,
    },
    {
      name: 'PNS (Push Notification Service)',
      desc: 'Dispatches instant push alerts & revocation events to registered Mobile Platform Provider (MPP) tokens.',
      icon: Bell,
      color: 'from-purple-500 to-pink-600',
      countLabel: 'Active Registrations',
      count: counts.pnsRegistrations ?? 0,
      metricLabel: 'Revocations Dispatched',
      metric: metrics.revocationsProcessed ?? 0,
    },
    {
      name: 'Status Lists',
      desc: 'Public unauthenticated Status List Token allocation, RFC/OID4VCI status token serving and caching.',
      icon: FileText,
      color: 'from-emerald-500 to-teal-600',
      countLabel: 'Status Lists Allocated',
      count: counts.statusLists ?? 0,
      metricLabel: 'Total API Requests',
      metric: metrics.totalRequests ?? 0,
    },
  ];

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-800 via-slate-800/90 to-slate-900 rounded-2xl p-6 border border-slate-700/60 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center space-x-2">
              <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> All Services Operational
              </span>
              <span className="text-xs text-slate-400">German Architecture Spec Compliance v1.0</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">German National EUDI Wallet Infrastructure</h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              Unified server deployment providing cryptographic attestation, hardware integrity checks, remote signature generation, push revocation notifications, and status list serving for the German EUDI Wallet ecosystem.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={onRefresh}
              className="px-4 py-2.5 bg-slate-700 hover:bg-slate-600 text-white rounded-xl text-sm font-medium transition flex items-center justify-center space-x-2 border border-slate-600"
            >
              <Activity className="w-4 h-4 text-blue-400" />
              <span>Refresh Metrics</span>
            </button>
          </div>
        </div>
      </div>

      {/* Quick Metrics Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
          <div className="text-xs font-medium text-slate-400">Total API Operations</div>
          <div className="text-2xl font-bold text-white mt-1">{metrics.totalRequests ?? 0}</div>
          <div className="text-[11px] text-blue-400 mt-1 flex items-center gap-1">
            <Server className="w-3 h-3" /> Live traffic logged
          </div>
        </div>
        <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
          <div className="text-xs font-medium text-slate-400">WIA Attestations Issued</div>
          <div className="text-2xl font-bold text-white mt-1">{metrics.attestationsIssued ?? 0}</div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
            <Shield className="w-3 h-3" /> Signed JWTs
          </div>
        </div>
        <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
          <div className="text-xs font-medium text-slate-400">Remote Signatures</div>
          <div className="text-2xl font-bold text-white mt-1">{metrics.signaturesGenerated ?? 0}</div>
          <div className="text-[11px] text-purple-400 mt-1 flex items-center gap-1">
            <Key className="w-3 h-3" /> HSM Key Bindings
          </div>
        </div>
        <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
          <div className="text-xs font-medium text-slate-400">MDVM Devices</div>
          <div className="text-2xl font-bold text-white mt-1">{counts.mdvmAccounts ?? 0}</div>
          <div className="text-[11px] text-cyan-400 mt-1 flex items-center gap-1">
            <Cpu className="w-3 h-3" /> Attested Android/iOS
          </div>
        </div>
      </div>

      {/* Architecture Modules Breakdown */}
      <div>
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-blue-400" /> System Component Architecture
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {services.map((srv) => {
            const Icon = srv.icon;
            return (
              <div
                key={srv.name}
                className="bg-slate-800/50 rounded-2xl p-5 border border-slate-700/60 hover:border-slate-600 transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center space-x-3 mb-3">
                    <div className={`p-2.5 rounded-xl bg-gradient-to-tr ${srv.color} text-white shadow-md`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <h4 className="font-semibold text-white text-base leading-tight">{srv.name}</h4>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed mb-4">{srv.desc}</p>
                </div>

                <div className="pt-3 border-t border-slate-700/50 flex justify-between items-center text-xs">
                  <div>
                    <span className="text-slate-400">{srv.countLabel}:</span>{' '}
                    <span className="font-bold text-white">{srv.count}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">{srv.metricLabel}:</span>{' '}
                    <span className="font-bold text-blue-400">{srv.metric}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
