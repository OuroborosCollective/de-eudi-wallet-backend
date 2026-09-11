import { apiFetch } from "./lib/api";
import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { Overview } from './components/Overview';
import { WpbTester } from './components/WpbTester';
import { RwscaTester } from './components/RwscaTester';
import { MdvmTester } from './components/MdvmTester';
import { PnsTester } from './components/PnsTester';
import { StatusListTester } from './components/StatusListTester';
import { SecurityHardening } from './components/SecurityHardening';
import { LogViewer } from './components/LogViewer';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [statusData, setStatusData] = useState<any>(null);

  const fetchStatus = async () => {
    try {
      const res = await apiFetch('/api/system/status');
      const data = await res.json();
      setStatusData(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        systemStatus={statusData?.status || 'ONLINE'}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'overview' && (
          <Overview statusData={statusData} onRefresh={fetchStatus} />
        )}
        {activeTab === 'security' && <SecurityHardening />}
        {activeTab === 'wpb' && <WpbTester />}
        {activeTab === 'rwsca' && <RwscaTester />}
        {activeTab === 'mdvm' && <MdvmTester />}
        {activeTab === 'pns' && <PnsTester />}
        {activeTab === 'statuslist' && <StatusListTester />}

        {/* Global Live Activity Log Section */}
        <LogViewer />
      </main>

      <footer className="border-t border-slate-800 bg-slate-900/60 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4">
          German National EUDI Wallet Backend Architecture Migration • WPB | RWSCA | MDVM | PNS | Status Lists
        </div>
      </footer>
    </div>
  );
}
