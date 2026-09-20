import React, { useState, useEffect } from 'react';
import { ShieldAlert, Activity, Users, AlertTriangle, Search, RotateCw, Wifi, Layers, Zap, Database, ShieldX, ArrowRight, X } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [connected, setConnected] = useState(false);
  const [pulse, setPulse] = useState({ mbps: 0, pps: 0, fps: 0, total_flows: 0, total_alerts: 0 });
  const [alerts, setAlerts] = useState([]);
  const [talkers, setTalkers] = useState([]);
  const [flows, setFlows] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Filters
  const [flowFilters, setFlowFilters] = useState({ src: '', dst: '', port: '' });
  const [alertFilters, setAlertFilters] = useState({ severity: '', category: '' });

  useEffect(() => {
    // 1. WebSocket Live Stream
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.hostname}:8000/ws/stream`;
    let ws = null;

    function connect() {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'NETWORK_PULSE') {
            setPulse(msg.data);
          } else if (msg.type === 'SECURITY_ALERT') {
            setAlerts((prev) => [msg.data, ...prev]);
          }
        } catch (e) {}
      };
    }

    connect();
    fetchInitialData();
    const interval = setInterval(fetchInitialData, 5000);

    return () => {
      if (ws) ws.close();
      clearInterval(interval);
    };
  }, []);

  const fetchInitialData = async () => {
    try {
      const [resOverview, resTalkers, resAlerts, resFlows, resProto] = await Promise.all([
        fetch('http://localhost:8000/api/v1/metrics/overview').then(r => r.json()),
        fetch('http://localhost:8000/api/v1/metrics/top-talkers?limit=10').then(r => r.json()),
        fetch('http://localhost:8000/api/v1/alerts?limit=50').then(r => r.json()),
        fetch('http://localhost:8000/api/v1/flows?limit=50').then(r => r.json()),
        fetch('http://localhost:8000/api/v1/metrics/protocols').then(r => r.json()),
      ]);

      if (resOverview && resOverview.network_pulse) {
        setPulse(prev => ({
          ...prev,
          mbps: resOverview.network_pulse.current_mbps,
          pps: resOverview.network_pulse.current_pps,
          fps: resOverview.network_pulse.current_fps,
          total_flows: resOverview.stats.total_flows_analyzed,
          total_alerts: resOverview.stats.total_alerts,
        }));
      }
      if (Array.isArray(resTalkers)) setTalkers(resTalkers);
      if (resAlerts && resAlerts.alerts) setAlerts(resAlerts.alerts);
      if (resFlows && resFlows.flows) setFlows(resFlows.flows);
      if (Array.isArray(resProto)) setProtocols(resProto);
    } catch (e) {}
  };

  const handleUpdateStatus = async (alertId, newStatus) => {
    try {
      await fetch(`http://localhost:8000/api/v1/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      setSelectedAlert(null);
      fetchInitialData();
    } catch (e) {}
  };

  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-col font-sans">
      {/* HEADER */}
      <header className="border-b border-[#1f2937] bg-[#111827]/90 backdrop-blur sticky top-0 z-30 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-lg text-blue-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-wider text-white text-base">NOVAFLOW <span className="text-blue-500">NDR</span></span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">SOC v1.0</span>
            </div>
            <p className="text-xs text-slate-400">Network Detection & Response &bull; NovaSec Technologies</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono border ${
            connected ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
          }`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`}></span>
            {connected ? 'WS CONECTADO' : 'CONECTANDO...'}
          </div>
          <button onClick={fetchInitialData} className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition">
            <RotateCw className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* TABS */}
      <nav className="border-b border-[#1f2937] bg-[#0a0e17] px-6 flex gap-6 text-sm font-medium">
        <button onClick={() => setActiveTab('overview')} className={`py-3 flex items-center gap-2 border-b-2 transition ${activeTab === 'overview' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
          <Activity className="w-4 h-4" /> Network Pulse
        </button>
        <button onClick={() => setActiveTab('talkers')} className={`py-3 flex items-center gap-2 border-b-2 transition ${activeTab === 'talkers' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
          <Users className="w-4 h-4" /> Top Talkers
        </button>
        <button onClick={() => setActiveTab('incidents')} className={`py-3 flex items-center gap-2 border-b-2 transition ${activeTab === 'incidents' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
          <AlertTriangle className="w-4 h-4" /> Incidentes de Seguridad
          <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono">{alerts.length}</span>
        </button>
        <button onClick={() => setActiveTab('flows')} className={`py-3 flex items-center gap-2 border-b-2 transition ${activeTab === 'flows' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
          <Search className="w-4 h-4" /> Explorador Forense
        </button>
      </nav>

      {/* CONTENT */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* STAT CARDS */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-4">
                <div className="text-xs text-slate-400 flex items-center justify-between">
                  <span>THROUGHPUT</span><Wifi className="w-4 h-4 text-blue-400" />
                </div>
                <div className="mt-2 text-3xl font-bold font-mono text-white">{pulse.mbps.toFixed(2)} <span className="text-xs text-slate-400 font-sans font-normal">Mbps</span></div>
              </div>

              <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-4">
                <div className="text-xs text-slate-400 flex items-center justify-between">
                  <span>TASA DE PAQUETES</span><Layers className="w-4 h-4 text-indigo-400" />
                </div>
                <div className="mt-2 text-3xl font-bold font-mono text-white">{pulse.pps.toLocaleString()} <span className="text-xs text-slate-400 font-sans font-normal">pkt/s</span></div>
              </div>

              <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-4">
                <div className="text-xs text-slate-400 flex items-center justify-between">
                  <span>TASA DE FLUJOS</span><Zap className="w-4 h-4 text-amber-400" />
                </div>
                <div className="mt-2 text-3xl font-bold font-mono text-white">{pulse.fps.toLocaleString()} <span className="text-xs text-slate-400 font-sans font-normal">flows/s</span></div>
              </div>

              <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-4">
                <div className="text-xs text-slate-400 flex items-center justify-between">
                  <span>TOTAL ANALIZADO</span><Database className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="mt-2 text-2xl font-bold font-mono text-white">{pulse.total_flows.toLocaleString()}</div>
              </div>

              <div className="bg-[#111827] border border-rose-900/40 rounded-xl p-4 bg-gradient-to-br from-rose-950/20 to-[#111827]">
                <div className="text-xs text-rose-300 flex items-center justify-between">
                  <span>ALERTAS ACTIVAS</span><ShieldX className="w-4 h-4 text-rose-400" />
                </div>
                <div className="mt-2 text-3xl font-bold font-mono text-rose-400">{alerts.length}</div>
              </div>
            </div>

            {/* QUICK ALERTS TABLE */}
            <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-white">ÚLTIMOS INCIDENTES DETECTADOS EN RED</h3>
                <button onClick={() => setActiveTab('incidents')} className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">Ver todos <ArrowRight className="w-3 h-3" /></button>
              </div>
              <div className="divide-y divide-[#1f2937]">
                {alerts.slice(0, 5).map(a => (
                  <div key={a.alert_id} onClick={() => setSelectedAlert(a)} className="py-3 flex items-center justify-between text-xs hover:bg-slate-900/50 px-2 rounded cursor-pointer transition">
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        a.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        a.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}>{a.severity}</span>
                      <div>
                        <div className="font-medium text-white">{a.title}</div>
                        <div className="text-[11px] text-slate-400 font-mono">{a.src_ip} &rarr; {a.dst_ip}:{a.dst_port}</div>
                      </div>
                    </div>
                    <span className="text-slate-400 font-mono text-[11px]">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'talkers' && (
          <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-5 overflow-x-auto">
            <h2 className="text-base font-semibold text-white mb-4">Top Talkers de la Red</h2>
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/70 text-slate-400 border-b border-[#1f2937]">
                <tr>
                  <th className="py-3 px-4">#</th>
                  <th className="py-3 px-4">DIRECCIÓN IP</th>
                  <th className="py-3 px-4">VOLUMEN (MB)</th>
                  <th className="py-3 px-4">PAQUETES</th>
                  <th className="py-3 px-4">FLUJOS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2937]">
                {talkers.map((t, idx) => (
                  <tr key={t.ip} className="hover:bg-slate-900/50">
                    <td className="py-3 px-4 text-slate-500">{idx + 1}</td>
                    <td className="py-3 px-4 font-bold text-blue-400">{t.ip}</td>
                    <td className="py-3 px-4 font-bold text-white">{t.total_mb} MB</td>
                    <td className="py-3 px-4 text-slate-300">{t.packets.toLocaleString()}</td>
                    <td className="py-3 px-4 text-slate-300">{t.flow_count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'incidents' && (
          <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-5 overflow-x-auto">
            <h2 className="text-base font-semibold text-white mb-4">Incidentes de Seguridad Detectados</h2>
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-slate-900/70 text-slate-400 font-mono border-b border-[#1f2937]">
                <tr>
                  <th className="py-3 px-4">HORA</th>
                  <th className="py-3 px-4">SEVERIDAD</th>
                  <th className="py-3 px-4">CATEGORÍA</th>
                  <th className="py-3 px-4">TÍTULO</th>
                  <th className="py-3 px-4">ORIGEN &rarr; DESTINO</th>
                  <th className="py-3 px-4">ESTADO</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2937]">
                {alerts.map(a => (
                  <tr key={a.alert_id} onClick={() => setSelectedAlert(a)} className="hover:bg-slate-900/50 cursor-pointer">
                    <td className="py-3 px-4 font-mono text-slate-400">{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        a.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        a.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}>{a.severity}</span>
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-slate-300">{a.category}</td>
                    <td className="py-3 px-4 text-white font-medium">{a.title}</td>
                    <td className="py-3 px-4 font-mono text-slate-400">{a.src_ip} &rarr; {a.dst_ip}:{a.dst_port}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300">{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'flows' && (
          <div className="bg-[#111827] border border-[#1f2937] rounded-xl p-5 overflow-x-auto font-mono text-xs">
            <h2 className="text-base font-semibold text-white mb-4 font-sans">Explorador Forense de Flujos</h2>
            <table className="w-full text-left">
              <thead className="bg-slate-900/70 text-slate-400 border-b border-[#1f2937]">
                <tr>
                  <th className="py-2 px-3">TIMESTAMP</th>
                  <th className="py-2 px-3">PROTOCOLO</th>
                  <th className="py-2 px-3">ORIGEN:PUERTO</th>
                  <th className="py-2 px-3">DESTINO:PUERTO</th>
                  <th className="py-2 px-3">BYTES</th>
                  <th className="py-2 px-3">PAQUETES</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2937]">
                {flows.map((f, i) => (
                  <tr key={i} className="hover:bg-slate-900/50">
                    <td className="py-2 px-3 text-slate-400">{new Date(f.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2 px-3 text-blue-400 font-bold">{f.protocol_name}</td>
                    <td className="py-2 px-3 text-white">{f.src_ip}:{f.src_port}</td>
                    <td className="py-2 px-3 text-white">{f.dst_ip}:{f.dst_port}</td>
                    <td className="py-2 px-3 text-slate-300">{f.bytes.toLocaleString()}</td>
                    <td className="py-2 px-3 text-slate-300">{f.packets.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>

      {/* MODAL DETALLE */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-[#1f2937] rounded-2xl max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">{selectedAlert.title}</h3>
                <p className="text-xs font-mono text-slate-400">{selectedAlert.category} &bull; {selectedAlert.severity}</p>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <p className="text-xs text-slate-300 bg-slate-900 p-3 rounded-lg border border-[#1f2937]">{selectedAlert.description}</p>
            <div className="text-xs">
              <span className="text-slate-400 font-mono block mb-1">Métricas del Ataque:</span>
              <pre className="bg-slate-950 p-3 rounded-lg text-emerald-400 text-[11px] overflow-x-auto border border-slate-800">
                {JSON.stringify(selectedAlert.metrics, null, 2)}
              </pre>
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-[#1f2937]">
              <button onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'INVESTIGATING')} className="px-3 py-1.5 rounded-lg bg-amber-600/20 text-amber-300 border border-amber-500/30 text-xs">Investigando</button>
              <button onClick={() => handleUpdateStatus(selectedAlert.alert_id, 'RESOLVED')} className="px-3 py-1.5 rounded-lg bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 text-xs">Resolver</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
