import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  FileText,
  CheckCircle2,
  ChevronRight,
  TrendingUp,
  AlertTriangle,
  RefreshCw,
  Terminal
} from 'lucide-react';
import {
  ComposedChart,
  Area,
  Bar,
  Legend,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import api from '../services/api';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      const response = await api.get('/api/dashboard/stats');
      setStats(response.data);
    } catch (err) {
      console.error('Failed to load dashboard statistics', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchStats();
  };

  // Merge event counts and threat counts per day into a single timeline series.
  const timelineData = useMemo(() => {
    const byDate = new Map();
    for (const d of stats?.events_over_time || []) {
      byDate.set(d.date, { date: d.date, events: d.events, threats: 0 });
    }
    for (const d of stats?.threat_timeline || []) {
      if (byDate.has(d.date)) {
        byDate.get(d.date).threats = d.threats;
      } else {
        byDate.set(d.date, { date: d.date, events: 0, threats: d.threats });
      }
    }
    return [...byDate.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)));
  }, [stats]);

  if (loading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center text-slate-9000 gap-2">
        <RefreshCw className="animate-spin text-primary" size={24} />
        <span>Loading SIEM Dashboard...</span>
      </div>
    );
  }

  // Fallback defaults if no logs uploaded
  const hasData = stats && stats.total_files > 0;
  
  const cardStats = [
    { name: 'Total Log Events', value: stats?.total_events || 0, icon: FileText, color: 'text-info', bg: 'bg-info/10 border-info/20' },
    { name: 'Total Threats Detected', value: stats?.total_threats || 0, icon: ShieldAlert, color: 'text-danger', bg: 'bg-danger/10 border-danger/20' },
    { name: 'Active Incidents', value: stats?.active_threats || 0, icon: AlertTriangle, color: 'text-warning', bg: 'bg-warning/10 border-warning/20' },
    { name: 'Processed Source Files', value: stats?.total_files || 0, icon: CheckCircle2, color: 'text-success', bg: 'bg-success/10 border-success/20' },
    { name: 'Critical Alerts', value: stats?.critical_alerts || 0, icon: ShieldAlert, color: 'text-danger', bg: 'bg-danger/10 border-danger/20' },
    { name: 'High Risk IPs', value: stats?.high_risk_ips || 0, icon: AlertTriangle, color: 'text-warning', bg: 'bg-warning/10 border-warning/20' },
    { name: 'Brute Force Attempts', value: stats?.brute_force_attempts || 0, icon: Activity, color: 'text-orange-500', bg: 'bg-orange-500/10 border-orange-500/20' },
    { name: 'Authentication Failures', value: stats?.authentication_failures || 0, icon: AlertTriangle, color: 'text-amber-500', bg: 'bg-amber-500/10 border-amber-500/20' },
    { name: 'SQL Injection Attempts', value: stats?.sql_injection_attempts || 0, icon: ShieldAlert, color: 'text-red-500', bg: 'bg-red-500/10 border-red-500/20' },
    { name: 'Malware Events', value: stats?.malware_events || 0, icon: ShieldAlert, color: 'text-fuchsia-600', bg: 'bg-fuchsia-500/10 border-fuchsia-500/20' },
  ];

  // Recharts color palettes
  const COLORS = ['#7C3AED', '#06B6D4', '#F59E0B', '#EF4444', '#10B981'];
  
  // Severity order mapping
  const severityColors = {
    'CRITICAL': '#EF4444',
    'HIGH': '#F97316',
    'MEDIUM': '#F59E0B',
    'LOW': '#3B82F6',
    'INFO': '#10B981'
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">SIEM Analytics Dashboard</h1>
          <p className="text-sm text-slate-9000 mt-1">Real-time parsed events, log distributions, and security alerts intelligence.</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 rounded-lg hover:border-slate-300 hover:bg-slate-100/50 text-slate-700 transition-all duration-200"
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          <span>{refreshing ? 'Refreshing...' : 'Refresh Logs'}</span>
        </button>
      </div>

      {/* Stats Widget Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        {cardStats.map((card, i) => {
          const Icon = card.icon;
          return (
            <div
              key={i}
              className={`bg-white border p-6 rounded-2xl flex items-center justify-between shadow-lg relative overflow-hidden group hover:scale-[1.02] transition-transform duration-200 ${card.bg}`}
            >
              <div className="space-y-1 z-10">
                <p className="text-xs font-medium text-slate-9000 uppercase tracking-wider">{card.name}</p>
                <p className="text-2xl sm:text-3xl font-extrabold text-slate-900">{card.value.toLocaleString()}</p>
              </div>
              <div className={`p-3 rounded-xl ${card.color} bg-slate-100/40 z-10`}>
                <Icon size={24} className="stroke-[1.5]" />
              </div>
            </div>
          );
        })}
      </div>

      {!hasData ? (
        <div className="bg-white border border-slate-200 rounded-2xl p-12 text-center text-slate-9000 space-y-4">
          <Terminal size={48} className="mx-auto text-slate-700 stroke-[1.5]" />
          <div className="max-w-md mx-auto space-y-2">
            <h3 className="text-md font-semibold text-slate-800">No Log Data Available</h3>
            <p className="text-xs text-slate-9000">
              Before you can see threat visualization widgets, you must upload and parse a valid log source file.
            </p>
          </div>
          <Link to="/upload" className="inline-block mt-2">
            <button className="px-5 py-2.5 bg-primary hover:bg-blue-700 rounded-xl text-white font-medium text-xs transition-colors shadow-lg shadow-primary/20">
              Upload Log Source
            </button>
          </Link>
        </div>
      ) : (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Timeline Composed Chart: events (area) + threats (bars) */}
            <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-5 flex flex-col min-h-[380px]">
              <div className="flex justify-between items-center mb-5">
                <div>
                  <h3 className="text-sm font-semibold text-slate-800">SIEM Activity Timeline</h3>
                  <p className="text-[10px] text-slate-9000">Log events processed vs. threats detected per day</p>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-primary font-medium">
                  <TrendingUp size={14} />
                  <span>Live</span>
                </div>
              </div>
              
              <div className="flex-1 w-full h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={timelineData}>
                    <defs>
                      <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#7C3AED" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#7C3AED" stopOpacity={0.0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" opacity={0.8} />
                    <XAxis 
                      dataKey="date" 
                      stroke="var(--chart-tick)" 
                      fontSize={10}
                      tickLine={false}
                    />
                    <YAxis 
                      stroke="var(--chart-tick)" 
                      fontSize={10} 
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#111827', borderColor: '#334155', borderRadius: '12px' }}
                      labelStyle={{ color: '#94A3B8', fontSize: '11px', fontWeight: 'bold' }}
                      itemStyle={{ color: '#F8FAFC', fontSize: '11px' }}
                    />
                    <Legend wrapperStyle={{ fontSize: '10px', paddingTop: '6px' }} />
                    <Area 
                      type="monotone" 
                      dataKey="events" 
                      name="Log Events" 
                      stroke="#7C3AED" 
                      strokeWidth={2.5} 
                      fillOpacity={1} 
                      fill="url(#colorEvents)" 
                    />
                    <Bar 
                      dataKey="threats" 
                      name="Threats Detected" 
                      fill="#EF4444" 
                      radius={[3, 3, 0, 0]} 
                      barSize={18}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Threat Distribution Pie */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 flex flex-col justify-between min-h-[380px]">
              <div>
                <h3 className="text-sm font-semibold text-slate-800">Threat Types Distribution</h3>
                <p className="text-[10px] text-slate-9000">Total detected incidents classified by signature</p>
              </div>

              {stats.threat_type_distribution.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-xs text-slate-9000 gap-2">
                  <CheckCircle2 size={32} className="text-success opacity-60" />
                  <span>No threats detected in log files. All clean!</span>
                </div>
              ) : (
                <div className="flex-1 flex flex-col justify-around py-4">
                  <div className="w-full h-[180px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={stats.threat_type_distribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={75}
                          paddingAngle={3}
                          dataKey="value"
                          isAnimationActive={false}
                        >
                          {stats.threat_type_distribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: '#111827', borderColor: '#334155', borderRadius: '12px' }}
                          itemStyle={{ color: '#F8FAFC', fontSize: '11px' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Legend Custom */}
                  <div className="grid grid-cols-2 gap-2 text-[10px] px-2 text-slate-9000">
                    {stats.threat_type_distribution.map((entry, index) => (
                      <div key={index} className="flex items-center gap-1.5">
                        <span 
                          className="w-2.5 h-2.5 rounded shrink-0" 
                          style={{ backgroundColor: COLORS[index % COLORS.length] }} 
                        />
                        <span className="truncate" title={entry.name}>{entry.name} ({entry.value})</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Lower Grid: Severity Donut, Top Attackers & Recent Threats */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Severity Donut */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 flex flex-col justify-between min-h-[380px]">
              <div>
                <h3 className="text-sm font-semibold text-slate-800">Threat Severity Breakdown</h3>
                <p className="text-[10px] text-slate-9000">Detected alerts classified by severity level</p>
              </div>

              {(stats.alert_severity_distribution || []).length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-xs text-slate-9000 gap-2">
                  <CheckCircle2 size={32} className="text-success opacity-60" />
                  <span>No threats detected. All clean!</span>
                </div>
              ) : (
                <div className="flex-1 flex flex-col justify-around py-4">
                  <div className="relative w-full h-[170px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={stats.alert_severity_distribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={52}
                          outerRadius={78}
                          paddingAngle={3}
                          dataKey="value"
                          stroke="none"
                          isAnimationActive={false}
                        >
                          {stats.alert_severity_distribution.map((entry, index) => (
                            <Cell key={`sev-${index}`} fill={severityColors[entry.name] || '#94A3B8'} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: '#111827', borderColor: '#334155', borderRadius: '12px' }}
                          itemStyle={{ color: '#F8FAFC', fontSize: '11px' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    {/* Center total */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <span className="text-2xl font-extrabold text-slate-900">
                        {stats.alert_severity_distribution.reduce((sum, d) => sum + d.value, 0).toLocaleString()}
                      </span>
                      <span className="text-[9px] text-slate-9000 uppercase tracking-wider">Alerts</span>
                    </div>
                  </div>

                  {/* Severity legend */}
                  <div className="grid grid-cols-1 gap-1.5 text-[10px] px-2 mt-3">
                    {stats.alert_severity_distribution.map((entry) => (
                      <div key={entry.name} className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5">
                          <span
                            className="w-2.5 h-2.5 rounded shrink-0"
                            style={{ backgroundColor: severityColors[entry.name] || '#94A3B8' }}
                          />
                          <span className="font-semibold text-slate-800">{entry.name}</span>
                        </div>
                        <span className="text-slate-9000 font-mono">{entry.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Top Attacking IPs */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-800">Top Attacking IPs</h3>
                <p className="text-[10px] text-slate-9000">Remote hosts triggering the most alerts</p>
              </div>

              {stats.top_ips.length === 0 ? (
                <div className="py-12 text-center text-xs text-slate-9000">No attacker IPs parsed.</div>
              ) : (
                <div className="flex-1 flex flex-col justify-center space-y-2.5 mt-4">
                  {stats.top_ips.map((ipObj, index) => {
                    const max = stats.top_ips[0]?.count || 1;
                    const pct = Math.max(10, Math.round((ipObj.count / max) * 100));
                    const rankColor = ['text-amber-500', 'text-slate-400', 'text-orange-700'][index] || 'text-slate-9000';
                    return (
                      <div key={index} className="relative p-3 bg-slate-50/40 border border-slate-200/80 rounded-xl overflow-hidden">
                        {/* Proportional activity bar */}
                        <div
                          className="absolute inset-y-0 left-0 bg-danger/10"
                          style={{ width: `${pct}%` }}
                        />
                        <div className="relative flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className={`text-xs font-extrabold ${rankColor}`}>{index + 1}</span>
                            <span className="text-xs font-mono font-bold text-slate-800">{ipObj.ip}</span>
                          </div>
                          <span className="text-[10px] text-danger bg-danger/10 px-2 py-0.5 rounded-full border border-danger/25 font-bold">
                            {ipObj.count} Alerts
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Live Incidents Timeline */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5 flex flex-col justify-between">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-800">Recent Threat Alerts</h3>
                  <p className="text-[10px] text-slate-9000">Latest active alerts flagged by parsing rules</p>
                </div>
                <Link to="/threats" className="text-xs font-semibold text-primary hover:text-blue-700 flex items-center gap-0.5">
                  <span>Triage Center</span>
                  <ChevronRight size={14} />
                </Link>
              </div>

              {stats.recent_threats.length === 0 ? (
                <div className="py-12 text-center text-xs text-slate-9000 flex flex-col items-center justify-center gap-1.5">
                  <CheckCircle2 size={24} className="text-success" />
                  No threat alerts triggered. System status healthy.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {stats.recent_threats.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-3 bg-slate-100/30 border border-slate-200/60 rounded-xl flex items-center justify-between hover:bg-slate-100/20 transition-colors"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span 
                            className="text-[9px] font-extrabold px-1.5 py-0.5 rounded font-mono"
                            style={{ 
                              backgroundColor: `${severityColors[alert.severity]}15`, 
                              color: severityColors[alert.severity],
                              border: `1px solid ${severityColors[alert.severity]}25` 
                            }}
                          >
                            {alert.severity}
                          </span>
                          <span className="text-xs font-bold text-slate-800">{alert.threat_type}</span>
                        </div>
                        <p className="text-[10px] text-slate-9000 max-w-md truncate">{alert.description}</p>
                      </div>
                      
                      <div className="text-right text-[9px] text-slate-9000 font-mono space-y-0.5">
                        <p>{alert.source_ip || 'No IP'}</p>
                        <p>{new Date(alert.timestamp).toLocaleTimeString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
