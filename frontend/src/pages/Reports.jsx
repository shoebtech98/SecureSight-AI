import React, { useState, useEffect } from 'react';
import {
  FileBarChart,
  Download,
  RefreshCw,
  Shield,
  Activity,
  Calendar,
  Clock,
  TrendingUp,
  FileBadge
} from 'lucide-react';
import {
  BarChart,
  Bar,
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

const SEVERITY_COLORS = {
  CRITICAL: '#EF4444',
  HIGH: '#F97316',
  MEDIUM: '#F59E0B',
  LOW: '#3B82F6',
  INFO: '#10B981',
};

const PIE_COLORS = ['#7C3AED', '#06B6D4', '#F59E0B', '#EF4444', '#10B981'];

const Reports = () => {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalIncidents, setTotalIncidents] = useState(0);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  const generatedAt = new Date();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, alertsRes] = await Promise.all([
        api.get('/api/dashboard/stats'),
        api.get('/api/threats', { params: { limit: 20 } })
      ]);
      setStats(statsRes.data);
      setAlerts(alertsRes.data);
      const incidentTotal = Number(alertsRes.headers?.['x-total-count']);
      setTotalIncidents(Number.isFinite(incidentTotal) ? incidentTotal : alertsRes.data.length);
    } catch (err) {
      console.error('Failed to load report data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handlePdfExport = async () => {
    setExporting(true);
    try {
      const response = await api.get('/api/reports/pdf', { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = `securesight-report-${new Date().toISOString().slice(0, 10)}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export PDF report', err);
      // Fallback to print dialog if server PDF fails
      window.print();
    } finally {
      setExporting(false);
    }
  };

  const handleCsvExport = async () => {
    try {
      const response = await api.get('/api/reports/alerts.csv', { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'securesight-alerts.csv';
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export alert CSV', err);
    }
  };


  // Severity counts come from the complete dashboard aggregates, not merely the
  // 20 alerts loaded for the on-screen registry preview.
  const severityBreakdown = (stats?.alert_severity_distribution || []).map((entry) => ({
    name: entry.name.charAt(0) + entry.name.slice(1).toLowerCase(),
    value: entry.value,
    color: SEVERITY_COLORS[entry.name] || '#94A3B8',
  }));

  const noData = !stats || stats.total_files === 0;

  if (loading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center text-slate-9000 gap-2">
        <RefreshCw className="animate-spin text-primary" size={24} />
        <span>Generating Security Report...</span>
      </div>
    );
  }

  return (
    <>
      {/* ── Print Styles (injected globally per-render) ──────────────── */}
      <style>{`
        @media print {
          body * { visibility: hidden !important; }
          #printable-report, #printable-report * { visibility: visible !important; }
          #printable-report { 
            position: fixed; top: 0; left: 0; width: 100%; 
            background: white !important; color: black !important;
            padding: 32px; font-family: 'Inter', sans-serif;
          }
          .no-print { display: none !important; }
          .print-border { border: 1px solid #e2e8f0 !important; }
          h1, h2, h3 { color: #1e293b !important; }
          p, span, td, th { color: #334155 !important; }
          .print-white { background: white !important; }
        }
      `}</style>

      <div className="space-y-6 max-w-7xl mx-auto">
        {/* ── Page Header ──────────────────────────────────────────── */}
        <div className="flex justify-between items-start no-print">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2.5">
              <div className="p-1.5 bg-primary/15 rounded-lg border border-primary/25">
                <FileBarChart size={20} className="text-primary" />
              </div>
              Security Reports
            </h1>
            <p className="text-sm text-slate-9000 mt-1 ml-0.5">
              Generate and export comprehensive security posture reports from your SIEM data.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchData}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 rounded-lg hover:border-slate-300 text-slate-700 transition-all"
            >
              <RefreshCw size={13} />
              Refresh
            </button>
            <button
              onClick={handlePdfExport}
              disabled={noData || exporting}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-primary hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg shadow-lg shadow-primary/20 transition-all"
            >
              {exporting ? (
                <RefreshCw size={13} className="animate-spin" />
              ) : (
                <Download size={13} />
              )}
              Export PDF
            </button>

            <button
              onClick={handleCsvExport}
              disabled={noData}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-white border border-slate-200 hover:border-slate-300 disabled:opacity-40 disabled:cursor-not-allowed text-slate-700 rounded-lg transition-all"
            >
              <Download size={13} />
              Export CSV
            </button>
          </div>
        </div>

        {/* ── Report Controls Panel ─────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 no-print">
          {[
            {
              icon: FileBadge,
              title: 'Security Posture Report',
              desc: 'Full threat overview, IP analysis, severity breakdown',
              badge: 'Available',
              badgeClass: 'bg-success/10 text-success border-success/25',
            },
            {
              icon: Activity,
              title: 'Incident Response Log',
              desc: 'Timeline of all alerts with triage actions taken',
              badge: 'Available',
              badgeClass: 'bg-success/10 text-success border-success/25',
            },
            {
              icon: TrendingUp,
              title: 'Traffic Analysis Report',
              desc: 'Event density, source services, and log volume trends',
              badge: 'Coming Soon',
              badgeClass: 'bg-slate-100 text-slate-9000 border-slate-300',
            },
          ].map((card, i) => {
            const Icon = card.icon;
            return (
              <div key={i} className="bg-white border border-slate-200 rounded-2xl p-5 flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                    <Icon size={16} className="text-primary" />
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${card.badgeClass}`}>
                    {card.badge}
                  </span>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-800">{card.title}</h3>
                  <p className="text-[11px] text-slate-9000 mt-0.5">{card.desc}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* ─────────────────────────────────────────────────────────── */}
        {/* PRINTABLE REPORT SECTION                                    */}
        {/* ─────────────────────────────────────────────────────────── */}
        <div id="printable-report">
          {/* Report Header */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 print-white print-border">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-2xl bg-primary/15 border border-primary/25 flex items-center justify-center">
                  <Shield size={28} className="text-primary" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-slate-800 tracking-tight">
                    SecureSight AI — Security Posture Report
                  </h2>
                  <p className="text-xs text-slate-9000 mt-0.5">
                    AI-Assisted SIEM Threat Analysis & Incident Summary
                  </p>
                </div>
              </div>
              <div className="text-right text-xs text-slate-9000 space-y-1">
                <div className="flex items-center gap-1.5 justify-end">
                  <Calendar size={11} />
                  <span>{generatedAt.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}</span>
                </div>
                <div className="flex items-center gap-1.5 justify-end">
                  <Clock size={11} />
                  <span>{generatedAt.toLocaleTimeString()}</span>
                </div>
                <div className="mt-2 px-2 py-0.5 bg-success/10 border border-success/20 rounded text-success font-bold text-[10px]">
                  REPORT STATUS: GENERATED
                </div>
              </div>
            </div>

            <div className="mt-6 pt-5 border-t border-slate-200 grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { label: 'Log Events Parsed', value: stats?.total_events?.toLocaleString() || 0, color: 'text-info' },
                { label: 'Total Threats Found', value: stats?.total_threats || 0, color: 'text-danger' },
                { label: 'Active Incidents', value: stats?.active_threats || 0, color: 'text-warning' },
                { label: 'Source Log Files', value: stats?.total_files || 0, color: 'text-success' },
              ].map((item, i) => (
                  <div key={i} className="text-center">
                    <div className={`text-3xl font-black ${item.color} mb-1`}>{item.value}</div>
                    <div className="text-[10px] text-slate-9000 uppercase tracking-wider">{item.label}</div>
                  </div>
                ))}
            </div>
          </div>

          {noData ? (
            <div className="bg-white border border-slate-200 rounded-2xl p-16 text-center mt-4">
              <FileBarChart size={48} className="mx-auto text-slate-700 stroke-[1.5] mb-4" />
              <h3 className="text-slate-800 font-semibold">No Data Available for Report</h3>
              <p className="text-xs text-slate-9000 mt-2">Upload and parse at least one log file to generate a security report.</p>
            </div>
          ) : (
            <>
              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
                {/* Severity Breakdown Bar Chart */}
                <div className="bg-white border border-slate-200 rounded-2xl p-5 print-white print-border">
                  <h3 className="text-sm font-semibold text-slate-800 mb-1">Severity Distribution</h3>
                  <p className="text-[10px] text-slate-9000 mb-4">Incidents classified by threat severity level</p>
                  {severityBreakdown.length === 0 ? (
                    <div className="py-10 text-center text-xs text-slate-9000">No severity data available</div>
                  ) : (
                    <div className="h-[200px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={severityBreakdown}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#CBD5E1" opacity={0.8} />
                          <XAxis dataKey="name" stroke="#64748B" fontSize={10} tickLine={false} />
                          <YAxis stroke="#64748B" fontSize={10} tickLine={false} axisLine={false} />
                          <Tooltip
                            contentStyle={{ backgroundColor: '#111827', borderColor: '#334155', borderRadius: '12px' }}
                            itemStyle={{ color: '#F8FAFC', fontSize: '11px' }}
                            labelStyle={{ color: '#94A3B8', fontSize: '11px' }}
                          />
                          <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                            {severityBreakdown.map((entry, index) => (
                              <Cell key={index} fill={entry.color} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>

                {/* Threat Type Pie */}
                <div className="bg-white border border-slate-200 rounded-2xl p-5 print-white print-border">
                  <h3 className="text-sm font-semibold text-slate-800 mb-1">Threat Type Breakdown</h3>
                  <p className="text-[10px] text-slate-9000 mb-4">Attack categories identified in ingested logs</p>
                  {(stats?.threat_type_distribution || []).length === 0 ? (
                    <div className="py-10 text-center text-xs text-slate-9000">No threat type data available</div>
                  ) : (
                    <div className="flex gap-4 items-center">
                      <div className="h-[200px] flex-1">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={stats.threat_type_distribution}
                              cx="50%"
                              cy="50%"
                              innerRadius={55}
                              outerRadius={80}
                              paddingAngle={3}
                              dataKey="value"
                            >
                              {stats.threat_type_distribution.map((_, index) => (
                                <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip
                              contentStyle={{ backgroundColor: '#111827', borderColor: '#334155', borderRadius: '12px' }}
                              itemStyle={{ color: '#F8FAFC', fontSize: '11px' }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="space-y-2 text-[10px] text-slate-9000 shrink-0">
                        {stats.threat_type_distribution.map((entry, i) => (
                          <div key={i} className="flex items-center gap-2">
                            <span
                              className="w-2.5 h-2.5 rounded shrink-0"
                              style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }}
                            />
                            <span className="max-w-[110px] truncate" title={entry.name}>
                              {entry.name} ({entry.value})
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Alert Incidents Table */}
              <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden mt-4 print-white print-border">
                <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-800">Incident Registry</h3>
                    <p className="text-[10px] text-slate-9000 mt-0.5">Latest detected security incidents</p>
                  </div>
                  <span className="text-[10px] px-2.5 py-1 bg-danger/10 border border-danger/25 text-danger rounded-full font-bold">
                    {totalIncidents} Total Incidents
                  </span>
                </div>

                {alerts.length === 0 ? (
                  <div className="py-10 text-center text-xs text-slate-9000">No incidents to display</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-100/30 text-slate-9000 uppercase tracking-wider text-[10px]">
                          <th className="px-5 py-3 font-semibold">#</th>
                          <th className="px-5 py-3 font-semibold">Threat Type</th>
                          <th className="px-5 py-3 font-semibold">Severity</th>
                          <th className="px-5 py-3 font-semibold">Source IP</th>
                          <th className="px-5 py-3 font-semibold">Status</th>
                          <th className="px-5 py-3 font-semibold">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/50">
                        {alerts.slice(0, 20).map((alert, i) => (
                          <tr key={alert.id} className="hover:bg-slate-100/20 text-slate-700">
                            <td className="px-5 py-3 text-slate-9000 font-mono text-[10px]">{i + 1}</td>
                            <td className="px-5 py-3 font-bold text-slate-800">{alert.threat_type}</td>
                            <td className="px-5 py-3">
                              <span
                                className="inline-flex px-2 py-0.5 rounded text-[9px] font-extrabold border"
                                style={{
                                  backgroundColor: `${SEVERITY_COLORS[alert.severity]}15`,
                                  color: SEVERITY_COLORS[alert.severity],
                                  borderColor: `${SEVERITY_COLORS[alert.severity]}30`
                                }}
                              >
                                {alert.severity}
                              </span>
                            </td>
                            <td className="px-5 py-3 font-mono text-slate-700">{alert.source_ip || '—'}</td>
                            <td className="px-5 py-3">
                              <span className={`inline-flex px-1.5 py-0.5 rounded text-[9px] uppercase font-bold ${
                                alert.status === 'active'
                                  ? 'bg-danger/10 text-danger'
                                  : alert.status === 'resolved'
                                  ? 'bg-success/10 text-success'
                                  : 'bg-slate-700 text-slate-9000'
                              }`}>
                                {alert.status.replace('_', ' ')}
                              </span>
                            </td>
                            <td className="px-5 py-3 font-mono text-[10px] text-slate-9000">
                              {new Date(alert.timestamp).toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {totalIncidents > alerts.length && (
                      <div className="px-5 py-3 border-t border-slate-200 text-[10px] text-slate-9000 text-center">
                        Showing {alerts.length} of {totalIncidents} incidents. Export PDF for full list.
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Top IPs section */}
              {stats?.top_ips?.length > 0 && (
                <div className="bg-white border border-slate-200 rounded-2xl p-5 mt-4 print-white print-border">
                  <h3 className="text-sm font-semibold text-slate-800 mb-1">Top Suspicious IP Addresses</h3>
                  <p className="text-[10px] text-slate-9000 mb-4">Remote hosts generating the highest alert volumes</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                    {stats.top_ips.map((ipObj, index) => (
                      <div
                        key={index}
                        className="flex flex-col gap-1 p-3 bg-danger/5 border border-danger/15 rounded-xl"
                      >
                        <div className="flex items-center gap-1.5">
                          <span className="text-[9px] w-4 h-4 bg-danger/20 text-danger rounded-full flex items-center justify-center font-bold">
                            {index + 1}
                          </span>
                          <span className="text-[10px] font-mono font-bold text-slate-800">{ipObj.ip}</span>
                        </div>
                        <span className="text-[10px] text-danger font-bold">{ipObj.count} alerts</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Report Footer */}
              <div className="mt-4 bg-white border border-slate-200 rounded-2xl px-6 py-4 flex justify-between items-center text-[10px] text-slate-9000 print-white print-border">
                <div className="flex items-center gap-2">
                  <Shield size={12} className="text-primary" />
                  <span>SecureSight AI — Security Intelligence Platform</span>
                </div>
                <span>Generated: {generatedAt.toLocaleString()}</span>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default Reports;
