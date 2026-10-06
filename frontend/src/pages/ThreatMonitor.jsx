import React, { useState, useEffect, useCallback } from 'react';
import { Shield, AlertTriangle, CheckCircle, HelpCircle, RefreshCw, Check, ShieldAlert, Terminal, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import api from '../services/api';
import Alert from '../components/Alert';
import Button from '../components/Button';

const ThreatMonitor = () => {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedLogEvent, setSelectedLogEvent] = useState(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState('active');
  const [severityFilter, setSeverityFilter] = useState('');

  // Pagination — the backend returns bounded pages so large alert sets stay fast.
  const PAGE_SIZE = 100;
  const [page, setPage] = useState(1);
  const [totalAlerts, setTotalAlerts] = useState(0);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const params = {
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE
      };
      
      const [alertsRes, statsRes] = await Promise.all([
        api.get('/api/threats', { params }),
        api.get('/api/threats/stats')
      ]);

      setAlerts(alertsRes.data);
      const filteredTotal = Number(alertsRes.headers?.['x-total-count']);
      setTotalAlerts(Number.isFinite(filteredTotal) ? filteredTotal : alertsRes.data.length);
      setStats(statsRes.data);
    } catch (err) {
      console.error('Failed to load threat monitoring data', err);
      setError('Failed to refresh security incidents board.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [statusFilter, severityFilter, page]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Changing filters returns to the first page.
  const changeStatusFilter = (value) => {
    setStatusFilter(value);
    setPage(1);
  };

  const changeSeverityFilter = (value) => {
    setSeverityFilter(value);
    setPage(1);
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      await api.put(`/api/threats/${id}`, { status: newStatus });
      setSuccess(`Incident updated to ${newStatus.replace('_', ' ')}.`);
      fetchData();
    } catch {
      setError('Failed to update incident status.');
    }
  };

  const getSeverityStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'LOW': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default: return 'bg-slate-100 text-slate-9000 border-slate-300/20';
    }
  };

  const getStatusBadgeStyle = (status) => {
    switch (status) {
      case 'active': return 'bg-red-500/10 text-danger border border-red-500/25 font-bold';
      case 'resolved': return 'bg-success/10 text-success border border-success/25 font-semibold';
      case 'false_positive': return 'bg-slate-100 text-slate-9000 border border-slate-300';
      default: return 'bg-slate-100 text-slate-700';
    }
  };

  if (loading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center text-slate-9000 gap-2">
        <RefreshCw className="animate-spin text-primary" size={24} />
        <span>Loading Threat Monitor Board...</span>
      </div>
    );
  }

  const counters = [
    { name: 'Active Incidents', value: stats?.active || 0, icon: AlertTriangle, color: 'text-danger' },
    { name: 'Resolved Incidents', value: stats?.resolved || 0, icon: CheckCircle, color: 'text-success' },
    { name: 'False Positives', value: stats?.false_positive || 0, icon: HelpCircle, color: 'text-slate-9000' },
  ];

  const totalPages = Math.max(1, Math.ceil(totalAlerts / PAGE_SIZE));

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header section */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Threat Monitor</h1>
          <p className="text-sm text-slate-9000 mt-1">SIEM Intrusion Detection. Review triggered alerts, inspect malicious payloads, and resolve incidents.</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold bg-white border border-slate-200 rounded-lg hover:border-slate-300 hover:bg-slate-100/50 text-slate-700 transition-all"
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          <span>{refreshing ? 'Refreshing...' : 'Refresh Board'}</span>
        </button>
      </div>

      {error && <Alert type="danger" message={error} onClose={() => setError('')} />}
      {success && <Alert type="success" message={success} onClose={() => setSuccess('')} />}

      {/* Counters Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {counters.map((item, index) => {
          const Icon = item.icon;
          return (
            <div key={index} className="bg-white border border-slate-200/80 p-5 rounded-2xl flex items-center justify-between">
              <div className="space-y-1">
                <span className="text-[10px] text-slate-9000 uppercase tracking-wider font-semibold">{item.name}</span>
                <p className="text-2xl font-extrabold text-slate-800">{item.value}</p>
              </div>
              <div className={`p-2.5 rounded-xl bg-slate-100/40 ${item.color}`}>
                <Icon size={20} className="stroke-[1.5]" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Incident List Table */}
      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden">
        {/* Toolbar Filters */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-100/10 flex flex-wrap justify-between items-center gap-4">
          <div className="flex gap-4">
            {/* Status Tabs */}
            <div className="flex bg-slate-50 p-1 rounded-lg border border-slate-200">
              <button
                onClick={() => changeStatusFilter('active')}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  statusFilter === 'active' ? 'bg-primary text-white font-bold' : 'text-slate-9000 hover:text-slate-800'
                }`}
              >
                Active
              </button>
              <button
                onClick={() => changeStatusFilter('resolved')}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  statusFilter === 'resolved' ? 'bg-primary text-white font-bold' : 'text-slate-9000 hover:text-slate-800'
                }`}
              >
                Resolved
              </button>
              <button
                onClick={() => changeStatusFilter('false_positive')}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  statusFilter === 'false_positive' ? 'bg-primary text-white font-bold' : 'text-slate-9000 hover:text-slate-800'
                }`}
              >
                False Positive
              </button>
              <button
                onClick={() => changeStatusFilter('')}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  statusFilter === '' ? 'bg-primary text-white font-bold' : 'text-slate-9000 hover:text-slate-800'
                }`}
              >
                All
              </button>
            </div>

            {/* Severity Dropdown */}
            <select
              value={severityFilter}
              onChange={(e) => changeSeverityFilter(e.target.value)}
              className="px-3 py-1 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <span className="text-xs text-slate-9000 font-medium">
            Showing <span className="text-slate-800 font-bold">{alerts.length}</span> of{' '}
            <span className="text-slate-800 font-bold">{totalAlerts}</span> alert signatures
          </span>
        </div>

        {/* Content body */}
        {alerts.length === 0 ? (
          <div className="py-20 text-center text-xs text-slate-9000 flex flex-col items-center justify-center gap-1.5">
            <Shield className="text-slate-700 stroke-[1.5]" size={36} />
            No alerts logged for this selection. System is clean.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-100/30 text-slate-9000 uppercase tracking-wider text-[10px]">
                  <th className="px-6 py-3.5 font-semibold">Incident Type</th>
                  <th className="px-6 py-3.5 font-semibold w-[90px]">Severity</th>
                  <th className="px-6 py-3.5 font-semibold w-[130px]">Attacking IP</th>
                  <th className="px-6 py-3.5 font-semibold w-[100px]">Risk / Confidence</th>
                  <th className="px-6 py-3.5 font-semibold">Description</th>
                  <th className="px-6 py-3.5 font-semibold w-[140px]">Triggered</th>
                  <th className="px-6 py-3.5 font-semibold w-[100px]">Status</th>
                  <th className="px-6 py-3.5 font-semibold text-right">Triage Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-100/20 text-slate-700">
                    <td className="px-6 py-3.5">
                      <div className="flex items-center gap-2">
                        <ShieldAlert size={14} className="text-danger shrink-0" />
                        <span className="font-bold text-slate-800">{alert.threat_type}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3.5">
                      <span className={`inline-flex px-2 py-0.5 rounded text-[9px] font-extrabold border ${getSeverityStyle(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 font-mono font-bold text-slate-800">{alert.source_ip || 'No IP'}</td>
                    <td className="px-6 py-3.5">
                      <div className="font-bold text-slate-800">{alert.risk_score ?? 0} / 100</div>
                      <div className="text-[10px] text-slate-500">{alert.confidence ?? 0}% confidence</div>
                    </td>
                    <td className="px-6 py-3.5 text-slate-600">{alert.description}</td>
                    <td className="px-6 py-3.5 font-mono text-[10px] text-slate-450">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3.5">
                      <span className={`inline-flex px-1.5 py-0.5 rounded text-[8px] tracking-wide uppercase border ${getStatusBadgeStyle(alert.status)}`}>
                        {alert.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-right space-x-1.5 whitespace-nowrap">
                      {alert.log_event && (
                        <button
                          onClick={() => setSelectedLogEvent(alert.log_event)}
                          className="p-1 text-primary hover:bg-primary/10 rounded-md transition-colors"
                          title="Inspect raw log evidence"
                        >
                          <Search size={14} />
                        </button>
                      )}
                      
                      {alert.status === 'active' ? (
                        <>
                          <button
                            onClick={() => handleUpdateStatus(alert.id, 'resolved')}
                            className="p-1 text-success hover:bg-green-500/10 rounded-md transition-colors inline-flex items-center"
                            title="Mark Resolved"
                          >
                            <Check size={14} />
                          </button>
                          <button
                            onClick={() => handleUpdateStatus(alert.id, 'false_positive')}
                            className="p-1 text-slate-450 hover:bg-slate-100/20 rounded-md transition-colors inline-flex items-center"
                            title="Dismiss as False Positive"
                          >
                            <HelpCircle size={14} />
                          </button>
                        </>
                      ) : (
                        <span className="text-[10px] text-slate-9000 font-semibold italic">Triaged</span>
                      )}
                    </td>
                  </tr>                    ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination footer */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-slate-200 flex justify-between items-center text-xs text-slate-9000 bg-slate-100/10">
            <div>
              Showing{' '}
              <span className="font-semibold text-slate-800">{(page - 1) * PAGE_SIZE + 1}</span> to{' '}
              <span className="font-semibold text-slate-800">{Math.min(page * PAGE_SIZE, totalAlerts)}</span> of{' '}
              <span className="font-semibold text-slate-800">{totalAlerts}</span> incidents
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(p - 1, 1))}
                disabled={page === 1}
                className="p-1.5 rounded-lg border border-slate-200 bg-white text-slate-700 hover:border-slate-300 disabled:opacity-40"
                title="Previous page"
              >
                <ChevronLeft size={14} />
              </button>
              <span className="px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg font-semibold text-slate-700">
                Page {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(p + 1, totalPages))}
                disabled={page === totalPages}
                className="p-1.5 rounded-lg border border-slate-200 bg-white text-slate-700 hover:border-slate-300 disabled:opacity-40"
                title="Next page"
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Log Event Inspection Modal */}
      {selectedLogEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="fixed inset-0 bg-slate-400/20 backdrop-blur-sm" onClick={() => setSelectedLogEvent(null)} />
          
          <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl relative z-10 animate-in fade-in zoom-in-95 duration-150">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-100/20">
              <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <Terminal size={16} className="text-primary" /> Security Event Evidence
              </h3>
              <button
                onClick={() => setSelectedLogEvent(null)}
                className="text-slate-9000 hover:text-slate-800"
              >
                <XCircleIcon className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <span className="text-slate-9000 block text-[10px] uppercase font-bold tracking-wider">Timestamp</span>
                  <span className="text-slate-800 font-mono">{new Date(selectedLogEvent.timestamp).toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-slate-9000 block text-[10px] uppercase font-bold tracking-wider">Source Host / Service</span>
                  <span className="text-slate-800 font-semibold">{selectedLogEvent.service || 'System'}</span>
                </div>
                {selectedLogEvent.ip_address && (
                  <div>
                    <span className="text-slate-9000 block text-[10px] uppercase font-bold tracking-wider">Source IP Address</span>
                    <span className="text-slate-800 font-mono font-bold">{selectedLogEvent.ip_address}</span>
                  </div>
                )}
                {selectedLogEvent.status_code && (
                  <div>
                    <span className="text-slate-9000 block text-[10px] uppercase font-bold tracking-wider">HTTP Status Response</span>
                    <span className="text-slate-800 font-bold">{selectedLogEvent.status_code}</span>
                  </div>
                )}
              </div>

              <div className="space-y-1.5">
                <span className="text-slate-550 block text-[10px] uppercase font-bold tracking-wider">Raw Message</span>
                <div className="p-4 bg-slate-700 border border-slate-200 rounded-xl">
                  <pre className="text-[10px] font-mono text-slate-600 whitespace-pre-wrap break-all leading-relaxed">
                    {selectedLogEvent.message}
                  </pre>
                </div>
              </div>
            </div>

            <div className="px-6 py-3.5 bg-slate-100/10 border-t border-slate-200 text-right">
              <Button onClick={() => setSelectedLogEvent(null)} className="px-4 py-1.5 text-xs">
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper Close Icon
const XCircleIcon = (props) => (
  <svg
    {...props}
    xmlns="http://www.w3.org/2000/svg"
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="10" />
    <path d="m15 9-6 6" />
    <path d="m9 9 6 6" />
  </svg>
);

export default ThreatMonitor;
