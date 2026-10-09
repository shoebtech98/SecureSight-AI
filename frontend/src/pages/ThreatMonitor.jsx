import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, ChevronLeft, ChevronRight, Eye, RefreshCw, Shield, X } from 'lucide-react';
import api from '../services/api';
import Alert from '../components/Alert';

const PAGE_SIZE = 10;
const colors = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#eab308', LOW: '#3b82f6' };

function Badge({ children, kind }) { return <span className={`incident-badge ${kind}`}>{children}</span>; }
const attackingIp = (alert) => alert.source_ip || alert.log_event?.source_ip || alert.log_event?.ip_address || 'Not captured';

export default function ThreatMonitor() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selected, setSelected] = useState(null);
  const [statusFilter, setStatusFilter] = useState('active');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchData = useCallback(async () => {
    try {
      setError('');
      const [alertResponse, statsResponse] = await Promise.all([
        api.get('/api/threats', { params: { status: statusFilter || undefined, severity: severityFilter || undefined, skip: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE } }),
        api.get('/api/threats/stats'),
      ]);
      setAlerts(alertResponse.data);
      const count = Number(alertResponse.headers?.['x-total-count']);
      setTotal(Number.isFinite(count) ? count : alertResponse.data.length);
      setStats(statsResponse.data);
      setSelected((current) => current && alertResponse.data.find((item) => item.id === current.id) || null);
    } catch {
      setError('Could not load the incidents. Try refreshing.');
    } finally { setLoading(false); setRefreshing(false); }
  }, [statusFilter, severityFilter, page]);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => {
    if (!selected) return;
    const closeOnEscape = (event) => { if (event.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [selected]);

  const updateStatus = async (alert, status) => {
    try {
      await api.put(`/api/threats/${alert.id}`, { status });
      setSuccess(`Incident marked ${status.replace('_', ' ')}.`);
      setSelected(null);
      fetchData();
    } catch { setError('Could not update this incident.'); }
  };

  if (loading) return <div className="overview-loading"><RefreshCw size={22} className="animate-spin" />Loading incidents…</div>;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const filters = [
    { label: 'Active', value: 'active', count: stats?.active || 0 },
    { label: 'Resolved', value: 'resolved', count: stats?.resolved || 0 },
    { label: 'False positive', value: 'false_positive', count: stats?.false_positive || 0 },
    { label: 'All', value: '', count: null },
  ];

  return <div className="incident-page">
    <div className="overview-heading"><div><h1>Threat Monitor</h1><p>Review triggered alerts, inspect malicious payloads, and resolve incidents.</p></div><button className="overview-action" type="button" disabled={refreshing} onClick={() => { setRefreshing(true); fetchData(); }}><RefreshCw size={17} className={refreshing ? 'animate-spin' : ''} />Refresh</button></div>
    {error && <Alert type="danger" message={error} onClose={() => setError('')} />}
    {success && <Alert type="success" message={success} onClose={() => setSuccess('')} />}
    <div className="incident-metrics">
      {[{ label: 'Active incidents', value: stats?.active, icon: AlertTriangle, note: 'Awaiting analyst triage', color: 'red' }, { label: 'Resolved', value: stats?.resolved, icon: CheckCircle2, note: 'Closed after review', color: 'green' }, { label: 'False positives', value: stats?.false_positive, icon: Shield, note: 'Used to tune detection rules', color: 'gray' }].map((item) => <div className="incident-metric overview-metric" key={item.label}><div className="overview-metric-top"><span>{item.label}</span><span className={`overview-metric-icon ${item.color}`}><item.icon size={19} /></span></div><strong>{Number(item.value || 0).toLocaleString()}</strong><small>{item.note}</small></div>)}
    </div>
    <section className="overview-panel incident-list">
      <div className="incident-toolbar"><div className="incident-filters"><div className="incident-tabs">{filters.map((filter) => <button type="button" key={filter.label} className={statusFilter === filter.value ? 'is-active' : ''} onClick={() => { setStatusFilter(filter.value); setPage(1); }}>{filter.label}{filter.count !== null && <small>{filter.count}</small>}</button>)}</div><select aria-label="Filter by severity" value={severityFilter} onChange={(event) => { setSeverityFilter(event.target.value); setPage(1); }}><option value="">Severity: All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></div><span>Showing <b>{alerts.length}</b> of <b>{total}</b> alert signatures</span></div>
      <div className="overview-table-scroll"><table className="overview-table incident-table"><thead><tr><th>Severity</th><th>Incident</th><th>Attacking IP</th><th>Risk</th><th>Triggered</th><th>Status</th><th>Actions</th></tr></thead><tbody>{alerts.length ? alerts.map((alert) => <tr key={alert.id} className="incident-selectable" onClick={() => setSelected(alert)}><td><Badge kind={String(alert.severity).toLowerCase()}>{alert.severity}</Badge></td><td><button type="button" className="incident-open" onClick={(event) => { event.stopPropagation(); setSelected(alert); }}><strong>{alert.threat_type} <small className="incident-id">INC-{alert.id}</small></strong><small>{alert.description}</small></button></td><td className="font-mono">{attackingIp(alert)}</td><td><div className="incident-risk"><span><i style={{ width: `${Math.min(100, alert.risk_score || 0)}%`, background: colors[alert.severity] || '#3b82f6' }} /></span><b>{alert.risk_score || 0}</b><small>{alert.confidence || 0}%</small></div></td><td className="font-mono">{new Date(alert.timestamp).toLocaleString()}</td><td><Badge kind={alert.status}>{alert.status.replace('_', ' ')}</Badge></td><td><div className="incident-actions"><button type="button" aria-label={`Inspect incident ${alert.id}`} title="Inspect incident" onClick={(event) => { event.stopPropagation(); setSelected(alert); }}><Eye size={17} /></button>{alert.status === 'active' && <button type="button" aria-label={`Resolve incident ${alert.id}`} title="Resolve incident" onClick={(event) => { event.stopPropagation(); updateStatus(alert, 'resolved'); }}><Check size={17} /></button>}</div></td></tr>) : <tr><td colSpan="7" className="incident-empty">No incidents match these filters.</td></tr>}</tbody></table></div>
      <div className="incident-pagination"><span>{total ? `${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, total)} of ${total}` : '0 incidents'}</span><div><button type="button" aria-label="Previous page" disabled={page === 1} onClick={() => setPage(page - 1)}><ChevronLeft size={17} /></button><span>Page {page} of {pages}</span><button type="button" aria-label="Next page" disabled={page === pages} onClick={() => setPage(page + 1)}><ChevronRight size={17} /></button></div></div>
    </section>
    {selected && <div className="incident-drawer-layer"><button type="button" className="incident-drawer-scrim" aria-label="Close incident details" onClick={() => setSelected(null)} /><aside className="incident-drawer" role="dialog" aria-modal="true" aria-label={`Incident ${selected.id} details`}>
      <div className="incident-drawer-head"><div><div className="incident-drawer-label">INC-{selected.id} <Badge kind={String(selected.severity).toLowerCase()}>{selected.severity}</Badge> <Badge kind={selected.status}>{selected.status.replace('_', ' ')}</Badge></div><h2>{selected.threat_type}</h2><p>{selected.description}</p></div><button type="button" aria-label="Close details" onClick={() => setSelected(null)}><X size={19} /></button></div>
      <div className="incident-drawer-body"><div className="incident-drawer-risk"><span>Risk score</span><strong>{selected.risk_score || 0} <small>/ 100 · {selected.confidence || 0}% confidence</small></strong><div><i style={{ width: `${Math.min(100, selected.risk_score || 0)}%`, background: colors[selected.severity] || '#3b82f6' }} /></div></div><div className="incident-details"><div><span>Attacking IP</span><b>{attackingIp(selected)}</b></div><div><span>Triggered</span><b>{new Date(selected.timestamp).toLocaleString()}</b></div><div><span>Detection rule</span><b>{selected.rule_triggered || 'Not specified'}</b></div></div><h3>Matched payload</h3><pre>{selected.log_event?.message || selected.evidence || 'No raw event is linked to this alert.'}</pre>{selected.recommended_action && <><h3>Recommended action</h3><p className="incident-recommendation">{selected.recommended_action}</p></>}</div>
      <div className="incident-drawer-actions">{selected.status === 'active' ? <><button type="button" className="incident-resolve" onClick={() => updateStatus(selected, 'resolved')}><Check size={17} />Resolve</button><button type="button" onClick={() => updateStatus(selected, 'false_positive')}><Shield size={17} />Mark false positive</button></> : <span>This incident has been triaged.</span>}</div>
    </aside></div>}
  </div>;
}
