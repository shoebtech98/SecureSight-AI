import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowUpRight, FileText, RefreshCw, ShieldAlert } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import api from '../services/api';

const palette = ['#f59e0b', '#ef4444', '#06b6d4', '#7c3aed', '#10b981'];
const attackColors = {
  'Directory Traversal': '#f59e0b',
  'SQL Injection': '#ef4444',
  'Cross-Site Scripting': '#06b6d4',
  'Cross Site Scripting': '#06b6d4',
  'Command Injection': '#7c3aed',
};

const calendarKey = (date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

function recentCalendarDays(count) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Array.from({ length: count }, (_, index) => {
    const day = new Date(today);
    day.setDate(today.getDate() - count + index + 1);
    return calendarKey(day);
  });
}

function Metric({ label, value, caption, icon: Icon, color }) {
  return <div className="overview-metric">
    <div className="overview-metric-top"><span>{label}</span><span className={`overview-metric-icon ${color}`}><Icon size={19} /></span></div>
    <strong>{Number(value || 0).toLocaleString()}</strong>
    <small>{caption}</small>
  </div>;
}

function SingleDayDot({ cx, cy, stroke }) {
  if (!Number.isFinite(cx) || !Number.isFinite(cy)) return null;
  return <g><line x1={cx - 22} x2={cx + 22} y1={cy} y2={cy} stroke={stroke} strokeWidth="3" strokeLinecap="round" /><circle cx={cx} cy={cy} r="5" fill={stroke} stroke="#fff" strokeWidth="2" /></g>;
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [chartVersion, setChartVersion] = useState(0);
  const [undatedLabel, setUndatedLabel] = useState('Uploaded logs');
  const [timelineRange, setTimelineRange] = useState(7);

  const fetchStats = async () => {
    try {
      setError('');
      const response = await api.get('/api/dashboard/stats');
      setStats(response.data);
      if (response.data.total_events > 0 && !response.data.events_over_time?.length && !response.data.threat_timeline?.length) {
        try {
          const files = (await api.get('/api/logs/files')).data.filter((file) => file.status === 'parsed');
          const uploadedAt = files.length === 1 && files[0].uploaded_at;
          const uploadTime = uploadedAt && new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(uploadedAt) ? uploadedAt : `${uploadedAt}Z`);
          const uploadDay = response.data.total_files === 1 && uploadTime && !Number.isNaN(uploadTime.valueOf()) && calendarKey(uploadTime);
          setUndatedLabel(/^\d{4}-\d{2}-\d{2}$/.test(uploadDay || '') ? uploadDay : 'Uploaded logs');
        } catch {
          setUndatedLabel('Uploaded logs');
        }
      } else {
        setUndatedLabel('Uploaded logs');
      }
      setChartVersion((version) => version + 1);
    } catch {
      setError('Could not load the dashboard. Try refreshing.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { fetchStats(); }, []);

  const timeline = useMemo(() => {
    const days = new Map();
    for (const item of stats?.events_over_time || []) days.set(item.date, { date: item.date, events: item.events, threats: 0 });
    for (const item of stats?.threat_timeline || []) {
      const day = days.get(item.date) || { date: item.date, events: 0, threats: 0 };
      day.threats = item.threats;
      days.set(item.date, day);
    }
    return [...days.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)));
  }, [stats]);
  const undatedOnly = (stats?.total_events || 0) > 0 && timeline.length === 0;
  const chartDays = recentCalendarDays(timelineRange);
  const visibleTimeline = timeline.filter((day) => day.date >= chartDays[0]);
  const datedDays = new Map(visibleTimeline.map((day) => [day.date, day]));
  const chartData = undatedOnly
    ? undatedLabel === 'Uploaded logs'
      ? [{ date: undatedLabel, events: stats.total_events, threats: stats.total_threats }]
      : chartDays.map((date) => ({
        date,
        events: date >= undatedLabel ? stats.total_events : 0,
        threats: date >= undatedLabel ? stats.total_threats : 0,
      }))
    : timelineRange === 7
      ? chartDays.map((date) => datedDays.get(date) || { date, events: 0, threats: 0 })
      : visibleTimeline;
  const datedEvents = timeline.reduce((sum, day) => sum + day.events, 0);
  const chartDescription = undatedOnly
    ? undatedLabel === 'Uploaded logs'
      ? 'Source events have no timestamps; showing totals for uploaded logs.'
      : 'Daily cumulative ingestion; source event times are unavailable.'
    : datedEvents < (stats?.total_events || 0)
      ? `${datedEvents.toLocaleString()} of ${stats.total_events.toLocaleString()} events have timestamps; undated events are excluded.`
      : timelineRange === 30
        ? 'Daily events and threats from up to 15 recent event dates.'
        : 'Log events processed vs. threats detected per day';
  const animateChart = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (loading) return <div className="overview-loading"><RefreshCw size={22} className="animate-spin" />Loading security overview…</div>;

  if (!stats) return <div className="overview-panel overview-empty" role="alert"><ShieldAlert size={32} /><h2>Dashboard unavailable</h2><p>{error || 'Could not load your security data.'}</p><button type="button" className="overview-action" onClick={() => { setLoading(true); fetchStats(); }}>Try again</button></div>;

  const attacks = [...(stats?.threat_type_distribution || [])].sort((a, b) => b.value - a.value);
  const maxAttack = Math.max(1, ...attacks.map((item) => item.value));
  const recent = stats?.recent_threats || [];
  const metrics = [
    { label: 'Events ingested', value: stats?.total_events, caption: `${stats.total_files} source ${stats.total_files === 1 ? 'file' : 'files'} processed`, icon: FileText, color: 'blue' },
    { label: 'Threats detected', value: stats?.total_threats, caption: `${stats?.total_events ? ((stats.total_threats / stats.total_events) * 100).toFixed(1) : 0}% of events`, icon: ShieldAlert, color: 'red' },
    { label: 'Active incidents', value: stats?.active_threats, caption: 'Awaiting analyst triage', icon: AlertTriangle, color: 'orange' },
    { label: 'Critical alerts', value: stats?.critical_alerts, caption: `${stats?.total_threats ? Math.round((stats.critical_alerts / stats.total_threats) * 100) : 0}% of incidents`, icon: Activity, color: 'red' },
  ];

  return <div className="overview-page">
    <div className="overview-heading">
      <div><h1>Security Overview</h1><p>Real-time parsed events, log distributions, and security alert intelligence.</p></div>
      <div className="overview-heading-actions">
        <div className="overview-period" role="group" aria-label="Activity timeline period">
          <button type="button" disabled title="Hourly timeline data is not available">24h</button>
          {[7, 30].map((days) => <button key={days} type="button" className={timelineRange === days ? 'is-active' : ''} onClick={() => { setTimelineRange(days); setChartVersion((version) => version + 1); }} disabled={undatedOnly && undatedLabel === 'Uploaded logs'} title={undatedOnly && undatedLabel === 'Uploaded logs' ? 'Upload dates are unavailable for this view' : `Show the last ${days} days`}>{days}d</button>)}
        </div>
        <button type="button" className="overview-action" onClick={() => { setRefreshing(true); fetchStats(); }} disabled={refreshing}><RefreshCw size={17} className={refreshing ? 'animate-spin' : ''} />Refresh</button>
      </div>
    </div>
    {error && <div className="overview-error" role="alert">{error}</div>}
    <div className="overview-metrics">{metrics.map((item) => <Metric key={item.label} {...item} />)}</div>
    {!stats?.total_files ? <div className="overview-panel overview-empty"><ShieldAlert size={32} /><h2>No log data yet</h2><p>Upload a log file to populate your security overview and detection timeline.</p><Link to="/upload">Upload logs <ArrowUpRight size={16} /></Link></div> : <>
      <div className="overview-grid">
        <section className="overview-panel overview-chart-panel">
          <div className="overview-panel-head"><div><h2>Activity timeline</h2><p>{chartDescription}</p></div><div className="overview-legend"><span><i className="blue" />Events</span><span><i className="red" />Threats</span></div></div>
          {chartData.length ? <div className="overview-chart" key={chartVersion}><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{ top: 18, right: 16, left: -12, bottom: 5 }}>
            <defs>
              <linearGradient id="overview-events-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#2563eb" stopOpacity=".18" /><stop offset="100%" stopColor="#2563eb" stopOpacity=".02" /></linearGradient>
              <linearGradient id="overview-threats-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity=".16" /><stop offset="100%" stopColor="#ef4444" stopOpacity=".02" /></linearGradient>
            </defs>
            <CartesianGrid stroke="#e1e7f0" strokeDasharray="3 4" vertical={false} />
            <XAxis dataKey="date" interval={timelineRange === 7 ? 0 : 'preserveStartEnd'} tickLine={false} axisLine={false} tick={{ fill: '#8290a6', fontSize: 12 }} tickFormatter={(value) => { if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return value; const date = new Date(`${value}T00:00:00`); return Number.isNaN(date.valueOf()) ? value : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); }} />
            <YAxis tickLine={false} axisLine={false} tickCount={5} domain={[0, 'auto']} tick={{ fill: '#8290a6', fontSize: 12 }} />
            <Tooltip contentStyle={{ border: '1px solid #dce3eb', borderRadius: 9, boxShadow: '0 10px 25px #15233b18' }} />
            <Area type="monotone" dataKey="events" name="Events" stroke="#2563eb" strokeWidth={2.5} fill="url(#overview-events-fill)" dot={chartData.length === 1 ? <SingleDayDot stroke="#2563eb" /> : false} activeDot={{ r: 5 }} isAnimationActive={animateChart} animationBegin={100} animationDuration={1100} animationEasing="ease-out" />
            <Area type="monotone" dataKey="threats" name="Threats" stroke="#ef4444" strokeWidth={2.3} fill="url(#overview-threats-fill)" dot={chartData.length === 1 ? <SingleDayDot stroke="#ef4444" /> : false} activeDot={{ r: 5 }} isAnimationActive={animateChart} animationBegin={250} animationDuration={1100} animationEasing="ease-out" />
          </AreaChart></ResponsiveContainer></div> : <div className="overview-chart-empty">No timestamped events in the selected period.</div>}
        </section>
        <section className="overview-panel">
          <div className="overview-panel-head"><div><h2>Top attack types</h2><p>Incidents by detection signature</p></div></div>
          <div className="overview-attacks">{attacks.length ? attacks.slice(0, 5).map((item, index) => <div key={item.name} className="overview-attack">
            <div><span><i style={{ backgroundColor: attackColors[item.name] || palette[index % palette.length] }} />{item.name}</span><strong>{item.value.toLocaleString()} <small>{stats.total_threats ? Math.round(item.value / stats.total_threats * 100) : 0}%</small></strong></div>
            <span className="overview-attack-track"><span style={{ width: `${item.value / maxAttack * 100}%`, backgroundColor: attackColors[item.name] || palette[index % palette.length] }} /></span>
          </div>) : <p className="overview-muted">No attack types detected.</p>}</div>
        </section>
      </div>
      <div className="overview-grid overview-lower-grid">
        <section className="overview-panel">
          <div className="overview-panel-head"><div><h2>Highest-risk alerts</h2><p>Recent incidents requiring review</p></div><Link to="/threats">View all <ArrowUpRight size={15} /></Link></div>
          <div className="overview-table-scroll"><table className="overview-table"><thead><tr><th>Severity</th><th>Alert</th><th>Source IP</th><th>Risk</th><th>Status</th></tr></thead><tbody>{recent.length ? [...recent].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 5).map((alert) => <tr key={alert.id}><td><span className={`overview-severity ${String(alert.severity).toLowerCase()}`}>{alert.severity}</span></td><td><strong>{alert.threat_type}</strong><small>{alert.description}</small></td><td className="font-mono">{alert.source_ip || 'Not captured'}</td><td>{alert.risk_score || 0}</td><td>{alert.status.replace('_', ' ')}</td></tr>) : <tr><td colSpan="5">No recent alerts.</td></tr>}</tbody></table></div>
        </section>
        <section className="overview-panel">
          <div className="overview-panel-head"><div><h2>Signal health</h2><p>Security signals from uploaded logs</p></div></div>
          <div className="overview-signals"><div><span>High-risk IPs</span><strong>{stats.high_risk_ips || 0}</strong></div><div><span>Brute-force attempts</span><strong>{stats.brute_force_attempts || 0}</strong></div><div><span>Authentication failures</span><strong>{stats.authentication_failures || 0}</strong></div><div><span>SQL injection attempts</span><strong>{stats.sql_injection_attempts || 0}</strong></div></div>
        </section>
      </div>
    </>}
  </div>;
}
