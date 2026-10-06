import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, RefreshCw, X, SlidersHorizontal, Terminal, Calendar, User, Activity, AlertOctagon } from 'lucide-react';
import api from '../services/api';
import Button from '../components/Button';
import { formatUtcDateTime } from '../utils/datetime';

const EventExplorer = () => {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [submittedSearch, setSubmittedSearch] = useState('');
  
  // Filtering States
  const [level, setLevel] = useState('');
  const [service, setService] = useState('');
  const [classification, setClassification] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const limit = 50;

  // Selected Log Drawer
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Discard stale responses when filters change faster than requests resolve.
  const requestSeq = useRef(0);

  // Support deep links from the top-nav search (e.g. /explorer?q=192.168.1.55).
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const q = searchParams.get('q');
    if (q) {
      setSearch(q);
      setSubmittedSearch(q);
      setPage(1);
    }
  }, [searchParams]);

  const getSourceIp = (event) => event?.source_ip || event?.ip_address || event?.src_ip || 'Unavailable';

  const fetchEvents = useCallback(async () => {
    const seq = ++requestSeq.current;
    setLoading(true);
    try {
      const skip = (page - 1) * limit;
      const params = {
        skip,
        limit,
        search: submittedSearch || undefined,
        level: level || undefined,
        service: service || undefined,
        classification: classification || undefined,
        ip_address: ipAddress || undefined
      };

      const response = await api.get('/api/logs/events', { params });
      if (seq === requestSeq.current) {
        setEvents(response.data.results);
        setTotal(response.data.total);
      }
    } catch (err) {
      console.error('Failed to load log events', err);
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [page, level, service, classification, ipAddress, submittedSearch]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    setSubmittedSearch(search);
  };

  const clearFilters = () => {
    setLevel('');
    setService('');
    setClassification('');
    setIpAddress('');
    setSearch('');
    setSubmittedSearch('');
    setPage(1);
  };

  const getLevelBadgeClass = (lvl) => {
    switch (lvl) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'ERROR': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'WARN': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'INFO': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      default: return 'bg-slate-100 text-slate-9000 border-slate-200';
    }
  };

  const getClassificationBadgeClass = (cls) => {
    if (cls === 'clean') return 'bg-slate-100 text-slate-9000';
    return 'bg-danger/10 text-danger border border-danger/25 font-bold';
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-4 max-w-7xl mx-auto relative min-h-[80vh]">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-800">Event Explorer</h1>
          <p className="text-sm text-slate-9000 mt-1">Audit trail of all parsed log files. Search and filter events in real-time.</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border rounded-lg transition-colors ${
              showFilters
                ? 'bg-primary text-white border-primary shadow-lg shadow-primary/20'
                : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
            }`}
          >
            <SlidersHorizontal size={14} />
            <span>Filters</span>
          </button>
          <button
            onClick={fetchEvents}
            disabled={loading}
            className="flex items-center justify-center p-2 bg-white border border-slate-200 rounded-lg text-slate-9000 hover:text-slate-800"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Filter and Search Panel */}
      <div className="bg-white border border-slate-200 rounded-2xl p-4 space-y-4">
        <form onSubmit={handleSearchSubmit} className="flex gap-3">
          <div className="relative flex-1">
            <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-9000 pointer-events-none">
              <Search size={16} />
            </span>
            <input
              type="text"
              placeholder="Search log messages, request paths, status codes..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs placeholder-slate-500 text-slate-800 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all duration-200 font-medium"
            />
          </div>
          <Button type="submit" className="px-5 text-xs py-2">
            Search
          </Button>
        </form>

        {showFilters && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 pt-3 border-t border-slate-200/60">
            {/* Level Selector */}
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-slate-9000 uppercase tracking-wider">Log Level</label>
              <select
                value={level}
                onChange={(e) => { setLevel(e.target.value); setPage(1); }}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-primary"
              >
                <option value="">All Levels</option>
                <option value="INFO">INFO</option>
                <option value="WARN">WARNING</option>
                <option value="ERROR">ERROR</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>

            {/* Service Source Selector */}
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-slate-9000 uppercase tracking-wider">Service Source</label>
              <select
                value={service}
                onChange={(e) => { setService(e.target.value); setPage(1); }}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-primary"
              >
                <option value="">All Services</option>
                <option value="sshd">sshd (SSH Logins)</option>
                <option value="web-server">web-server (HTTP Access)</option>
                <option value="system">system logs</option>
              </select>
            </div>

            {/* Classification Selector */}
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-slate-9000 uppercase tracking-wider">Security Classification</label>
              <select
                value={classification}
                onChange={(e) => { setClassification(e.target.value); setPage(1); }}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-primary"
              >
                <option value="">All Traffic</option>
                <option value="clean">Clean Traffic</option>
                <option value="failed_login">Failed Logins</option>
                <option value="repeated_failed_login">Brute Force Alerts</option>
                <option value="sql_injection">SQL Injection Alerts</option>
                <option value="xss">XSS Alerts</option>
                <option value="directory_traversal">Traversal Alerts</option>
                <option value="command_injection">Command Injection</option>
                <option value="malware_indicator">Malware Indicators</option>
                <option value="privilege_escalation">Privilege Escalation</option>
                <option value="port_scan">Scanning Anomalies</option>
                <option value="suspicious_authentication">Suspicious Auth</option>
              </select>
            </div>

            {/* IP address filter */}
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-slate-9000 uppercase tracking-wider">Client IP Address</label>
              <input
                type="text"
                placeholder="E.g. 192.168.1.1"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                onBlur={() => { setPage(1); fetchEvents(); }}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-800 focus:outline-none focus:border-primary placeholder-slate-650"
              />
            </div>
            
            <div className="sm:col-span-2 md:col-span-4 flex justify-end">
              <button
                type="button"
                onClick={clearFilters}
                className="text-xs text-slate-9000 hover:text-slate-800 underline font-medium"
              >
                Clear all filters
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Log Events Table */}
      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="py-24 text-center text-xs text-slate-9000 flex flex-col items-center justify-center gap-2">
            <RefreshCw className="animate-spin text-primary" size={24} />
            Querying SIEM database...
          </div>
        ) : events.length === 0 ? (
          <div className="py-24 text-center text-xs text-slate-9000 flex flex-col items-center justify-center gap-2">
            <Terminal size={36} className="text-slate-700 stroke-[1.5]" />
            No events match your search filters. Try updating parameters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-100/30 text-slate-9000 uppercase tracking-wider text-[10px]">
                  <th className="px-5 py-3 font-semibold w-[160px]">Timestamp</th>
                  <th className="px-5 py-3 font-semibold w-[100px]">Level</th>
                  <th className="px-5 py-3 font-semibold w-[100px]">Service</th>
                  <th className="px-5 py-3 font-semibold w-[130px]">Source IP</th>
                  <th className="px-5 py-3 font-semibold">Event Message</th>
                  <th className="px-5 py-3 font-semibold w-[140px]">Classification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {events.map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => setSelectedEvent(event)}
                    className="hover:bg-slate-100/25 text-slate-700 cursor-pointer transition-colors duration-100"
                  >
                    <td className="px-5 py-3 font-mono text-[10px] text-slate-9000">
                      {formatUtcDateTime(event.timestamp)}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[9px] font-extrabold border ${getLevelBadgeClass(event.level)}`}>
                        {event.level}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-semibold text-slate-9000">{event.service}</td>
                    <td className="px-5 py-3 font-mono font-bold text-slate-800">{getSourceIp(event)}</td>
                    <td className="px-5 py-3 truncate max-w-sm font-medium text-slate-800" title={event.message}>
                      {event.message}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex px-1.5 py-0.5 rounded text-[9px] font-medium border border-transparent ${getClassificationBadgeClass(event.classification)}`}>
                        {event.classification.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Console */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-slate-200 flex justify-between items-center text-xs text-slate-9000 bg-slate-100/10">
            <div>
              Showing <span className="font-semibold text-slate-800">{(page - 1) * limit + 1}</span> to{' '}
              <span className="font-semibold text-slate-800">{Math.min(page * limit, total)}</span> of{' '}
              <span className="font-semibold text-slate-800">{total}</span> events
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => setPage(p => Math.max(p - 1, 1))}
                disabled={page === 1}
                className="px-3 py-1.5 text-xs font-semibold"
              >
                Previous
              </Button>
              <Button
                variant="secondary"
                onClick={() => setPage(p => Math.min(p + 1, totalPages))}
                disabled={page === totalPages}
                className="px-3 py-1.5 text-xs font-semibold"
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Selected Event Details Drawer */}
      {selectedEvent && (
        <>
          {/* Overlay background */}
          <div
            className="fixed inset-0 bg-slate-700/60 backdrop-blur-xs z-40 transition-opacity"
            onClick={() => setSelectedEvent(null)}
          />
          
          {/* Details Sidebar Slider */}
          <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[500px] bg-white border-l border-slate-200 flex flex-col shadow-2xl animate-[slideLeft_0.25s_ease-out]">
            {/* Drawer Header */}
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-100/20">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-800">Log Entry Analysis</h3>
                <span className="text-[9px] text-slate-9000 font-mono">ID: {selectedEvent.id}</span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 rounded-lg text-slate-9000 hover:bg-slate-50 hover:text-slate-800"
              >
                <X size={16} />
              </button>
            </div>

            {/* Drawer Body content */}
            <div className="flex-1 p-6 space-y-6 overflow-y-auto">
              {/* Field grids */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider flex items-center gap-1">
                    <Calendar size={11} /> Timestamp
                  </span>
                  <p className="text-xs font-mono text-slate-700">{formatUtcDateTime(selectedEvent.timestamp)}</p>
                </div>
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider flex items-center gap-1">
                    <Activity size={11} /> Log Level
                  </span>
                  <div>
                    <span className={`inline-flex px-2 py-0.5 border rounded text-[9px] font-bold ${getLevelBadgeClass(selectedEvent.level)}`}>
                      {selectedEvent.level}
                    </span>
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider flex items-center gap-1">
                    <User size={11} /> Client IP
                  </span>
                  <p className="text-xs font-mono font-bold text-slate-800">{getSourceIp(selectedEvent)}</p>
                </div>
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider flex items-center gap-1">
                    <AlertOctagon size={11} /> Classification
                  </span>
                  <div>
                    <span className={`inline-flex px-1.5 py-0.5 rounded text-[9px] font-bold ${getClassificationBadgeClass(selectedEvent.classification)}`}>
                      {selectedEvent.classification.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Service block */}
              <div className="border-t border-slate-200/80 pt-4 space-y-1.5">
                <h4 className="text-[10px] text-slate-550 font-bold uppercase tracking-wider">Service Source</h4>
                <p className="text-xs text-slate-700 font-semibold">{selectedEvent.service}</p>
              </div>

              {/* Web-specific HTTP metadata properties */}
              {selectedEvent.service === 'web-server' && (
                <div className="border-t border-slate-200/80 pt-4 space-y-4">
                  <h4 className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider">HTTP Web Properties</h4>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="text-[10px] text-slate-9000 block">Method</span>
                      <span className="font-bold font-mono text-primary">{selectedEvent.method || '-'}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-9000 block">Response Status</span>
                      <span className={`font-bold ${
                        selectedEvent.status_code >= 400 ? 'text-danger' : 'text-success'
                      }`}>{selectedEvent.status_code || '-'}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-[10px] text-slate-9000 block">Request Path</span>
                      <span className="font-mono text-slate-700 bg-slate-50/55 px-2 py-1.5 rounded block mt-1 break-all border border-slate-200">
                        {selectedEvent.path || '-'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Raw log message box */}
              <div className="border-t border-slate-200/80 pt-4 space-y-2">
                <h4 className="text-[10px] text-slate-9000 font-bold uppercase tracking-wider">Full Message String</h4>
                <div className="p-4 bg-slate-700 border border-slate-200 rounded-xl max-h-56 overflow-y-auto">
                  <pre className="text-[10px] font-mono text-slate-700 whitespace-pre-wrap break-all leading-relaxed">
                    {selectedEvent.message}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default EventExplorer;
