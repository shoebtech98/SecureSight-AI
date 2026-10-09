import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Bell, ChevronDown, ChevronRight, FileBarChart, LayoutDashboard,
  LogOut, Menu, Search, Settings, Shield, Sparkles, Upload, X,
} from 'lucide-react';
import api from '../services/api';
import ThemeToggle from '../components/ThemeToggle';
import { getProfilePhoto } from '../utils/profilePhoto';

const groups = [
  { label: 'Overview', items: [{ name: 'Dashboard', path: '/', icon: LayoutDashboard }] },
  { label: 'Detection & Response', items: [
    { name: 'Threat Monitor', path: '/threats', icon: AlertTriangle },
    { name: 'Event Explorer', path: '/explorer', icon: Search },
    { name: 'AI Assistant', path: '/ai-assistant', icon: Sparkles },
  ] },
  { label: 'Data', items: [
    { name: 'Upload Logs', path: '/upload', icon: Upload },
    { name: 'Reports', path: '/reports', icon: FileBarChart },
  ] },
];

const titles = { '/': 'Dashboard', '/threats': 'Threat Monitor', '/explorer': 'Event Explorer', '/ai-assistant': 'AI Assistant', '/upload': 'Upload Logs', '/reports': 'Reports', '/settings': 'Settings' };

export default function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [user, setUser] = useState(null);
  const [profilePhoto, setProfilePhoto] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [search, setSearch] = useState('');
  const searchRef = useRef(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    api.get('/api/auth/me').then(({ data }) => { if (active) { setUser(data); setProfilePhoto(getProfilePhoto(data.id)); } }).catch(() => {});
    api.get('/api/dashboard/stats').then(({ data }) => {
      if (active) { setSummary(data); setAlerts(data.recent_threats || []); }
    }).catch(() => {});
    return () => { active = false; };
  }, [location.pathname]);

  useEffect(() => {
    const syncProfile = (event) => {
      setProfilePhoto((current) => event.detail.userId === user?.id ? event.detail.imageData : current);
    };
    window.addEventListener('securesight:profile-updated', syncProfile);
    return () => window.removeEventListener('securesight:profile-updated', syncProfile);
  }, [user?.id]);

  useEffect(() => {
    const focusSearch = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, []);

  const logout = () => {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    navigate('/login');
  };

  const submitSearch = (event) => {
    event.preventDefault();
    navigate(search.trim() ? `/explorer?q=${encodeURIComponent(search.trim())}` : '/explorer');
    setSearch('');
  };

  const navItem = ({ name, path, icon: Icon }) => (
    <NavLink key={path} to={path} end={path === '/'} onClick={() => setSidebarOpen(false)}
      className={({ isActive }) => `workspace-nav-link ${isActive ? 'is-active' : ''}`}>
      <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
      <span>{name}</span>
      {path === '/threats' && summary?.active_threats > 0 && <span className="workspace-nav-count">{summary.active_threats}</span>}
    </NavLink>
  );

  return (
    <div className="workspace-shell">
      {sidebarOpen && <button type="button" className="workspace-mobile-scrim" aria-label="Close menu" onClick={() => setSidebarOpen(false)} />}
      <aside className={`workspace-sidebar ${sidebarOpen ? 'is-open' : ''}`}>
        <div className="workspace-brand-row">
          <Link to="/" className="workspace-brand" onClick={() => setSidebarOpen(false)}>
            <span className="workspace-brand-mark"><Shield size={21} aria-hidden="true" /></span>
            <span>SecureSight AI</span>
          </Link>
          <span className="workspace-env">{import.meta.env.PROD ? 'PROD' : 'DEV'}</span>
          <button type="button" className="workspace-close" aria-label="Close menu" onClick={() => setSidebarOpen(false)}><X size={19} /></button>
        </div>
        <nav className="workspace-nav" aria-label="Main navigation">
          {groups.map((group) => <div className="workspace-nav-group" key={group.label}>
            <p className="workspace-nav-heading">{group.label}</p>
            {group.items.map(navItem)}
          </div>)}
        </nav>
        <div className="workspace-sidebar-bottom">
          <div className="workspace-health">
            <span><i />Workspace ready</span>
            <small>{summary ? `${summary.total_files} source ${summary.total_files === 1 ? 'file' : 'files'} ingested` : 'Loading source status…'}</small>
          </div>
          {navItem({ name: 'Settings', path: '/settings', icon: Settings })}
          <button type="button" className="workspace-nav-link" onClick={logout}><LogOut size={18} /><span>Logout</span></button>
        </div>
      </aside>

      <div className="workspace-main">
        <header className="workspace-header">
          <div className="workspace-breadcrumb">
            <button type="button" className="workspace-menu-button" aria-label="Open menu" onClick={() => setSidebarOpen(true)}><Menu size={20} /></button>
            <span>Workspace</span><ChevronRight size={16} /><strong>{titles[location.pathname] || 'Workspace'}</strong>
          </div>
          <form className="workspace-global-search" onSubmit={submitSearch} role="search">
            <Search size={18} aria-hidden="true" />
            <input ref={searchRef} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search events and IPs..." aria-label="Search events and IPs" />
            <kbd>Ctrl K</kbd>
          </form>
          <div className="workspace-header-actions">
            <ThemeToggle />
            <div className="workspace-popover-anchor">
              <button type="button" className="workspace-icon-button" aria-label="Recent alerts" aria-expanded={notificationsOpen} onClick={() => { setNotificationsOpen(!notificationsOpen); setProfileOpen(false); }}><Bell size={19} />{alerts.length > 0 && <i />}</button>
              {notificationsOpen && <div className="workspace-popover workspace-alert-popover">
                <strong>Recent alerts</strong>
                {alerts.length ? alerts.slice(0, 5).map((alert) => <Link to="/threats" key={alert.id} onClick={() => setNotificationsOpen(false)}><b>{alert.threat_type}</b><small>{alert.description}</small></Link>) : <p>No recent alerts.</p>}
                <Link to="/threats" onClick={() => setNotificationsOpen(false)}>View all alerts</Link>
              </div>}
            </div>
            <span className="workspace-header-divider" />
            <div className="workspace-popover-anchor">
              <button type="button" className="workspace-profile-trigger" aria-expanded={profileOpen} onClick={() => { setProfileOpen(!profileOpen); setNotificationsOpen(false); }}>
                <span className="workspace-avatar">{profilePhoto ? <img src={profilePhoto} alt="" /> : user?.full_name?.charAt(0)?.toUpperCase() || 'S'}</span>
                <span className="workspace-profile-text"><strong>{user?.full_name || 'Account'}</strong><small>Security Analyst</small></span>
                <ChevronDown size={15} />
              </button>
              {profileOpen && <div className="workspace-popover workspace-profile-popover"><Link to="/settings" onClick={() => setProfileOpen(false)}>Account settings</Link><button type="button" onClick={logout}>Sign out</button></div>}
            </div>
          </div>
        </header>
        <main className="workspace-content"><Outlet /></main>
      </div>
    </div>
  );
}
