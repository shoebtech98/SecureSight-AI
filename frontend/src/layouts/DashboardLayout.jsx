import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation, Outlet } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Upload,
  Search,
  AlertTriangle,
  Sparkles,
  FileBarChart,
  Settings,
  LogOut,
  Bell,
  User as UserIcon,
  Menu,
  X,
  ChevronDown
} from 'lucide-react';
import api from '../services/api';
import ThemeToggle from '../components/ThemeToggle';

const DashboardLayout = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [user, setUser] = useState(null);
  
  const navigate = useNavigate();
  const location = useLocation();
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [globalSearch, setGlobalSearch] = useState('');

  // Top-nav search: run the query inside the Event Explorer.
  const handleGlobalSearch = (e) => {
    e.preventDefault();
    const q = globalSearch.trim();
    navigate(q ? `/explorer?q=${encodeURIComponent(q)}` : '/explorer');
    setGlobalSearch('');
  };

  useEffect(() => {
    // Fetch profile info for top navigation
    const fetchProfile = async () => {
      try {
        const response = await api.get('/api/auth/me');
        setUser(response.data);
      } catch {
        console.error('Failed to load user profile in layout');
      }
    };
    // Fetch the latest alerts for the notification bell
    const fetchRecentAlerts = async () => {
      try {
        const response = await api.get('/api/dashboard/stats');
        setRecentAlerts(response.data.recent_threats || []);
      } catch {
        // Notifications are non-critical; ignore failures silently.
      }
    };
    fetchProfile();
    fetchRecentAlerts();
  }, [location.pathname]); // Update when routing changes

  const handleLogout = () => {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    navigate('/login');
  };

  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Upload Logs', path: '/upload', icon: Upload },
    { name: 'Event Explorer', path: '/explorer', icon: Search },
    { name: 'Threat Monitor', path: '/threats', icon: AlertTriangle },
    { name: 'AI Assistant', path: '/ai-assistant', icon: Sparkles },
    { name: 'Reports', path: '/reports', icon: FileBarChart },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const currentPath = location.pathname;

  return (
    <div className="min-h-screen bg-bg-main text-slate-800 flex font-sans">
      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-400/20 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* Sidebar Panel */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-slate-200/80 flex flex-col transform lg:translate-x-0 transition-transform duration-300 ease-in-out ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:relative lg:flex`}
      >
        {/* Sidebar Header */}
        <div className="h-16 flex items-center justify-between px-6 border-b border-slate-200/80">
          <Link to="/" className="flex items-center gap-2.5" onClick={() => setIsSidebarOpen(false)}>
            <div className="p-1.5 bg-primary/10 rounded-lg text-primary border border-primary/20">
              <Shield size={20} className="stroke-[2]" />
            </div>
            <span className="font-bold text-lg tracking-tight text-slate-900">
              SecureSight AI
            </span>
          </Link>
          <button
            onClick={() => setIsSidebarOpen(false)}
            className="lg:hidden text-slate-9000 hover:text-slate-800"
          >
            <X size={20} />
          </button>
        </div>

        {/* Navigation Menu */}
        <nav className="flex-1 px-4 py-6 space-y-1.5 overflow-y-auto">
          {menuItems.map((item) => {
            const isActive = currentPath === item.path;
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                to={item.path}
                onClick={() => setIsSidebarOpen(false)}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-primary text-white shadow-lg shadow-primary/25 border-l-4 border-white'
                    : 'text-slate-9000 hover:bg-slate-50/50 hover:text-slate-800'
                }`}
              >
                <Icon size={18} className={isActive ? 'text-white' : 'text-slate-9000'} />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer / Logout */}
        <div className="p-4 border-t border-slate-200/80">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium text-danger hover:bg-red-500/10 hover:text-red-400 transition-colors duration-150"
          >
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area Container */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen overflow-x-hidden">
        {/* Top Navigation Header */}
        <header className="h-16 bg-white/45 backdrop-blur-md border-b border-slate-200/80 flex items-center justify-between px-4 sm:px-6 sticky top-0 z-30">
          {/* Left: Mobile Toggle */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="lg:hidden p-2 rounded-lg text-slate-9000 hover:bg-slate-50 hover:text-slate-800 transition-colors"
            >
              <Menu size={20} />
            </button>

            {/* Global Search — opens the Event Explorer with the query applied */}
            <form onSubmit={handleGlobalSearch} className="hidden md:flex items-center relative w-64">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-9000 pointer-events-none">
                <Search size={16} />
              </span>
              <input
                type="text"
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
                placeholder="Search events, IPs, alerts..."
                className="w-full pl-9 pr-4 py-1.5 bg-slate-50 border border-slate-300/80 rounded-lg text-xs placeholder-slate-500 text-slate-800 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all duration-200"
              />
            </form>
          </div>

          {/* Right: Notifications, Settings & User Dropdown */}
          <div className="flex items-center gap-3">
            {/* Theme Toggle */}
            <ThemeToggle />

            {/* Notifications Dropdown Container */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="p-2 rounded-lg text-slate-9000 hover:bg-slate-50 hover:text-slate-800 transition-colors relative"
              >
                <Bell size={18} />
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-danger rounded-full ring-2 ring-bg-card" />
              </button>

              {notificationsOpen && (
                <>
                  <div className="fixed inset-0 z-30" onClick={() => setNotificationsOpen(false)} />
                  <div className="absolute right-0 mt-2 w-80 bg-white border border-slate-200 rounded-xl shadow-2xl z-40 py-2">
                    <div className="px-4 py-2 border-b border-slate-200 flex justify-between items-center">
                      <span className="font-semibold text-xs text-slate-800">Recent Alerts</span>
                      {recentAlerts.length > 0 && (
                        <span className="text-[10px] text-danger bg-danger/10 px-1.5 py-0.5 rounded font-bold">{recentAlerts.length}</span>
                      )}
                    </div>
                    <div className="max-h-60 overflow-y-auto">
                      {recentAlerts.length === 0 ? (
                        <div className="px-4 py-6 text-center text-[10px] text-slate-9000">
                          No recent alerts. System is clean.
                        </div>
                      ) : (
                        recentAlerts.map((alert) => (
                          <div key={alert.id} className="px-4 py-3 hover:bg-slate-50/50 border-b border-slate-200/40 cursor-pointer">
                            <p className="text-xs font-semibold text-slate-800">{alert.threat_type}</p>
                            <p className="text-[10px] text-slate-9000 mt-0.5">{alert.description}</p>
                            <span className="text-[9px] text-slate-9000 block mt-1">
                              {alert.source_ip || 'No IP'} · {new Date(alert.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        ))
                      )}
                    </div>
                    <div className="px-4 py-1.5 text-center border-t border-slate-200">
                      <Link to="/threats" onClick={() => setNotificationsOpen(false)} className="text-[11px] text-primary hover:text-blue-700 font-semibold">
                        View All Alerts
                      </Link>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Separator */}
            <div className="w-px h-5 bg-slate-100 hidden sm:block" />

            {/* Profile Dropdown Container */}
            <div className="relative">
              <button
                onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
                className="flex items-center gap-2.5 p-1.5 rounded-lg hover:bg-slate-50/80 transition-colors"
              >
                <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold text-sm">
                  {user ? user.full_name.charAt(0).toUpperCase() : <UserIcon size={16} />}
                </div>
                <div className="hidden sm:block text-left">
                  <p className="text-xs font-semibold text-slate-800">
                    {user ? user.full_name : 'Loading...'}
                  </p>
                  <p className="text-[10px] text-slate-9000">Security Analyst</p>
                </div>
                <ChevronDown size={14} className="text-slate-9000 hidden sm:block" />
              </button>

              {profileDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-30" onClick={() => setProfileDropdownOpen(false)} />
                  <div className="absolute right-0 mt-2 w-48 bg-white border border-slate-200 rounded-xl shadow-2xl z-40 py-1.5">
                    <Link
                      to="/settings"
                      onClick={() => setProfileDropdownOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-xs text-slate-700 hover:bg-slate-50/80 hover:text-slate-800"
                    >
                      <UserIcon size={14} />
                      Profile Settings
                    </Link>
                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        handleLogout();
                      }}
                      className="w-full flex items-center gap-2 px-4 py-2 text-xs text-danger hover:bg-red-500/10 hover:text-red-400 text-left"
                    >
                      <LogOut size={14} />
                      Sign Out
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Page Content viewport */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
