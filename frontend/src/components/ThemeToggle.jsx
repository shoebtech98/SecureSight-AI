import React, { useState } from 'react';
import { Moon, Sun } from 'lucide-react';

/**
 * Dark / light theme toggle. Flips the `dark` class on <html> and persists the
 * choice in localStorage ('ss-theme'). Works anywhere in the app; the persisted
 * value is applied before first paint by an inline script in index.html.
 */
const ThemeToggle = ({ className = '' }) => {
  const [dark, setDark] = useState(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
  );

  const toggleTheme = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle('dark', next);
    try {
      localStorage.setItem('ss-theme', next ? 'dark' : 'light');
    } catch {
      // Storage unavailable — theme still applies for this session.
    }
  };

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      className={`p-2 rounded-lg text-slate-800 hover:bg-slate-50 hover:text-slate-700 transition-colors ${className}`}
    >
      {dark ? <Sun size={18} /> : <Moon size={18} />}
    </button>
  );
};

export default ThemeToggle;
