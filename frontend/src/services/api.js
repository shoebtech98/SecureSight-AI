import axios from 'axios';
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});


// Add a request interceptor to attach JWT token if present
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token') || sessionStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor to handle common errors like 401 Unauthorized
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const requestAuthorization = error.config?.headers?.Authorization;
      const currentToken = localStorage.getItem('token') || sessionStorage.getItem('token');
      // A late 401 from an older session must not sign out a newer login.
      if (requestAuthorization !== `Bearer ${currentToken}` || !currentToken) {
        return Promise.reject(error);
      }
      localStorage.removeItem('token');
      sessionStorage.removeItem('token');
      // If we are not already on the login/register/forgot-password pages, we redirect to login
      const currentPath = window.location.pathname;
      if (!['/login', '/register', '/forgot-password'].includes(currentPath)) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
