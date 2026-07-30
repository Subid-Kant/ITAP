// ITAP — Authentication Hook
// Manages JWT state, login/logout, and token refresh.
import { useState, useCallback, useEffect, createContext, useContext } from 'react';
import { api } from '../api';

const AuthContext = createContext(null);

const TOKEN_KEY = 'itap_access_token';
const REFRESH_KEY = 'itap_refresh_token';
const USER_KEY = 'itap_user';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); }
    catch { return null; }
  });
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const login = useCallback(async (username, password) => {
    setLoading(true);
    setError('');
    try {
      const data = await api.login(username, password);
      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(REFRESH_KEY, data.refresh_token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      setToken(data.access_token);
      setUser(data.user);
      return true;
    } catch (e) {
      const msg = e?.message || '';
      if (msg.toLowerCase().includes('too many')) {
        setError('Too many attempts. Please wait a moment and try again.');
      } else {
        setError('Invalid credentials. Please try again.');
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
    setToken('');
    setUser(null);
  }, []);

  // Auto-refresh token before expiry (every 7 hours)
  useEffect(() => {
    if (!token) return;
    const interval = setInterval(async () => {
      const refresh = localStorage.getItem(REFRESH_KEY);
      if (refresh) {
        try {
          const data = await api.refreshToken(refresh);
          localStorage.setItem(TOKEN_KEY, data.access_token);
          setToken(data.access_token);
        } catch {
          logout();
        }
      }
    }, 7 * 60 * 60 * 1000); // 7 hours
    return () => clearInterval(interval);
  }, [token, logout]);

  return (
    <AuthContext.Provider value={{ user, token, loading, error, login, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

export default useAuth;
