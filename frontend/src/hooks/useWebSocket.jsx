// ITAP — WebSocket Live Feed Hook
// Manages WebSocket connection with auto-reconnect, event dispatch, and heartbeat.
import { useEffect, useRef, useState, useCallback, createContext, useContext } from 'react';

// The backend will not broadcast to an unauthenticated socket: /ws/live accepts the
// connection, then waits a couple of seconds for a first frame of
// {"type":"auth","token":"<access token>"} and closes with code 4401 if it never
// arrives or does not validate. Browsers cannot set an Authorization header on a
// WebSocket, so this handshake frame is the only way to subscribe.
const TOKEN_KEY = 'itap_access_token'; // same key api.js and useAuth.jsx write
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live';
const RECONNECT_DELAY = 3000;
const WSContext = createContext(null);

export function WebSocketProvider({ children, onEvent }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const heartbeatTimer = useRef(null);

  const connect = useCallback(function connectSocket() {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    // No token means nobody is signed in: retry quietly instead of opening a socket
    // the server is going to close. This is also how the feed comes back to life
    // right after a login, without a page refresh.
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      reconnectTimer.current = setTimeout(() => connectSocket(), RECONNECT_DELAY);
      return;
    }

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        // Must be the very first frame: the server rejects anything else (including
        // the heartbeat 'ping') with 4401, and starts the auth timeout the moment it
        // accepts the socket.
        ws.send(JSON.stringify({ type: 'auth', token }));
      };

      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data === 'pong' || evt.data === 'pong') return;

          if (data.type === 'connected') {
            // The server only sends this once the token has been verified, so it —
            // not onopen — is the truthful "we are subscribed" signal.
            setConnected(true);
            clearInterval(heartbeatTimer.current);
            heartbeatTimer.current = setInterval(() => {
              if (ws.readyState === WebSocket.OPEN) ws.send('ping');
            }, 30000);
            return;
          }

          const event = { ...data, id: Date.now() };
          setEvents(prev => [event, ...prev].slice(0, 100)); // Keep last 100 events
          if (onEvent) onEvent(event);
        } catch { /* ignore non-JSON */ }
      };

      ws.onerror = () => {};

      ws.onclose = () => {
        setConnected(false);
        clearInterval(heartbeatTimer.current);
        // Auto-reconnect with backoff. 4401 means the token expired or was revoked;
        // api.js refreshes it on the next REST call, and the retry below picks the
        // new one up because the token is read from localStorage each attempt.
        reconnectTimer.current = setTimeout(() => connectSocket(), RECONNECT_DELAY);
      };
    } catch { 
      // ignore parse errors
    }
  }, [onEvent]);

  useEffect(() => {
    connect();
    return () => {
      clearInterval(heartbeatTimer.current);
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return (
    <WSContext.Provider value={{ connected, events }}>
      {children}
    </WSContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useWebSocket() {
  const ctx = useContext(WSContext);
  if (!ctx) return { connected: false, events: [] };
  return ctx;
}

// eslint-disable-next-line react-refresh/only-export-components
export default useWebSocket;
