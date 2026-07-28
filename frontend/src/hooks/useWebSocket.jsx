// ITAP — WebSocket Live Feed Hook
// Manages WebSocket connection with auto-reconnect, event dispatch, and heartbeat.
import { useEffect, useRef, useState, useCallback, createContext, useContext } from 'react';

const WS_URL = 'ws://localhost:8000/ws/live';
const WSContext = createContext(null);

export function WebSocketProvider({ children, onEvent }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const heartbeatTimer = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        // Start heartbeat
        heartbeatTimer.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, 30000);
      };

      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data.type === 'connected' || data === 'pong' || evt.data === 'pong') return;

          const event = { ...data, id: Date.now() };
          setEvents(prev => [event, ...prev].slice(0, 100)); // Keep last 100 events
          if (onEvent) onEvent(event);
        } catch { /* ignore non-JSON */ }
      };

      ws.onerror = () => {};

      ws.onclose = () => {
        setConnected(false);
        clearInterval(heartbeatTimer.current);
        // Auto-reconnect with backoff
        reconnectTimer.current = setTimeout(() => connect(), 3000);
      };
    } catch { }
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

export function useWebSocket() {
  const ctx = useContext(WSContext);
  if (!ctx) return { connected: false, events: [] };
  return ctx;
}

export default useWebSocket;
