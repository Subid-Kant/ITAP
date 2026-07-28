import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import { X, AlertTriangle, Shield, Info, CheckCircle } from 'lucide-react';

const ToastContext = createContext(null);

let toastIdCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = 'info', duration = 5000) => {
    const id = ++toastIdCounter;
    setToasts(prev => [...prev.slice(-4), { id, message, type, duration }]);
    if (duration > 0) {
      setTimeout(() => removeToast(id), duration);
    }
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) return { addToast: () => {}, removeToast: () => {} };
  return ctx;
}

const ICONS = {
  critical: AlertTriangle,
  error: AlertTriangle,
  warning: AlertTriangle,
  success: CheckCircle,
  info: Info,
  threat: Shield,
};

const TYPE_CLASSES = {
  critical: 'toast-critical',
  error: 'toast-error',
  warning: 'toast-warning',
  success: 'toast-success',
  info: 'toast-info',
  threat: 'toast-threat',
};

function ToastItem({ toast, onRemove }) {
  const [exiting, setExiting] = useState(false);
  const Icon = ICONS[toast.type] || Info;

  const handleClose = () => {
    setExiting(true);
    setTimeout(() => onRemove(toast.id), 300);
  };

  useEffect(() => {
    if (toast.duration > 0) {
      const timer = setTimeout(() => handleClose(), toast.duration - 300);
      return () => clearTimeout(timer);
    }
  }, []);

  return (
    <div className={`toast-item ${TYPE_CLASSES[toast.type] || 'toast-info'} ${exiting ? 'toast-exit' : 'toast-enter'}`}>
      <div className="toast-icon-wrap">
        <Icon size={16} />
      </div>
      <div className="toast-body">
        <div className="toast-message">{toast.message}</div>
      </div>
      <button className="toast-close" onClick={handleClose} aria-label="Close notification">
        <X size={12} />
      </button>
      {toast.duration > 0 && (
        <div className="toast-progress" style={{ animationDuration: `${toast.duration}ms` }} />
      )}
    </div>
  );
}

function ToastContainer({ toasts, onRemove }) {
  return (
    <div className="toast-container" aria-live="polite" aria-label="Notifications">
      {toasts.map(t => (
        <ToastItem key={t.id} toast={t} onRemove={onRemove} />
      ))}
    </div>
  );
}

export default ToastProvider;
