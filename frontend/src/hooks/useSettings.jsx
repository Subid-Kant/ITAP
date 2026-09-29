import React, { createContext, useContext, useState, useEffect } from 'react';

// Default settings object
const DEFAULT_SETTINGS = {
  theme: 'dark', // 'dark', 'light', 'black'
  accentColor: 'blue', // 'blue', 'green', 'red', 'purple'
  density: 'comfortable', // 'comfortable', 'compact'
  animations: true, // boolean
  defaultLandingPage: 'dashboard',
  
  // OSINT Keys
  shodanKey: '',
  virusTotalKey: '',
  alienVaultKey: '',
  
  // Scanner Config
  scanDepth: 'normal', // 'fast', 'normal', 'deep'
  autoArchiveDays: 30,
};

const SettingsContext = createContext(null);

export function SettingsProvider({ children }) {
  const [settings, setSettings] = useState(() => {
    try {
      const stored = localStorage.getItem('itap_settings');
      if (stored) {
        return { ...DEFAULT_SETTINGS, ...JSON.parse(stored) };
      }
    } catch (e) {
      console.error('Failed to parse settings from local storage', e);
    }
    return DEFAULT_SETTINGS;
  });

  // Persist settings whenever they change
  useEffect(() => {
    localStorage.setItem('itap_settings', JSON.stringify(settings));
    
    // Apply global UI settings via dataset attributes on the root <html> or <body> element
    // This allows CSS to react instantly (e.g. data-density="compact", data-theme="black")
    document.documentElement.dataset.theme = settings.theme;
    document.documentElement.dataset.density = settings.density;
    document.documentElement.dataset.animations = settings.animations.toString();
    document.documentElement.dataset.accent = settings.accentColor;
  }, [settings]);

  const updateSettings = (updates) => {
    setSettings(prev => ({ ...prev, ...updates }));
  };

  return (
    <SettingsContext.Provider value={{ settings, updateSettings }}>
      {children}
    </SettingsContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSettings() {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
}
