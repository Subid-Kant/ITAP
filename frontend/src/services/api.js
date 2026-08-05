// Re-export from root api.js for backwards-compatible path resolution.
// Both App.jsx ("./services/api") and components ("../services/api") resolve here.
export { api } from '../api.js';

// Additional API methods not yet in root api.js
// These are imported directly by components via "../services/api"
export { api as default } from '../api.js';

