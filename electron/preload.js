const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  setOpacity: (value) => ipcRenderer.invoke('set-opacity', value),
  toggleOverlay: () => ipcRenderer.invoke('toggle-overlay'),
  loadCanvas: (url) => ipcRenderer.invoke('load-canvas', url),
  getServerUrl: () => ipcRenderer.invoke('get-server-url'),

  // Platform info
  platform: process.platform,
  isElectron: true
});
