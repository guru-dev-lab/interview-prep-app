const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  setOpacity: (value) => ipcRenderer.invoke('set-opacity', value),
  toggleOverlay: () => ipcRenderer.invoke('toggle-overlay'),
  loadCanvas: (url) => ipcRenderer.invoke('load-canvas', url),
  getServerUrl: () => ipcRenderer.invoke('get-server-url'),
  quitApp: () => ipcRenderer.invoke('quit-app'),
  setStealth: (on) => ipcRenderer.invoke('set-stealth', on),

  // Window drag support for Windows (CSS -webkit-app-region can be flaky on Win)
  startWindowDrag: () => ipcRenderer.invoke('start-window-drag'),

  // Display change listener — fires when overlay moves to a different monitor
  onDisplayChanged: (callback) => ipcRenderer.on('display-changed', (_, displayId) => callback(displayId)),

  // Platform info
  platform: process.platform,
  isElectron: true,
  isWindows: process.platform === 'win32',
  isMac: process.platform === 'darwin'
});
