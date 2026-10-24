const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  setOpacity: (value) => ipcRenderer.invoke('set-opacity', value),
  toggleOverlay: () => ipcRenderer.invoke('toggle-overlay'),
  loadCanvas: (url) => ipcRenderer.invoke('load-canvas', url),
  getServerUrl: () => ipcRenderer.invoke('get-server-url'),
  quitApp: () => ipcRenderer.invoke('quit-app'),
  setStealth: (on) => ipcRenderer.invoke('set-stealth', on),
  captureDisplay: (maxW) => ipcRenderer.invoke('capture-display', maxW),
  getBounds: () => ipcRenderer.invoke('get-bounds'),

  // Window drag support for Windows (CSS -webkit-app-region can be flaky on Win)
  startWindowDrag: () => ipcRenderer.invoke('start-window-drag'),

  // Manual corner resize — supplements tiny native resize zones on transparent frameless windows
  resizeWindow: (deltaW, deltaH, direction) => ipcRenderer.invoke('resize-window', deltaW, deltaH, direction),

  // Display change listener — fires when overlay moves to a different monitor
  onDisplayChanged: (callback) => ipcRenderer.on('display-changed', (_, displayId) => callback(displayId)),

  // Auto-update listeners — fires when a new version is available/downloaded
  onUpdateAvailable: (callback) => ipcRenderer.on('update-available', (_, version) => callback(version)),
  onUpdateDownloaded: (callback) => ipcRenderer.on('update-downloaded', (_, version) => callback(version)),
  installUpdate: () => ipcRenderer.invoke('install-update'), // 1.1.8+: Mac updates itself too (electron/mac-updater.js)

  // Mac privacy permissions — check, ask for the mic, open the exact Settings page, restart to apply
  permStatus: () => ipcRenderer.invoke('perm-status'),
  permRequestMic: () => ipcRenderer.invoke('perm-request-mic'),
  permOpenSettings: (kind) => ipcRenderer.invoke('perm-open-settings', kind),
  relaunchApp: () => ipcRenderer.invoke('app-relaunch'),

  // Click-through on the transparent parts of the window (true = clicks pass to the apps behind)
  setClickThrough: (on) => ipcRenderer.send('set-click-through', !!on),

  // Global Shortcut Mode: Cmd+Enter from any app → this page's Screen Assist. set returns { on, accelerator, error? }
  setGlobalShortcut: (on) => ipcRenderer.invoke('set-global-shortcut', !!on),
  onGlobalShortcut: (callback) => ipcRenderer.on('global-shortcut', (_, action) => callback(action)),

  // Answer Note: its own window, hidden from screen sharing like the overlay (1.1.7+). Pages check it exists first.
  openNote: (url) => ipcRenderer.invoke('open-note', url),
  noteOnTop: (on) => ipcRenderer.invoke('note-on-top', on),
  noteGlass: (on) => ipcRenderer.invoke('note-glass', on), // 1.1.10+: the note as a glass window, like the overlay

  // Platform info
  platform: process.platform,
  isElectron: true,
  isWindows: process.platform === 'win32',
  isMac: process.platform === 'darwin'
});
