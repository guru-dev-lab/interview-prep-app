const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, screen, session, desktopCapturer, systemPreferences } = require('electron');
const path = require('path');

// ===== CONFIG =====
const SERVER_URL = process.env.XHIRE_SERVER || 'https://xhire.app';
let mainWindow = null;
let tray = null;
let isVisible = true;

// ===== APP LIFECYCLE =====

// Single instance lock — prevent multiple overlays
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  console.log('[Xhire] Another instance is running, quitting.');
  app.quit();
}

app.on('second-instance', () => {
  if (mainWindow) {
    // Reload launcher fresh when re-opening
    mainWindow.loadURL(SERVER_URL + '/launcher').catch(() => {
      mainWindow.loadFile(path.join(__dirname, 'launcher.html'));
    });
    mainWindow.show();
    mainWindow.focus();
  }
});

app.whenReady().then(() => {
  // Hide dock icon — CRITICAL for overlay to float above fullscreen apps on macOS
  if (process.platform === 'darwin') {
    app.dock.hide();
  }

  createTray();
  createOverlay();

  // Handle getDisplayMedia from renderer — required for audio/screen capture in Electron
  session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
    desktopCapturer.getSources({ types: ['screen', 'window'] }).then((sources) => {
      if (sources.length === 0) {
        callback({});
        return;
      }
      // Grant first screen source + system audio loopback
      callback({ video: sources[0], audio: 'loopback' });
    }).catch(() => {
      callback({});
    });
  });

  // Request microphone permission on macOS
  if (process.platform === 'darwin') {
    systemPreferences.askForMediaAccess('microphone').then((granted) => {
      console.log('[Xhire] Microphone access:', granted ? 'granted' : 'denied');
    });
  }
});

app.on('window-all-closed', (e) => {
  e.preventDefault(); // Keep app alive via tray
});

// ===== TRAY ICON =====

function createTray() {
  // Create a simple tray icon (16x16 template image for macOS menu bar)
  const iconPath = path.join(__dirname, 'tray-icon.png');
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    trayIcon = trayIcon.resize({ width: 16, height: 16 });
    if (process.platform === 'darwin') trayIcon.setTemplateImage(true);
  } catch (e) {
    // Fallback: create a simple colored icon programmatically
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip('Xhire Interview Prep');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show/Hide Overlay',
      click: () => toggleOverlay()
    },
    {
      label: 'Reset Position',
      click: () => resetPosition()
    },
    { type: 'separator' },
    {
      label: 'Small (400x500)',
      click: () => resizeOverlay(400, 500)
    },
    {
      label: 'Medium (450x650)',
      click: () => resizeOverlay(450, 650)
    },
    {
      label: 'Large (500x800)',
      click: () => resizeOverlay(500, 800)
    },
    { type: 'separator' },
    {
      label: 'Opacity: 100%',
      click: () => setOpacity(1.0)
    },
    {
      label: 'Opacity: 80%',
      click: () => setOpacity(0.8)
    },
    {
      label: 'Opacity: 60%',
      click: () => setOpacity(0.6)
    },
    { type: 'separator' },
    {
      label: 'Quit Xhire',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);

  // Click tray icon to toggle overlay
  tray.on('click', () => toggleOverlay());
}

// ===== OVERLAY WINDOW =====

function createOverlay() {
  const { width: screenW, height: screenH } = screen.getPrimaryDisplay().workAreaSize;

  mainWindow = new BrowserWindow({
    width: 420,
    height: 650,
    x: screenW - 440,           // Right side of screen
    y: Math.round(screenH * 0.05), // Near top
    transparent: true,
    frame: false,
    hasShadow: false,
    resizable: true,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    type: 'panel',               // CRITICAL for macOS — NSPanel floats over fullscreen
    visibleOnAllWorkspaces: true,
    hiddenInMissionControl: true,
    paintWhenInitiallyHidden: true,
    backgroundColor: '#00000000',
    minWidth: 320,
    minHeight: 400,
    maxWidth: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,             // Needed for audio capture APIs
      webSecurity: false,         // Allow fetch from file:// to https://
    }
  });

  // CRITICAL macOS settings — must be called AFTER window creation
  mainWindow.setAlwaysOnTop(true, 'screen-saver');
  mainWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  mainWindow.setHiddenInMissionControl(true);

  // Hide overlay from screen sharing — interviewer won't see it
  mainWindow.setContentProtection(true);

  // Load launcher from the server (same-origin for API calls)
  // Falls back to local file if server is unreachable
  mainWindow.loadURL(SERVER_URL + '/launcher').catch(() => {
    console.log('[Xhire] Server unreachable, loading local launcher');
    mainWindow.loadFile(path.join(__dirname, 'launcher.html'));
  });

  // Handle close — hide instead of quit (tray keeps app alive)
  mainWindow.on('close', (e) => {
    if (!app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      isVisible = false;
    }
  });

  // Workaround for Electron bug: briefly focus to ensure workspace visibility works
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
    // Then make it not steal focus going forward
    setTimeout(() => {
      mainWindow.blur();
    }, 200);
  });

  console.log('[Xhire] Overlay window created');
}

// ===== IPC HANDLERS =====

// Opacity control from renderer
ipcMain.handle('set-opacity', (_, value) => {
  if (mainWindow) mainWindow.setOpacity(Math.max(0.2, Math.min(1.0, value)));
});

// Toggle visibility
ipcMain.handle('toggle-overlay', () => {
  toggleOverlay();
});

// Navigate to canvas URL after user authenticates
ipcMain.handle('load-canvas', (_, url) => {
  if (mainWindow) {
    console.log('[Xhire] Loading canvas:', url);
    mainWindow.loadURL(url);
  }
});

// Get server URL
ipcMain.handle('get-server-url', () => {
  return SERVER_URL;
});

// Quit the app
ipcMain.handle('quit-app', () => {
  app.isQuitting = true;
  app.quit();
});

// Stealth mode — toggle content protection (hide from screen sharing)
ipcMain.handle('set-stealth', (_, on) => {
  if (mainWindow) {
    mainWindow.setContentProtection(!!on);
    console.log('[Xhire] Content protection:', on ? 'ON' : 'OFF');
  }
});

// Window dragging support (fallback if -webkit-app-region doesn't work)
ipcMain.handle('start-drag', () => {
  // No-op — handled by CSS -webkit-app-region:drag
});

// ===== HELPERS =====

function toggleOverlay() {
  if (!mainWindow) return;
  if (isVisible) {
    mainWindow.hide();
    isVisible = false;
  } else {
    // Reload launcher so it's a fresh start (kills stale WebSocket)
    mainWindow.loadURL(SERVER_URL + '/launcher').catch(() => {
      mainWindow.loadFile(path.join(__dirname, 'launcher.html'));
    });
    mainWindow.show();
    isVisible = true;
  }
}

function resetPosition() {
  if (!mainWindow) return;
  const { width: screenW, height: screenH } = screen.getPrimaryDisplay().workAreaSize;
  mainWindow.setBounds({
    x: screenW - 440,
    y: Math.round(screenH * 0.05),
    width: 420,
    height: 650
  });
}

function resizeOverlay(w, h) {
  if (!mainWindow) return;
  const bounds = mainWindow.getBounds();
  mainWindow.setBounds({ x: bounds.x, y: bounds.y, width: w, height: h });
}

function setOpacity(val) {
  if (mainWindow) mainWindow.setOpacity(val);
}
