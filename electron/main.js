const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, screen, session, desktopCapturer, systemPreferences, dialog } = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');

// Safe logging — prevents EIO crash when stdout pipe is broken
const _log = (...args) => { try { console.log(...args); } catch(e) {} };

// ===== AUTO-UPDATER =====
// Checks GitHub Releases for new versions and installs silently in background.
// On next app restart the new version is active — no user action needed.
autoUpdater.logger = { info: _log, warn: _log, error: _log };
autoUpdater.autoDownload = true;
autoUpdater.autoInstallOnAppQuit = true;

autoUpdater.on('checking-for-update', () => _log('[Update] Checking for updates...'));
autoUpdater.on('update-available', (info) => {
  _log('[Update] New version available:', info.version);
  // Notify the renderer so it can show a subtle toast
  if (mainWindow) mainWindow.webContents.send('update-available', info.version);
});
autoUpdater.on('update-not-available', () => _log('[Update] App is up to date'));
autoUpdater.on('download-progress', (progress) => {
  _log(`[Update] Downloading: ${Math.round(progress.percent)}%`);
});
autoUpdater.on('update-downloaded', (info) => {
  _log('[Update] Update downloaded:', info.version, '— will install on next restart');
  // Notify the renderer
  if (mainWindow) mainWindow.webContents.send('update-downloaded', info.version);
});
autoUpdater.on('error', (err) => {
  _log('[Update] Error:', err.message);
});

// Transparency fix — disable hardware acceleration on macOS (required for transparency)
// On Windows, hardware acceleration is needed for performance but transparency uses a different approach
if (process.platform === 'darwin') {
  app.disableHardwareAcceleration();
  app.commandLine.appendSwitch('disable-features', 'RoundedWindowMac');
}
// Windows: enable transparency with DWM composition
if (process.platform === 'win32') {
  app.commandLine.appendSwitch('enable-transparent-visuals');
  app.commandLine.appendSwitch('disable-gpu-compositing');
}

// ===== CONFIG =====
const SERVER_URL = process.env.XHIRE_SERVER || 'https://xhire.app';
let mainWindow = null;
let tray = null;
let isVisible = true;

// ===== APP LIFECYCLE =====

// Single instance lock — prevent multiple overlays
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  _log('[Xhire] Another instance is running, quitting.');
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
  if (process.platform === 'darwin' && app.dock) {
    app.dock.hide();
  }
  // Windows: skip taskbar is set in BrowserWindow options

  createTray();
  createOverlay();

  // Handle getDisplayMedia from renderer — required for audio/screen capture in Electron
  // Auto-detect which screen the overlay window is on and capture THAT screen.
  // This way Co-Pilot always sees what's behind the overlay, even if you move monitors.
  session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
    desktopCapturer.getSources({ types: ['screen'] }).then((sources) => {
      const screenSources = sources.filter(s => s.id.startsWith('screen:'));
      if (screenSources.length === 0) {
        _log('[Xhire] No screen sources found');
        callback({});
        return;
      }

      // Single monitor — just use it
      if (screenSources.length === 1) {
        _log('[Xhire] Single screen:', screenSources[0].name);
        // 'loopback' captures system audio — works on both macOS and Windows (Electron 28+)
        // Note: 'loopbackWithMute' is macOS-only and breaks Windows!
        const audioOption = 'loopback';
        callback({ video: screenSources[0], audio: audioOption });
        return;
      }

      // Multi-monitor: find which display the overlay window is on
      let chosenIndex = 0;
      if (mainWindow) {
        const winBounds = mainWindow.getBounds();
        const winCenterX = winBounds.x + Math.round(winBounds.width / 2);
        const winCenterY = winBounds.y + Math.round(winBounds.height / 2);
        const currentDisplay = screen.getDisplayNearestPoint({ x: winCenterX, y: winCenterY });
        const allDisplays = screen.getAllDisplays();

        // Match current display to its index in allDisplays (same order as desktopCapturer)
        for (let i = 0; i < allDisplays.length; i++) {
          if (allDisplays[i].id === currentDisplay.id) {
            chosenIndex = i;
            break;
          }
        }
        _log('[Xhire] Window is on display', chosenIndex, '(id:', currentDisplay.id, ') —', allDisplays.length, 'displays total');
      }

      // Clamp to available sources
      chosenIndex = Math.min(chosenIndex, screenSources.length - 1);
      const chosen = screenSources[chosenIndex];
      _log('[Xhire] Capturing screen:', chosen.name, '(' + chosen.id + ')');
      const audioOption = 'loopback';
      callback({ video: chosen, audio: audioOption });
    }).catch((e) => {
      _log('[Xhire] desktopCapturer error:', e);
      callback({});
    });
  });

  // Request microphone permission on macOS (Windows doesn't need explicit system permission)
  if (process.platform === 'darwin') {
    systemPreferences.askForMediaAccess('microphone').then((granted) => {
      _log('[Xhire] Microphone access:', granted ? 'granted' : 'denied');
    });
  }

  _log('[Xhire] Platform:', process.platform, '| Electron:', process.versions.electron);

  // Check for updates after a short delay (don't slow down startup)
  setTimeout(() => {
    autoUpdater.checkForUpdatesAndNotify().catch(e => {
      _log('[Update] Check failed (offline or no releases):', e.message);
    });
  }, 5000);

  // Re-check every 2 hours while running
  setInterval(() => {
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
  }, 2 * 60 * 60 * 1000);
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

  const isWin = process.platform === 'win32';
  const isMac = process.platform === 'darwin';

  mainWindow = new BrowserWindow({
    width: 420,
    height: 650,
    x: screenW - 440,
    y: Math.round(screenH * 0.05),
    transparent: true,
    frame: false,
    hasShadow: false,
    resizable: true,
    movable: true,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    // macOS-only properties (ignored on Windows but set for safety)
    ...(isMac ? {
      visibleOnAllWorkspaces: true,
      hiddenInMissionControl: true,
    } : {}),
    backgroundColor: '#00000000',
    // Windows: use WS_EX_LAYERED for proper transparency
    ...(isWin ? { thickFrame: false } : {}),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: false,
      backgroundThrottling: false,
    }
  });

  // CRITICAL always-on-top — must be called AFTER window creation
  if (process.platform === 'darwin') {
    mainWindow.setAlwaysOnTop(true, 'screen-saver');
    mainWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
    mainWindow.setHiddenInMissionControl(true);
  } else {
    // Windows: 'screen-saver' level isn't supported the same way
    // Use 'floating' which stays above normal windows
    mainWindow.setAlwaysOnTop(true, 'floating');
    mainWindow.setSkipTaskbar(true);
  }

  // Hide overlay from screen sharing — interviewer won't see it
  // On Windows, setContentProtection uses WDA (Windows Display Affinity)
  // which can require a small delay after window creation
  setTimeout(() => {
    mainWindow.setContentProtection(true);
    _log('[Xhire] Content protection enabled (platform:', process.platform, ')');
  }, process.platform === 'win32' ? 500 : 0);

  // Load launcher from the server (same-origin for API calls)
  // Falls back to local file if server is unreachable
  mainWindow.loadURL(SERVER_URL + '/launcher').catch(() => {
    _log('[Xhire] Server unreachable, loading local launcher');
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

  // Track which display the window is on — notify renderer when it changes
  // so screen capture stream can be refreshed to the correct monitor
  let lastDisplayId = null;
  mainWindow.on('moved', () => {
    if (!mainWindow) return;
    const bounds = mainWindow.getBounds();
    const display = screen.getDisplayNearestPoint({ x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2 });
    if (lastDisplayId !== null && display.id !== lastDisplayId) {
      _log('[Xhire] Window moved to display', display.id, '— notifying renderer to refresh screen stream');
      mainWindow.webContents.send('display-changed', display.id);
    }
    lastDisplayId = display.id;
  });

  _log('[Xhire] Overlay window created');
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
    _log('[Xhire] Loading canvas:', url);
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
// Windows quirk: WDA (Windows Display Affinity) needs the window to briefly hide/show
// for the DWM to pick up the change. Without this, it takes a second click.
ipcMain.handle('set-stealth', (_, on) => {
  if (mainWindow) {
    if (process.platform === 'win32') {
      // Windows: force DWM to re-evaluate display affinity
      mainWindow.setContentProtection(!!on);
      // Briefly toggle visibility to force Windows to apply the change
      mainWindow.setOpacity(0.99);
      setTimeout(() => {
        mainWindow.setOpacity(1.0);
      }, 50);
    } else {
      mainWindow.setContentProtection(!!on);
    }
    _log('[Xhire] Content protection:', on ? 'ON' : 'OFF');
  }
});

// Window dragging support — on Windows, CSS -webkit-app-region:drag can be
// unreliable with transparent frameless windows. This IPC call lets the
// renderer trigger native window drag via the OS.
ipcMain.handle('start-drag', () => {
  // No-op — handled by CSS -webkit-app-region:drag
});

// Windows drag fallback — renderer calls this on mousedown on the toolbar
ipcMain.handle('start-window-drag', () => {
  if (mainWindow && process.platform === 'win32') {
    // On Windows, we need to use moveTop + track position manually
    // But the simplest reliable fix is to ensure the window is properly movable
    try {
      mainWindow.setMovable(true);
    } catch(e) {}
  }
});

// ===== HELPERS =====

function toggleOverlay() {
  if (!mainWindow) return;
  if (isVisible) {
    mainWindow.hide();
    isVisible = false;
  } else {
    // Just show — don't reload. User's session and canvas stay intact.
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
