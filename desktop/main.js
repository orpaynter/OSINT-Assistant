const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const log = require('electron-log');
const kill = require('tree-kill');

const BACKEND_PORT = process.env.BACKEND_PORT || 5000;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
const isDev = !app.isPackaged || process.env.NODE_ENV === 'development';
let backendProcess = null;

const paths = {
  packagedExe: () => path.join(process.resourcesPath, 'backend', 'osint_web_app.exe'),
  localExe: () => path.join(__dirname, 'backend', 'osint_web_app.exe'),
  distExe: () => path.join(__dirname, '..', 'dist', 'OSINT-Assistant.exe'),
  pythonScript: () => path.join(__dirname, '..', 'osint_web_app.py'),
  icon: () => path.join(__dirname, 'icon.ico')
};

function resolveBackend() {
  if (!isDev && fs.existsSync(paths.packagedExe())) {
    return { cmd: paths.packagedExe(), args: [], cwd: process.resourcesPath };
  }

  if (fs.existsSync(paths.localExe())) {
    return { cmd: paths.localExe(), args: [], cwd: path.join(__dirname, 'backend') };
  }

  if (fs.existsSync(paths.distExe())) {
    return { cmd: paths.distExe(), args: [], cwd: path.join(__dirname, '..') };
  }

  if (fs.existsSync(paths.pythonScript())) {
    const pythonCmd = process.env.PYTHON || 'python';
    return { cmd: pythonCmd, args: [paths.pythonScript()], cwd: path.join(__dirname, '..') };
  }

  return null;
}

function startBackend() {
  const target = resolveBackend();
  if (!target) {
    dialog.showErrorBox('Backend missing', 'No backend executable found. Build with PyInstaller (packaging/pyinstaller-win.ps1) or provide a Python interpreter to run osint_web_app.py.');
    return null;
  }

  log.info('Launching backend:', target.cmd, target.args.join(' '));
  const child = spawn(target.cmd, target.args, {
    cwd: target.cwd,
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout?.on('data', (data) => log.info(`[backend] ${data.toString().trim()}`));
  child.stderr?.on('data', (data) => log.error(`[backend] ${data.toString().trim()}`));
  child.on('exit', (code) => log.info(`Backend exited with code ${code}`));

  return child;
}

function stopBackend() {
  if (!backendProcess) return;
  const pid = backendProcess.pid;
  log.info('Stopping backend', pid);
  try {
    kill(pid);
  } catch (err) {
    log.error('Failed to stop backend', err);
  }
  backendProcess = null;
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    icon: fs.existsSync(paths.icon()) ? paths.icon() : undefined,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.on('close', () => stopBackend());

  const load = () => {
    win.loadURL(BACKEND_URL).catch((err) => {
      log.warn('Retrying UI load after backend start delay', err);
      setTimeout(load, 1000);
    });
  };

  setTimeout(load, 800);
}

app.on('ready', () => {
  backendProcess = startBackend();
  createWindow();
});

app.on('before-quit', () => stopBackend());
app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
