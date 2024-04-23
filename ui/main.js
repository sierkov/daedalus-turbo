const path = require('path');
const { app, dialog, ipcMain, BrowserWindow } = require('electron');
const fetch = require('node-fetch');
const { spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const log4js = require('log4js');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const processIsAlive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return false;
  }
};

const execFilename = path.basename(process.execPath, '.exe').toLowerCase();
const devEnv = execFilename === "electron" || process?.argv?.includes("--dev");
const osEnv = os.platform();
let installDir = devEnv ? process.cwd() : path.resolve(path.dirname(process.execPath), '..');
let roamingDataDir = installDir;
if (osEnv === 'win32' && !devEnv && process?.env?.APPDATA) {
  roamingDataDir = path.resolve(process.env.APPDATA, 'DaedalusTurbo');
}
const roamingDataCfg = path.resolve(installDir, 'etc/data-dir.txt');
if (fs.existsSync(roamingDataCfg))
  roamingDataDir = fs.readFileSync(roamingDataCfg).toString();
log4js.configure({
  appenders: {
    file: { type: 'file', filename: path.resolve(roamingDataDir, 'log/dt-ui.log') }
  },
  categories: {
    default: { appenders: ['file'], level: 'all' }
  }
});
const logger = log4js.getLogger();
const api = {
  execFilename,
  cmd: path.resolve(path.dirname(process.execPath), 'dt'),
  dev: devEnv,
  dataDir: path.resolve(roamingDataDir, 'data'),
  logPath: path.resolve(roamingDataDir, 'log/dt-api.log'),
  uiDataPath: path.resolve(roamingDataDir, 'ui'),
  etcPath: path.resolve(installDir, 'etc'),
  pidPath: path.resolve(roamingDataDir, 'dt-ui.pid'),
  ip: '127.0.0.1',
  port: 55556,
  os: osEnv
};
api.uri = `http://${api.ip}:${api.port}`;
const startInfo = `Initializing DT UI cwd: ${process.cwd()} execPath: ${process.execPath} ` +
  `installDir: ${installDir} roamingDataDir: ${roamingDataDir} api: ${JSON.stringify(api, null, 2)}`;
// log to the console first for the case the logger configuration is broken
console.log(startInfo);
logger.debug(startInfo);
logger.debug('api config: ' + JSON.stringify(api, null, 2));
if (fs.existsSync(api.pidPath)) {
  const pid = parseInt(fs.readFileSync(api.pidPath).toString());
  if (processIsAlive(pid)) {
    const msg = `Discovered another UI process with pid ${pid}: exiting`;
    logger.error(msg);
    console.error(msg);
    process.exit(1);
  }
}
fs.writeFileSync(api.pidPath, process.pid.toString());

let apiServer;
let apiServerReadyTime;

const startAPI = () => {
  if (api.dev) {
    apiServerReadyTime = Date.now();
    return;
  }
  const args = [ 'http-api', api.dataDir, '--ip=' + api.ip, '--port=' + api.port ];
  const env = { DT_LOG: api.logPath, DT_ETC: api.etcPath };
  logger.info(`starting the DT API server ${api.cmd} ${args} ${JSON.stringify(env, null, 2)}`);
  try {
    apiServerReadyTime = Date.now() + 2000;
    apiServer = spawn(api.cmd, args, { env });
    apiServer.on('error', err => {
      logger.error(`the API server failed: ${err}`);
      app.quit();
    });
    apiServer.on('close', (code, signal) => {
      if (code !== null)
        logger.error(`the API server exited with code: ${code}, terminating the UI`);
      else
        logger.error(`the API server exited due to signal ${signal}, terminating the UI`);
      app.quit();
    });
  } catch (e) {
    logger.error('failed to spawn the API server:', e);
    app.quit();
  }
};

const createWindow = () => {
  logger.info('creating the application window');
  const win = new BrowserWindow({
    width: 1024,
    height: 768,
    minWidth: 960,
    minHeight: 720,
    icon: './static/logo-256.png',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: false
    }
  });
  if (!api.dev)
    win.removeMenu();
  win.once('ready-to-show', () => {
    win.show();
    win.focus();
  })
  win.loadFile('index.html');
};

app.setPath('userData', api.uiDataPath);
app.whenReady().then(async () => {
  startAPI();
  // Give the API server 500ms second to start
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});
app.on('window-all-closed', () => {
  if (apiServer) {
    logger.info('The app window is closed, killing the API server');
    apiServer.kill('SIGKILL');
  }
  app.quit();
});
app.on('quit', () => {
  fs.unlinkSync(api.pidPath);
});

const fetchWithRetries = async (url, maxRetries) => {
  for (let retry = 0; retry < maxRetries; ++retry) {
    try {
      return await fetch(url);
    } catch (err) {
      logger.warn(`fetch attempt ${retry} for ${url} failed:`, err);
      await sleep(2000);
    }
  }
  throw Error(`failed to fetch ${url} after ${maxRetries} retries`);
};

function setupIdRequest(name, baseURI, reqURI) {
  ipcMain.on(name, async (ev, reqId, params) => {
    try {
      const start = Date.now();
      if (!apiServerReadyTime)
        throw Error(`API server has not been started!`);
      if (start < apiServerReadyTime) {
        const sleepTime = apiServerReadyTime - start;
        logger.info(`request for ${name} too early, sleeping for ${sleepTime}`);
        await sleep(sleepTime);
      }
      const reqTarget = reqURI + params.map(v => encodeURIComponent(v)).join('/');
      let resRaw = await fetchWithRetries(baseURI + reqTarget, 3);
      let res = await resRaw.json();
      if (res?.delayed === true) {
        for (;;) {
          resRaw = await fetch(baseURI + '/status/' + Date.now());
          res = await resRaw.json();
          if (res?.requests?.[reqTarget]) {
            resRaw = await fetch(baseURI + reqTarget);
            res = await resRaw.json();
            break;
          }
          await sleep(100);
        }
      }
      const duration = (Date.now() - start) / 1000;
      if (duration >= 0.100)
        logger.warn(`main ${name} ${reqId} took ${duration} secs, sending the response to the renderer`);
      ev.reply(name, reqId, undefined, await res);
    } catch (err) {
      logger.error('HTTP API error:', err);
      ev.reply(name, reqId, err);
    }
  });
}

ipcMain.on("exit", () => app.quit());
setupIdRequest('status', api.uri, '/status/');
setupIdRequest('txInfo', api.uri, '/tx/');
setupIdRequest('stakeInfo', api.uri, '/stake/');
setupIdRequest('stakeAssets', api.uri, '/stake-assets/');
setupIdRequest('stakeTxs', api.uri, '/stake-txs/');
setupIdRequest('payInfo', api.uri, '/pay/');
setupIdRequest('payAssets', api.uri, '/pay-assets/');
setupIdRequest('payTxs', api.uri, '/pay-txs/');