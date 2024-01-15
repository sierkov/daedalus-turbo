const path = require('path');
const { app, dialog, ipcMain, BrowserWindow } = require('electron');
const fetch = require('node-fetch');
const { spawn } = require('child_process');

console.log('Initializing DT UI cwd:', process.cwd(), 'execPath:', process.execPath);
const execFilename = path.basename(process.execPath);
const api = {
  cmd: path.resolve(path.dirname(process.execPath), 'dt'),
  dev: execFilename === "Electron" || execFilename === "electron.exe",
  dataDir: path.resolve(path.dirname(process.execPath), '../data'),
  logPath: path.resolve(path.dirname(process.execPath), '../log/dt-api.log'),
  ip: '127.0.0.1',
  port: 55556
};
api.uri = `http://${api.ip}:${api.port}`;
console.log('api:', api);

let apiServer;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const startAPI = () => {
  if (api.dev)
    return;
  const args = [ 'http-api', api.dataDir, '--ip=' + api.host, '--port=' + api.port ];
  const env = { DT_LOG: api.logPath };
  console.log('starting the DT API server', api.cmd, args, env, { stdio: 'inherit' });
  try {
    apiServer = spawn(api.cmd, args, { env });
    apiServer.on('error', err => {
      console.error(`the API server failed: ${err}`);
      app.quit();
    });
    apiServer.on('close', code => {
      console.error(`the API server exited with code: ${code}, terminating the UI`);
      app.quit();
    });
  } catch (e) {
    console.error('failed to spawn the API server:', e);
    app.quit();
  }
};

const createWindow = () => {
  console.log('creating application window');
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
  //win.removeMenu();
  win.loadFile('index.html');
};

app.whenReady().then(() => {
  startAPI();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});
app.on('window-all-closed', () => {
  console.log('The app window is closed, killing the API server');
  //if (process.platform !== 'darwin') {
  if (apiServer)
    apiServer.kill('SIGKILL');
  app.quit();
  //}
});

function setupIdRequest(name, baseURI, reqURI) {
  ipcMain.on(name, async (ev, reqId, params) => {
    try {
      const start = Date.now();
      const reqTarget = reqURI + params.map(v => encodeURIComponent(v)).join('/');
      let resRaw = await fetch(baseURI + reqTarget);
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
      console.log(`main ${name} ${reqId} took ${duration} secs, sending the response to the renderer`);
      ev.reply(name, reqId, undefined, await res);
    } catch (err) {
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