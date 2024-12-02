const { contextBridge, ipcRenderer } = require('electron');

const openRequests = {};

function multiRequest(name, ...params) {
  if (!(name in openRequests)) {
    openRequests[name] = {};
    ipcRenderer.on(name, (ev, origReqId, err, res) => {
      if (origReqId in openRequests[name]) {
        const [resolve, reject, start] = openRequests[name][origReqId];
        const duration = (Date.now() - start) / 1000;
        if (duration > 0.100)
          console.warn(`renderer ${name} ${origReqId} took ${duration} secs, sending the data to the UI`);
        //console.log(`${name} ${origReqId} response:`, err, res);
        delete openRequests[name][origReqId];
        if (err) reject(err);
        else resolve(res);
      }
    });
  }
  return new Promise((resolve, reject) => {
    const reqId = params.join('/');
    openRequests[name][reqId] = [ resolve, reject, Date.now() ];
    ipcRenderer.send(name, reqId, params);
  });
}

contextBridge.exposeInMainWorld('appAPI', {
  configSync: (netSrc, valMode) => multiRequest('configSync', netSrc, valMode),
  exit: () => ipcRenderer.send('exit'),
  export: (path) => multiRequest('export', path),
  freeSpace: (path) => multiRequest('freeSpace', path),
  selectDir: () => multiRequest('selectDir', Date.now()),
  status: (now) => multiRequest('status', now),
  txInfo: (hash) => multiRequest('txInfo', hash),
  stakeInfo: (hash) => multiRequest('stakeInfo', hash),
  stakeAssets: (hash, offset, limit) => multiRequest('stakeAssets', hash, offset, limit),
  stakeTxs: (hash, offset, limit) => multiRequest('stakeTxs', hash, offset, limit),
  sync: (now) => multiRequest('sync', now),
  paperLink: () => ipcRenderer.send('paperLink'),
  payInfo: (hash) => multiRequest('payInfo', hash),
  payAssets: (hash, offset, limit) => multiRequest('payAssets', hash, offset, limit),
  payTxs: (hash, offset, limit) => multiRequest('payTxs', hash, offset, limit)
});