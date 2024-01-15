const { contextBridge, ipcRenderer } = require('electron');

const openRequests = {};

function multiRequest(name, ...params) {
  if (!(name in openRequests)) {
    openRequests[name] = {};
    ipcRenderer.on(name, (ev, origReqId, err, res) => {
      if (origReqId in openRequests[name]) {
        const [resolve, reject, start] = openRequests[name][origReqId];
        const duration = (Date.now() - start) / 1000;
        console.log(`renderer ${name} ${origReqId} took ${duration} secs, sending the data to the UI`);
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
  exit: () => ipcRenderer.send('exit'),
  status: (now) => multiRequest('status', now),
  txInfo: (hash) => multiRequest('txInfo', hash),
  stakeInfo: (hash) => multiRequest('stakeInfo', hash),
  stakeAssets: (hash, offset, limit) => multiRequest('stakeAssets', hash, offset, limit),
  stakeTxs: (hash, offset, limit) => multiRequest('stakeTxs', hash, offset, limit),
  payInfo: (hash) => multiRequest('payInfo', hash),
  payAssets: (hash, offset, limit) => multiRequest('payAssets', hash, offset, limit),
  payTxs: (hash, offset, limit) => multiRequest('payTxs', hash, offset, limit)
});