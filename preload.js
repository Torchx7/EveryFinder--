const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('ef', {
  platform: process.platform,
  start: () => ipcRenderer.send('term:start'),
  write: (cmd) => ipcRenderer.send('term:write', cmd),
  stop: () => ipcRenderer.send('term:stop'),
  keysStatus: () => ipcRenderer.invoke('keys:status'),
  keySet: (s, k) => ipcRenderer.invoke('keys:set', s, k),
  api: (s, t) => ipcRenderer.invoke('api:run', s, t),
  onData: (cb) => ipcRenderer.on('term:data', (_, d) => cb(d))
});
