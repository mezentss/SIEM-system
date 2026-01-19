const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  fetch: (url, options) => fetch(url, options)
});
