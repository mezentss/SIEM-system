const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  fetch: async (url, options) => {
    const response = await fetch(url, options);

    // Бросаем осмысленную ошибку при неуспешном статусе
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`HTTP ${response.status}: ${text || response.statusText}`);
    }

    return response.json();
  },
});