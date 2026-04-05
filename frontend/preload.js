const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  fetch: async (url, options) => {
    try {
      const response = await fetch(url, options);

      // Возвращаем response object с методами для совместимости с обычным fetch
      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        json: async () => {
          if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(`HTTP ${response.status}: ${text || response.statusText}`);
          }
          return response.json();
        },
        text: async () => response.text(),
      };
    } catch (err) {
      // При ошибке сети возвращаем объект с ошибкой
      return {
        ok: false,
        status: 0,
        statusText: err.message,
        json: async () => { throw err; },
        text: async () => err.message,
      };
    }
  },

  // Метод для сохранения данных перед закрытием
  saveAppState: (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (e) {
      console.error('Failed to save app state:', e);
      return false;
    }
  },

  // Метод для загрузки сохранённых данных
  loadAppState: (key) => {
    try {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    } catch (e) {
      console.error('Failed to load app state:', e);
      return null;
    }
  }
});