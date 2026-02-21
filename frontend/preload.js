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