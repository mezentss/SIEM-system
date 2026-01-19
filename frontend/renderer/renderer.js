const API_BASE = 'http://127.0.0.1:8000';

function showOutput(text) {
  const outputArea = document.getElementById('outputArea');
  outputArea.textContent = text;
}

async function apiCall(url, options = {}) {
  try {
    // В Electron preload возвращает уже JSON
    return await window.electronAPI.fetch(url, options);
  } catch (error) {
    throw new Error(error?.message || 'Ошибка связи с backend');
  }
}

async function loadEvents() {
  showOutput('Загрузка событий...');
  try {
    const data = await apiCall(`${API_BASE}/api/events/?limit=50&offset=0`);

    if (!Array.isArray(data) || data.length === 0) {
      showOutput('События загружены: данных нет.');
      return;
    }

    showOutput(
      `События загружены (${data.length} шт.):\n\n` +
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    showOutput(`Ошибка при загрузке событий:\n${error.message}`);
  }
}

async function runAnalysis() {
  showOutput('Запуск анализа...');
  try {
    const data = await apiCall(
      `${API_BASE}/api/analyze/run?since_minutes=60`,
      { method: 'POST' }
    );

    const incidentsFound = data?.incidents_found ?? 0;

    showOutput(
      `Анализ завершён.\nИнцидентов найдено: ${incidentsFound}\n\n` +
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    showOutput(`Ошибка при запуске анализа:\n${error.message}`);
  }
}

async function collectFileEvents() {
  showOutput('Сбор реальных логов из system.log...');
  try {
    const data = await apiCall(
      `${API_BASE}/api/collect/file?file_path=./logs/system.log&max_lines=200`,
      { method: 'POST' }
    );

    const collected = data?.collected_count ?? 0;
    const saved = data?.saved_count ?? 0;

    if (collected === 0) {
      showOutput('В файле логов нет новых событий.');
      return;
    }

    showOutput(
      `События собраны.\nСохранено: ${saved}\n\nЗагрузка событий...`
    );

    await loadEvents();
  } catch (error) {
    showOutput(`Ошибка при сборе событий:\n${error.message}`);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('loadEventsBtn')
    .addEventListener('click', loadEvents);

  document.getElementById('runAnalysisBtn')
    .addEventListener('click', runAnalysis);

  document.getElementById('generateMockBtn')
    .addEventListener('click', collectFileEvents);
});