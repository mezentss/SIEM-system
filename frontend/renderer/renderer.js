const API_BASE = 'http://127.0.0.1:8000';

function showOutput(text) {
  const outputArea = document.getElementById('outputArea');
  outputArea.textContent = text;
}

async function apiCall(url, options = {}) {
  try {
    return await window.electronAPI.fetch(url, options);
  } catch (error) {
    throw new Error(error?.message || 'Ошибка связи с backend');
  }
}

/**
 * ==== БЛОК: агрегация и диаграмма по серьёзности СЕКЦИЙ ====
 */

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};
const SEVERITY_COLORS = {
  critical: '#d62728',
  high: '#1f77b4',
  medium: '#ff7f0e',
  low: '#6baed6',
};

async function loadSeverityOverview(lastDays = 3) {
  const canvas = document.getElementById('severityChart');
  const legendContainer = document.getElementById('severityLegend');
  const totalEl = document.getElementById('severityTotal');
  const periodEl = document.getElementById('severityPeriod');

  if (!canvas || !legendContainer || !totalEl) {
    return;
  }

  periodEl.textContent = `за последние ${lastDays} дня`;

  try {
    // Загружаем ИНЦИДЕНТЫ (incidents), а не события (events)
    const data = await apiCall(`${API_BASE}/api/incidents/?limit=1000&offset=0`);

    if (!Array.isArray(data) || data.length === 0) {
      drawEmptyChart(canvas, totalEl);
      legendContainer.innerHTML = '<div class="severity-legend-empty">Нет инцидентов за выбранный период</div>';
      return;
    }

    const now = Date.now();
    const cutoff = now - lastDays * 24 * 60 * 60 * 1000;

    // Фильтруем инциденты по дате
    const recentIncidents = data.filter((incident) => {
      if (!incident.detected_at) return false;
      const detectedAt = Date.parse(incident.detected_at);
      if (Number.isNaN(detectedAt)) return false;
      return detectedAt >= cutoff;
    });

    if (recentIncidents.length === 0) {
      drawEmptyChart(canvas, totalEl);
      legendContainer.innerHTML = '<div class="severity-legend-empty">Нет инцидентов за выбранный период</div>';
      return;
    }

    // Считаем инциденты по уровням серьёзности
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const incident of recentIncidents) {
      const sev = (incident.severity || '').toLowerCase();
      if (sev in counts) {
        counts[sev] += 1;
      } else {
        // Всё неизвестное считаем как low
        counts.low += 1;
      }
    }

    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) {
      drawEmptyChart(canvas, totalEl);
      legendContainer.innerHTML = '<div class="severity-legend-empty">Все инциденты внеклассовые</div>';
      return;
    }

    drawSeverityChart(canvas, counts, total, totalEl);
    renderSeverityLegend(legendContainer, counts, total);
  } catch (error) {
    drawEmptyChart(canvas, totalEl);
    legendContainer.innerHTML = `<div class="severity-legend-empty">Ошибка при загрузке: ${error.message}</div>`;
  }
}

function drawEmptyChart(canvas, totalEl) {
  const ctx = canvas.getContext('2d');
  const { width, height } = canvas;
  ctx.clearRect(0, 0, width, height);

  const centerX = width / 2;
  const centerY = height / 2;
  const outerRadius = Math.min(width, height) / 2 - 5;
  const innerRadius = outerRadius * 0.6;

  // Внешний круг светлый
  ctx.beginPath();
  ctx.arc(centerX, centerY, outerRadius, 0, Math.PI * 2);
  ctx.fillStyle = '#e5e9f0';
  ctx.fill();

  // Дырка
  ctx.beginPath();
  ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
  ctx.fillStyle = '#ffffff';
  ctx.fill();

  totalEl.textContent = '0';
}

function drawSeverityChart(canvas, counts, total, totalEl) {
  const ctx = canvas.getContext('2d');
  const { width, height } = canvas;
  ctx.clearRect(0, 0, width, height);

  const centerX = width / 2;
  const centerY = height / 2;
  const outerRadius = Math.min(width, height) / 2 - 5;
  const innerRadius = outerRadius * 0.6;

  let startAngle = -Math.PI / 2; // Сверху

  for (const sev of SEVERITY_ORDER) {
    const count = counts[sev];
    if (!count) continue;

    const sliceAngle = (count / total) * Math.PI * 2;
    const endAngle = startAngle + sliceAngle;

    // Сегмент
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.arc(centerX, centerY, outerRadius, startAngle, endAngle);
    ctx.closePath();
    ctx.fillStyle = SEVERITY_COLORS[sev] || '#ccc';
    ctx.fill();

    startAngle = endAngle;
  }

  // Внутренняя "дыра"
  ctx.beginPath();
  ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
  ctx.fillStyle = '#ffffff';
  ctx.fill();

  totalEl.textContent = total.toString();
}

function renderSeverityLegend(container, counts, total) {
  container.innerHTML = '';

  for (const sev of SEVERITY_ORDER) {
    const count = counts[sev];
    if (!count) continue;

    const percent = ((count / total) * 100).toFixed(1);
    const row = document.createElement('div');
    row.className = 'severity-row';

    row.innerHTML = `
      <div class="severity-label">
        <span class="severity-color" style="background-color:${SEVERITY_COLORS[sev]}"></span>
        <span>${SEVERITY_LABELS[sev] || sev}</span>
      </div>
      <div class="severity-bar-wrap">
        <div class="severity-bar" style="width:${percent}%"></div>
      </div>
      <div class="severity-count">${count}</div>
    `;

    container.appendChild(row);
  }
}

/**
 * ==== ФУНКЦИИ ВЗАИМОДЕЙСТВИЯ С БЭКЕНДОМ ====
 */

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

    // После анализа обновляем диаграмму
    await loadSeverityOverview(3);
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
      `События собраны.\nСохранено: ${saved}\n\nЗагрузка инцидентов...`
    );

    // После сбора событий запускаем анализ и обновляем диаграмму
    await runAnalysis();
  } catch (error) {
    showOutput(`Ошибка при сборе событий:\n${error.message}`);
  }
}

// Новая функция для загрузки инцидентов напрямую
async function loadIncidents() {
  showOutput('Загрузка инцидентов...');
  try {
    const data = await apiCall(`${API_BASE}/api/incidents/?limit=50&offset=0`);

    if (!Array.isArray(data) || data.length === 0) {
      showOutput('Инциденты загружены: данных нет.');
      return;
    }

    showOutput(
      `Инциденты загружены (${data.length} шт.):\n\n` +
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    showOutput(`Ошибка при загрузке инцидентов:\n${error.message}`);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('loadEventsBtn')
    .addEventListener('click', async () => {
      await loadEvents();
      await loadSeverityOverview(3);
    });

  document.getElementById('runAnalysisBtn')
    .addEventListener('click', runAnalysis);

  document.getElementById('generateMockBtn')
    .addEventListener('click', collectFileEvents);

  // Добавляем кнопку для загрузки инцидентов
  const loadIncidentsBtn = document.getElementById('loadIncidentsBtn');
  if (loadIncidentsBtn) {
  loadIncidentsBtn.addEventListener('click', loadIncidents);
  }

  // Автоматически подгружаем сводку за последние 3 дня при старте
  loadSeverityOverview(3).catch(() => {});
});