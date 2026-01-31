const API_BASE = 'http://127.0.0.1:8000';

function showOutput(text) {
  const outputArea = document.getElementById('outputArea');
  outputArea.textContent = text;
}

async function apiCall(url, options = {}) {
  try {
    return await window.electronAPI.fetch(url, options);
  } catch (error) {
    const message = error && typeof error.message === 'string' ? error.message : String(error);

    if (
      message.includes('Failed to fetch') ||
      message.includes('fetch failed') ||
      message.includes('NetworkError')
    ) {
      throw new Error('Backend недоступен');
    }

    throw new Error(message || 'Ошибка связи с backend');
  }
}

/**
 * ==== БЛОК: агрегация и диаграмма по серьёзности СЕКЦИЙ ====
 */

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const SEVERITY_LABELS = {
  critical: 'Критическая',
  high: 'Высокая',
  medium: 'Средняя',
  low: 'Низкая',
};
const SEVERITY_COLORS = {
  critical: '#d62728',
  high: '#1f77b4',
  medium: '#ff7f0e',
  low: '#6baed6',
};

const INCIDENT_TYPE_LABELS = {
  multiple_failed_logins: 'Множественные неудачные попытки входа',
  repeated_network_errors: 'Повторяющиеся сетевые ошибки',
  service_crash_or_restart: 'Сбой или перезапуск службы',
};

const appState = {
  incidents: [],
  incidentsLoading: false,
  incidentsError: null,
  incidentsLastUpdatedAt: 0,
  pollingTimerId: null,
  pollingInFlight: false,
  severitySlices: [],
};

function getRoute() {
  const raw = (window.location.hash || '').replace(/^#/, '');
  const [path, queryString] = raw.split('?');
  const params = new URLSearchParams(queryString || '');

  const view = path || 'dashboard';
  const severity = (params.get('severity') || '').toLowerCase();
  const mode = (params.get('mode') || '').toLowerCase();

  return {
    view,
    severity,
    mode,
  };
}

function navigateToDashboard() {
  window.location.hash = '#dashboard';
}

function navigateToIncidents(severity) {
  const sev = (severity || '').toLowerCase();
  window.location.hash = `#incidents?severity=${encodeURIComponent(sev)}`;
}

function navigateToIncidentsList(severity) {
  const sev = (severity || '').toLowerCase();
  window.location.hash = `#incidents?severity=${encodeURIComponent(sev)}&mode=list`;
}

function setView(view) {
  const dashboardEl = document.getElementById('view-dashboard');
  const incidentsEl = document.getElementById('view-incidents');

  if (!dashboardEl || !incidentsEl) {
    return;
  }

  if (view === 'incidents') {
    dashboardEl.hidden = true;
    incidentsEl.hidden = false;
    return;
  }

  dashboardEl.hidden = false;
  incidentsEl.hidden = true;
}

function formatDateTimeParts(isoString) {
  const ts = Date.parse(isoString || '');
  if (Number.isNaN(ts)) {
    return { date: '-', time: '-' };
  }
  const d = new Date(ts);
  return {
    date: d.toLocaleDateString('ru-RU'),
    time: d.toLocaleTimeString('ru-RU'),
  };
}

function getIncidentPlace(details) {
  const d = details || {};
  const place = (
    d.application ||
    d.service ||
    d.process ||
    d.app ||
    d.source ||
    d.detector ||
    d.origin ||
    ''
  );

  const normalized = String(place || '').trim();
  if (!normalized) return 'Не определено';
  if (/^\d+$/.test(normalized)) return 'Не определено';
  return normalized;
}

function setIncidentModalOpen(isOpen) {
  const modal = document.getElementById('incidentModal');
  if (!modal) return;

  modal.hidden = !isOpen;
}

function openIncidentModal(incident) {
  const modalTitle = document.getElementById('incidentModalTitle');
  const modalSubtitle = document.getElementById('incidentModalSubtitle');
  const modalDate = document.getElementById('incidentModalDate');
  const modalTime = document.getElementById('incidentModalTime');
  const modalSeverity = document.getElementById('incidentModalSeverity');
  const modalType = document.getElementById('incidentModalType');
  const modalPlace = document.getElementById('incidentModalPlace');
  const modalDescription = document.getElementById('incidentModalDescription');
  const modalDetails = document.getElementById('incidentModalDetails');

  if (
    !modalTitle ||
    !modalSubtitle ||
    !modalDate ||
    !modalTime ||
    !modalSeverity ||
    !modalType ||
    !modalPlace ||
    !modalDescription ||
    !modalDetails
  ) {
    return;
  }

  const parts = formatDateTimeParts(incident?.detected_at);
  const sev = (incident?.severity || '').toLowerCase();
  const place = getIncidentPlace(incident?.details);
  const desc = incident?.friendly_description || incident?.description || '-';
  const typeCode = incident?.incident_type || '';
  const typeLabel = INCIDENT_TYPE_LABELS[typeCode] || typeCode || '-';

  modalTitle.textContent = `Инцидент #${incident?.id ?? '-'}`;
  modalSubtitle.textContent = [
    SEVERITY_LABELS[sev] ? `Серьёзность: ${SEVERITY_LABELS[sev]}` : '',
    typeLabel ? `Тип: ${typeLabel}` : '',
  ].filter(Boolean).join(' · ');

  modalDate.textContent = parts.date;
  modalTime.textContent = parts.time;
  modalSeverity.textContent = SEVERITY_LABELS[sev] || incident?.severity || '-';
  modalType.textContent = typeLabel;
  modalPlace.textContent = place;
  modalDescription.textContent = desc;

  try {
    modalDetails.textContent = JSON.stringify(incident?.details || {}, null, 2);
  } catch (_e) {
    modalDetails.textContent = '{}';
  }

  setIncidentModalOpen(true);
}

function closeIncidentModal() {
  setIncidentModalOpen(false);
}

async function refreshIncidents(options = {}) {
  if (appState.incidentsLoading) {
    return appState.incidents;
  }

  appState.incidentsLoading = true;
  appState.incidentsError = null;

  try {
    const data = await apiCall(`${API_BASE}/api/incidents/?limit=500&offset=0`);
    const arr = Array.isArray(data) ? data : [];
    arr.sort((a, b) => {
      const ta = Date.parse(a?.detected_at || '') || 0;
      const tb = Date.parse(b?.detected_at || '') || 0;
      return tb - ta;
    });

    appState.incidents = arr;
    appState.incidentsLastUpdatedAt = Date.now();
    return arr;
  } catch (error) {
    appState.incidentsError = error;
    if (!options.silent) {
      throw error;
    }
    return appState.incidents;
  } finally {
    appState.incidentsLoading = false;
  }
}

function startIncidentsPolling() {
  if (appState.pollingTimerId) {
    return;
  }

  appState.pollingTimerId = setInterval(() => {
    pollTick().catch(() => {});
  }, 10000);
}

async function pollTick() {
  if (appState.pollingInFlight) {
    return;
  }

  appState.pollingInFlight = true;
  try {
    // Чтобы появлялись новые инциденты без ручного клика, периодически запускаем анализ.
    // Дедупликация на backend защищает от спама одинаковыми инцидентами.
    await apiCall(`${API_BASE}/api/analyze/run?since_minutes=60`, { method: 'POST' });
  } catch (_e) {
    // В polling ошибки не показываем пользователю (не спамим), просто пропускаем тик.
  }

  try {
    await refreshIncidents({ silent: true });
    await renderCurrentRoute({ silent: true });
  } finally {
    appState.pollingInFlight = false;
  }
}

async function renderCurrentRoute(options = {}) {
  const route = getRoute();
  if (route.view === 'incidents') {
    setView('incidents');
    await renderIncidentsView(route, options);
    return;
  }

  setView('dashboard');
  await loadSeverityOverview(3, options);
}

async function loadSeverityOverview(lastDays = 3, options = {}) {
  const canvas = document.getElementById('severityChart');
  const legendContainer = document.getElementById('severityLegend');
  const totalEl = document.getElementById('severityTotal');
  const periodEl = document.getElementById('severityPeriod');

  if (!canvas || !legendContainer || !totalEl || !periodEl) {
    return;
  }

  periodEl.textContent = `за последние ${lastDays} дня`;

  try {
    const data = await refreshIncidents({ silent: !!options.silent });

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

  let startAngle = -Math.PI / 2;
  appState.severitySlices = [];
  let normalizedStart = 0;

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

    appState.severitySlices.push({
      severity: sev,
      start: normalizedStart,
      end: normalizedStart + sliceAngle,
    });

    normalizedStart += sliceAngle;

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

    row.dataset.severity = sev;
    row.classList.add('severity-row-clickable');
    row.addEventListener('click', () => {
      navigateToIncidents(sev);
    });

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

    await refreshIncidents({ silent: true });
    await renderCurrentRoute({ silent: true });
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

    await runAnalysis();
  } catch (error) {
    showOutput(`Ошибка при сборе событий:\n${error.message}`);
  }
}

// Новая функция для загрузки инцидентов напрямую
async function loadIncidents() {
  showOutput('Загрузка инцидентов...');
  try {
    const data = await refreshIncidents();

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

function renderIncidentsTable(incidents) {
  const tbody = document.getElementById('incidentsTbody');
  if (!tbody) return;

  tbody.textContent = '';

  for (const incident of incidents) {
    const tr = document.createElement('tr');

    const parts = formatDateTimeParts(incident?.detected_at);
    const typeCode = incident?.incident_type || '';
    const type = INCIDENT_TYPE_LABELS[typeCode] || typeCode || '-';
    const place = getIncidentPlace(incident?.details);
    const desc = incident?.friendly_description || incident?.description || '-';

    const tdDate = document.createElement('td');
    tdDate.textContent = parts.date;
    tr.appendChild(tdDate);

    const tdTime = document.createElement('td');
    tdTime.textContent = parts.time;
    tr.appendChild(tdTime);

    const tdType = document.createElement('td');
    tdType.textContent = type;
    tr.appendChild(tdType);

    const tdPlace = document.createElement('td');
    tdPlace.textContent = place;
    tr.appendChild(tdPlace);

    const tdDesc = document.createElement('td');
    tdDesc.textContent = desc;
    tr.appendChild(tdDesc);

    const tdActions = document.createElement('td');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'details-btn';
    btn.textContent = 'Детали';
    btn.addEventListener('click', () => {
      openIncidentModal(incident);
    });
    tdActions.appendChild(btn);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  }
}

async function renderIncidentsView(route, options = {}) {
  const titleEl = document.getElementById('incidentsTitle');
  const subtitleEl = document.getElementById('incidentsSubtitle');
  const statusEl = document.getElementById('incidentsStatus');
  const emptyEl = document.getElementById('incidentsEmpty');
  const tableWrap = document.querySelector('.incidents-table-wrap');

  if (!titleEl || !subtitleEl || !statusEl || !emptyEl) {
    return;
  }

  const sev = (route?.severity || '').toLowerCase();
  const isAll = !sev || sev === 'all';

  titleEl.textContent = isAll ? 'Инциденты' : `Инциденты: ${SEVERITY_LABELS[sev] || sev}`;
  subtitleEl.textContent = isAll ? 'Все категории' : `Категория: ${SEVERITY_LABELS[sev] || sev}`;

  if (!options.silent) {
    statusEl.textContent = appState.incidentsLoading ? 'Загрузка...' : '';
  } else {
    statusEl.textContent = '';
  }

  if (!appState.incidentsLastUpdatedAt) {
    if (!options.silent) {
      statusEl.textContent = 'Загрузка...';
    }
    await refreshIncidents({ silent: !!options.silent });
    if (!options.silent) {
      statusEl.textContent = '';
    }
  }

  if (appState.incidentsError && !options.silent) {
    statusEl.textContent = `Ошибка загрузки: ${appState.incidentsError.message}`;
  }

  const filtered = (appState.incidents || []).filter((incident) => {
    if (isAll) return true;
    return (incident?.severity || '').toLowerCase() === sev;
  });

  filtered.sort((a, b) => {
    const ta = Date.parse(a?.detected_at || '') || 0;
    const tb = Date.parse(b?.detected_at || '') || 0;
    return tb - ta;
  });

  const showList = (route?.mode || '') === 'list';
  if (tableWrap) {
    tableWrap.hidden = !showList;
  }

  if (!showList) {
    emptyEl.hidden = true;
    statusEl.textContent = `Найдено инцидентов: ${filtered.length}. Нажмите «Подробнее», чтобы открыть список.`;
    renderIncidentsTable([]);
    return;
  }

  statusEl.textContent = '';
  emptyEl.hidden = filtered.length !== 0;
  renderIncidentsTable(filtered);
}

function setupSeverityChartClick() {
  const canvas = document.getElementById('severityChart');
  if (!canvas) return;

  canvas.addEventListener('click', (e) => {
    if (!appState.severitySlices || appState.severitySlices.length === 0) {
      return;
    }

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const dx = x - centerX;
    const dy = y - centerY;
    const distance = Math.sqrt(dx * dx + dy * dy);

    const outerRadius = Math.min(rect.width, rect.height) / 2 - 5;
    const innerRadius = outerRadius * 0.6;

    if (distance < innerRadius || distance > outerRadius) {
      return;
    }

    const rawAngle = Math.atan2(dy, dx);
    let normalized = rawAngle + Math.PI / 2;
    if (normalized < 0) {
      normalized += Math.PI * 2;
    }

    for (const slice of appState.severitySlices) {
      if (normalized >= slice.start && normalized < slice.end) {
        navigateToIncidents(slice.severity);
        return;
      }
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const loadEventsBtn = document.getElementById('loadEventsBtn');
  if (loadEventsBtn) {
    loadEventsBtn.addEventListener('click', async () => {
      await loadEvents();
      await loadSeverityOverview(3);
    });
  }

  const runAnalysisBtn = document.getElementById('runAnalysisBtn');
  if (runAnalysisBtn) {
    runAnalysisBtn.addEventListener('click', runAnalysis);
  }

  const collectBtn = document.getElementById('generateMockBtn');
  if (collectBtn) {
    collectBtn.addEventListener('click', collectFileEvents);
  }

  const loadIncidentsBtn = document.getElementById('loadIncidentsBtn');
  if (loadIncidentsBtn) {
    loadIncidentsBtn.addEventListener('click', () => {
      navigateToIncidents('all');
    });
  }

  const backBtn = document.getElementById('backToDashboardBtn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      navigateToDashboard();
    });
  }

  const showListBtn = document.getElementById('showIncidentsListBtn');
  if (showListBtn) {
    showListBtn.addEventListener('click', () => {
      const route = getRoute();
      navigateToIncidentsList(route.severity || 'all');
    });
  }

  const modalCloseBtn = document.getElementById('incidentModalCloseBtn');
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', closeIncidentModal);
  }

  const modalBackdrop = document.getElementById('incidentModalBackdrop');
  if (modalBackdrop) {
    modalBackdrop.addEventListener('click', closeIncidentModal);
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeIncidentModal();
    }
  });

  setupSeverityChartClick();

  window.addEventListener('hashchange', () => {
    renderCurrentRoute({ silent: false }).catch(() => {});
  });

  if (!window.location.hash) {
    navigateToDashboard();
  }

  refreshIncidents({ silent: true }).catch(() => {});
  renderCurrentRoute({ silent: false }).catch(() => {});
  startIncidentsPolling();
});