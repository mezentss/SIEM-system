const API_BASE = 'http://127.0.0.1:8000';

const SEEN_INCIDENTS_KEY = 'siem_seen_incident_ids';
const POLL_INTERVAL_MS = 10000;

let allIncidents = [];
let seenIncidentIds = new Set();

function loadSeenIncidentIds() {
  try {
    const raw = localStorage.getItem(SEEN_INCIDENTS_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      seenIncidentIds = new Set(Array.isArray(arr) ? arr : []);
    }
  } catch (_) {
    seenIncidentIds = new Set();
  }
}

function saveSeenIncidentIds() {
  try {
    localStorage.setItem(SEEN_INCIDENTS_KEY, JSON.stringify([...seenIncidentIds]));
  } catch (_) {}
}

function showOutput(text) {
  const outputArea = document.getElementById('outputArea');
  if (outputArea) outputArea.textContent = text;
}

async function apiCall(url, options = {}) {
  const response = await window.electronAPI.fetch(url, options);
  if (response && typeof response === 'object' && typeof response.ok === 'boolean') {
    if (!response.ok) {
      let text = '';
      if (typeof response.text === 'function') {
        try {
          text = await response.text();
        } catch (_) {}
      }
      throw new Error(text || `HTTP ${response.status}`);
    }
    if (typeof response.json === 'function') {
      return response.json();
    }
  }
  return response;
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
    await checkNewIncidents();
    await loadIncidentsAndChart();
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
    await checkNewIncidents();
    await loadIncidentsAndChart();
  } catch (error) {
    showOutput(`Ошибка при сборе событий:\n${error.message}`);
  }
}

function showNewIncidentToast(incident) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const description = toRussianDescription(incident);
  const msg = `Обнаружен новый инцидент: ${description}`;
  const toast = document.createElement('div');
  toast.className = 'toast toast-new-incident';
  toast.setAttribute('role', 'alert');
  toast.textContent = msg;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-visible'));
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => toast.remove(), 300);
  }, 6000);
}

async function fetchIncidents() {
  const data = await apiCall(`${API_BASE}/api/incidents/?limit=500&offset=0`);
  return Array.isArray(data) ? data : [];
}

async function loadEventsHistory() {
  const listEl = document.getElementById('eventsHistory');
  if (!listEl) return;
  try {
    const data = await apiCall(`${API_BASE}/api/events/?limit=20&offset=0`);
    listEl.innerHTML = '';
    if (!Array.isArray(data) || data.length === 0) {
      listEl.innerHTML = '<div class="history-empty">Событий нет</div>';
      return;
    }
    for (const ev of data) {
      const dt = ev.ts ? new Date(ev.ts) : null;
      const timeStr = dt ? dt.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
      const title = `${ev.event_type || ''} [${ev.severity || ''}]`.trim();
      const meta = `${timeStr} · ${ev.source_category || ''} · ${ev.source_os || ''}`;
      const item = document.createElement('div');
      item.className = 'history-item';
      item.innerHTML = `<div class="history-item-title">${escapeHtml(title || 'Событие')}</div><div class="history-item-meta">${escapeHtml(meta)}</div>`;
      listEl.appendChild(item);
    }
  } catch (_) {
    listEl.innerHTML = '<div class="history-empty">Не удалось загрузить события</div>';
  }
}

async function loadNotificationsHistory() {
  const listEl = document.getElementById('notificationsHistory');
  if (!listEl) return;
  try {
    const data = await apiCall(`${API_BASE}/api/notifications/?limit=20&offset=0`);
    listEl.innerHTML = '';
    if (!Array.isArray(data) || data.length === 0) {
      listEl.innerHTML = '<div class="history-empty">Уведомлений нет</div>';
      return;
    }
    for (const n of data) {
      const dt = n.created_at ? new Date(n.created_at) : null;
      const timeStr = dt ? dt.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
      const title = n.title || 'Уведомление';
      const metaParts = [];
      if (n.severity) metaParts.push(n.severity);
      if (n.notification_type) metaParts.push(n.notification_type);
      metaParts.push(timeStr);
      const meta = metaParts.join(' · ');
      const item = document.createElement('div');
      item.className = 'history-item';
      item.innerHTML = `<div class="history-item-title">${escapeHtml(title)}</div><div class="history-item-meta">${escapeHtml(meta)}</div>`;
      listEl.appendChild(item);
    }
  } catch (_) {
    listEl.innerHTML = '<div class="history-empty">Не удалось загрузить уведомления</div>';
  }
}

async function loadHistory() {
  await Promise.all([loadEventsHistory(), loadNotificationsHistory()]);
}

async function checkNewIncidents() {
  try {
    const list = await fetchIncidents();
    let changed = false;
    for (const inc of list) {
      const id = inc.id;
      if (id != null && !seenIncidentIds.has(id)) {
        seenIncidentIds.add(id);
        changed = true;
        showNewIncidentToast(inc);
      }
    }
    if (changed) saveSeenIncidentIds();
  } catch (_) {}
}

function severityOrder(s) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, warning: 4 };
  return order[s] ?? 5;
}

function buildSeverityCounts(incidents) {
  const counts = {};
  for (const inc of incidents) {
    const s = inc.severity || 'unknown';
    counts[s] = (counts[s] || 0) + 1;
  }
  const entries = Object.entries(counts);
  entries.sort((a, b) => severityOrder(a[0]) - severityOrder(b[0]));
  return entries;
}

const SEVERITY_COLORS = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f1c40f',
  low: '#2ecc71',
  warning: '#9b59b6',
  unknown: '#95a5a6'
};

const SEVERITY_LABELS = {
  critical: 'Критический',
  high: 'Высокий',
  medium: 'Средний',
  low: 'Низкий',
  warning: 'Предупреждение',
  unknown: 'Неизвестно'
};

function renderSeverityChart(counts) {
  const container = document.getElementById('chartContainer');
  if (!container) return;
  container.innerHTML = '';
  if (counts.length === 0) {
    container.innerHTML = '<p class="chart-empty">Нет инцидентов для отображения.</p>';
    return;
  }
  const total = counts.reduce((s, [, n]) => s + n, 0);
  const size = 280;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  canvas.className = 'pie-canvas';
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'Круговая диаграмма инцидентов по серьёзности');

  const ctx = canvas.getContext('2d');
  const cx = size / 2;
  const cy = size / 2;
  const r = Math.min(cx, cy) - 8;
  let startAngle = -Math.PI / 2;

  const segments = [];
  for (const [severity, count] of counts) {
    const ratio = count / total;
    const sweep = ratio * 2 * Math.PI;
    const endAngle = startAngle + sweep;
    segments.push({ severity, startAngle, endAngle, count });
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.closePath();
    ctx.fillStyle = SEVERITY_COLORS[severity] || SEVERITY_COLORS.unknown;
    ctx.fill();
    ctx.strokeStyle = '#fff';
    ctx.lineWidth = 2;
    ctx.stroke();
    startAngle = endAngle;
  }

  function getSegmentAt(angle) {
    const norm = (a) => ((a % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
    const clickNorm = norm(angle + Math.PI / 2);
    for (const seg of segments) {
      const s = norm(seg.startAngle + Math.PI / 2);
      const e = norm(seg.endAngle + Math.PI / 2);
      if (s <= e && clickNorm >= s && clickNorm < e) return seg;
      if (s > e && (clickNorm >= s || clickNorm < e)) return seg;
    }
    return null;
  }

  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left - cx;
    const y = e.clientY - rect.top - cy;
    const d = Math.sqrt(x * x + y * y);
    if (d > r) return;
    const angle = Math.atan2(y, x);
    const seg = getSegmentAt(angle);
    if (seg) openDrilldown(seg.severity);
  });

  canvas.style.cursor = 'pointer';
  container.appendChild(canvas);

  const legend = document.createElement('div');
  legend.className = 'pie-legend';
  for (const [severity, count] of counts) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'pie-legend-item';
    item.setAttribute('data-severity', severity);
    item.innerHTML = `<span class="pie-legend-dot" style="background:${SEVERITY_COLORS[severity] || SEVERITY_COLORS.unknown}"></span><span>${SEVERITY_LABELS[severity] || severity}: ${count}</span>`;
    item.addEventListener('click', () => openDrilldown(severity));
    legend.appendChild(item);
  }
  container.appendChild(legend);
}

function openDrilldown(severity) {
  const mainView = document.getElementById('mainView');
  const detailView = document.getElementById('detailView');
  const titleEl = document.getElementById('drilldownTitle');
  titleEl.textContent = `Подробное описание инцидентов: ${SEVERITY_LABELS[severity] || severity}`;
  const filtered = allIncidents
    .filter((inc) => (inc.severity || 'unknown') === severity)
    .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at));
  renderDrilldownList(filtered);
  if (mainView) mainView.classList.add('hidden');
  if (detailView) detailView.classList.remove('hidden');
}

function backToChart() {
  const mainView = document.getElementById('mainView');
  const detailView = document.getElementById('detailView');
  if (mainView) mainView.classList.remove('hidden');
  if (detailView) detailView.classList.add('hidden');
}

function toRussianDescription(incident) {
  const t = incident.incident_type || '';
  if (t === 'multiple_failed_logins') {
    return 'множественные неуспешные попытки входа';
  }
  if (t === 'repeated_network_errors') {
    const count = incident.details && incident.details.events_count ? incident.details.events_count : null;
    const windowMin = incident.details && incident.details.window_minutes ? incident.details.window_minutes : 60;
    if (count != null) {
      return `повторяющиеся сетевые ошибки: ${count} событий за последние ${windowMin} минут`;
    }
    return 'повторяющиеся сетевые ошибки';
  }
  if (t === 'service_crash_or_restart') {
    const svc = incident.details && (incident.details.service || incident.details.process || incident.details.program);
    if (svc) {
      return `сбой или перезапуск службы ${svc}`;
    }
    return 'сбой или перезапуск службы';
  }
  return incident.description || 'инцидент безопасности';
}

function renderDrilldownList(incidents) {
  const listEl = document.getElementById('drilldownList');
  if (!listEl) return;
  listEl.innerHTML = '';
  if (incidents.length === 0) {
    listEl.innerHTML = '<p class="drilldown-empty">Нет инцидентов в этой категории.</p>';
    return;
  }
  const header = document.createElement('div');
  header.className = 'drilldown-row drilldown-row-header';
  header.innerHTML = '<div class="drilldown-row-desc">Описание ошибки</div><div class="drilldown-row-program">Приложение/служба</div><div class="drilldown-row-time-h">Время обнаружения</div>';
  listEl.appendChild(header);
  for (const inc of incidents) {
    const dt = inc.detected_at ? new Date(inc.detected_at) : null;
    const timeStr = dt ? dt.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
    const program =
      (inc.details && (inc.details.service || inc.details.process || inc.details.program)) ||
      inc.incident_type ||
      '—';
    const description = toRussianDescription(inc);
    const row = document.createElement('div');
    row.className = 'drilldown-row';
    row.innerHTML = `
      <div class="drilldown-row-desc">${escapeHtml(description)}</div>
      <div class="drilldown-row-program">${escapeHtml(program)}</div>
      <div class="drilldown-row-time-h">${escapeHtml(timeStr)}</div>
    `;
    listEl.appendChild(row);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function loadIncidentsAndChart() {
  try {
    allIncidents = await fetchIncidents();
    const counts = buildSeverityCounts(allIncidents);
    renderSeverityChart(counts);
    await loadHistory();
  } catch (_) {
    const container = document.getElementById('chartContainer');
    if (container) container.innerHTML = '<p class="chart-empty">Не удалось загрузить инциденты.</p>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadSeenIncidentIds();
  document.getElementById('loadEventsBtn').addEventListener('click', loadEvents);
  document.getElementById('runAnalysisBtn').addEventListener('click', runAnalysis);
  document.getElementById('generateMockBtn').addEventListener('click', collectFileEvents);
  document.getElementById('backToChartBtn').addEventListener('click', backToChart);

  loadIncidentsAndChart();
  checkNewIncidents();

  setInterval(async () => {
    try {
      await apiCall(`${API_BASE}/api/analyze/run?since_minutes=60`, { method: 'POST' });
    } catch (_) {}
    checkNewIncidents();
    loadIncidentsAndChart();
  }, POLL_INTERVAL_MS);
});