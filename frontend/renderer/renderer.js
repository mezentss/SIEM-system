const API_BASE = 'http://127.0.0.1:8000';

const SEEN_INCIDENTS_KEY = 'siem_seen_incident_ids';
const POLL_INTERVAL_MS = 10000;

const AUTH_CREDS_KEY = 'siem_auth_creds';

let allIncidents = [];
let seenIncidentIds = new Set();
let drilldownSeverity = null;
let drilldownQuery = '';

let currentUser = null;

function getAuthHeaders() {
  const creds = localStorage.getItem(AUTH_CREDS_KEY);
  console.log('[DEBUG] Retrieved creds from localStorage:', creds ? 'found' : 'not found');
  if (!creds) return {};
  const [username, password] = atob(creds).split(':');
  console.log('[DEBUG] Parsed username:', username, 'password length:', password ? password.length : 0);
  return {
    Authorization: 'Basic ' + btoa(username + ':' + password)
  };
}

async function apiCall(url, options = {}) {
  const fetchFn = window.electronAPI?.fetch || window.fetch;
  const resp = await fetchFn(API_BASE + url, {
    headers: { ...getAuthHeaders(), ...(options.headers || {}) },
    ...options,
  });
  console.log('[DEBUG] fetch response:', resp);
  // If electronAPI.fetch returns parsed JSON directly
  if (resp && typeof resp === 'object' && !resp.status && !resp.statusCode) {
    // Assume it's already parsed JSON and successful
    return resp;
  }
  // Handle normal fetch Response object
  const status = resp.status ?? resp.statusCode ?? resp.ok ? 200 : 500;
  const statusText = resp.statusText ?? resp.statusMessage ?? '';
  console.log('[DEBUG] status:', status, 'statusText:', statusText);
  if (status !== 200) {
    if (status === 401) {
      logout();
    }
    throw new Error(`HTTP ${status}: ${statusText}`);
  }
  const text = await resp.text();
  console.log('[DEBUG] response text:', text);
  try {
    return JSON.parse(text);
  } catch (_) {
    throw new Error('Invalid JSON response');
  }
}

function logout() {
  localStorage.removeItem(AUTH_CREDS_KEY);
  currentUser = null;
  if (window.location.pathname.endsWith('login.html')) {
    return;
  }
  window.location.href = 'login.html';
}

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

function formatNumberRu(n) {
  const num = Number(n);
  if (!Number.isFinite(num)) return '—';
  return num.toLocaleString('ru-RU');
}

function isSameDay(a, b) {
  const da = new Date(a);
  const db = new Date(b);
  return (
    da.getFullYear() === db.getFullYear() &&
    da.getMonth() === db.getMonth() &&
    da.getDate() === db.getDate()
  );
}

function updateDashboardStats({ events = [], incidents = [] } = {}) {
  const totalEventsEl = document.getElementById('statTotalEvents');
  const activeIncidentsEl = document.getElementById('statActiveIncidents');
  const alertsTodayEl = document.getElementById('statAlertsToday');
  const healthEl = document.getElementById('statSystemHealth');

  const totalEvents = Array.isArray(events) ? events.length : 0;
  const totalIncidents = Array.isArray(incidents) ? incidents.length : 0;

  const now = new Date();
  const incidentsToday = (Array.isArray(incidents) ? incidents : []).filter((inc) => {
    const ts = inc?.detected_at;
    return ts ? isSameDay(ts, now) : false;
  }).length;

  const hasCritical = (Array.isArray(incidents) ? incidents : []).some(
    (inc) => (inc?.severity || '').toLowerCase() === 'critical'
  );

  if (totalEventsEl) totalEventsEl.textContent = formatNumberRu(totalEvents);
  if (activeIncidentsEl) activeIncidentsEl.textContent = formatNumberRu(totalIncidents);
  if (alertsTodayEl) alertsTodayEl.textContent = formatNumberRu(incidentsToday);

  if (healthEl) {
    healthEl.textContent = hasCritical ? 'Требует внимания' : 'Норма';
    healthEl.style.color = hasCritical ? '#b63c3b' : '#2c3e50';
  }
}

async function loadEvents() {
  showOutput('Загрузка событий...');
  try {
    const data = await apiCall('/api/events/?limit=50&offset=0');
    if (!Array.isArray(data) || data.length === 0) {
      showOutput('События загружены: данных нет.');
      return;
    }
    showOutput(
      `События загружены (${data.length} шт.):\n\n` +
      JSON.stringify(data, null, 2)
    );
  } catch (e) {
    showOutput('Ошибка при загрузке событий: ' + e.message);
  }
}

async function runAnalysis() {
  showOutput('Запуск анализа...');
  try {
    const data = await apiCall(
      '/api/analyze/run?since_minutes=60',
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
      '/api/collect/file?max_lines=200',
      { method: 'POST' }
    );
    const collected = data?.collected_count ?? 0;
    const saved = data?.saved_count ?? 0;
    const filePath = data?.file_path ?? 'unknown';
    if (collected === 0) {
      showOutput('В файле логов нет новых событий.\nПуть к файлу: ' + filePath);
      return;
    }
    showOutput(
      `События собраны.\nСохранено: ${saved}\nПуть: ${filePath}\n\nЗагрузка событий...`
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
  const data = await apiCall('/api/incidents/?limit=500&offset=0');
  return Array.isArray(data) ? data : [];
}

async function loadEventsHistory() {
  const listEl = document.getElementById('eventsHistory');
  if (!listEl) return;
  try {
    const data = await apiCall('/api/events/?limit=20&offset=0');
    listEl.innerHTML = '';
    if (!Array.isArray(data) || data.length === 0) {
      listEl.innerHTML = '<div class="history-empty">Событий нет</div>';
      return;
    }
    for (const ev of data) {
      const dt = ev.ts ? new Date(ev.ts) : null;
      const timeStr = dt ? dt.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
      const title = `${ev.event_type || ''} [${ev.severity || ''}]`.trim();
      
      // Translate source category
      const sourceCat = {
        'service': 'Сервис',
        'user_process': 'Приложение',
        'os': 'ОС'
      }[ev.source_category] || ev.source_category;
      
      const meta = `${timeStr} · ${sourceCat} · ${ev.source_os || ''}`;
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
    const data = await apiCall('/api/notifications/?limit=20&offset=0');
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
  // Инициализируем все категории с нулём
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) {
    const s = (inc.severity || 'unknown').toLowerCase();
    if (s in counts) {
      counts[s] = (counts[s] || 0) + 1;
    } else {
      counts.unknown = (counts.unknown || 0) + 1;
    }
  }
  // Возвращаем в порядке важности
  const order = ['critical', 'high', 'medium', 'low'];
  return order.map(s => [s, counts[s] || 0]);
}

const SEVERITY_COLORS = {
  critical: '#ed4246',
  high: '#fa7415', 
  medium: '#ecb30c',
  low: '#3c83f7',
  warning: '#6c757d',
  unknown: '#495057',
};

const SEVERITY_LABELS = {
  critical: 'Критический',
  high: 'Высокий',
  medium: 'Средний',
  low: 'Низкий',
  warning: 'Предупреждение',
  unknown: 'Неизвестно',
};

function buildEventsByHour(events) {
  // Показываем события за последние 24 часа с группировкой по часам
  const now = new Date();
  const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 часа назад
  const buckets = {};
  for (const ev of events) {
    if (!ev.ts) continue;
    const ts = new Date(ev.ts);
    if (ts < cutoff) continue;
    // Округляем до часа для группировки
    const hour = new Date(ts);
    hour.setMinutes(0, 0, 0);
    const moscowMs = hour.getTime() + 3 * 60 * 60 * 1000;
    const moscow = new Date(moscowMs);
    const label = moscow.toLocaleString('ru-RU', {
      day: '2-digit',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit'
    });
    if (!buckets[label]) {
      buckets[label] = { critical: 0, high: 0, medium: 0, low: 0 };
    }
    const s = ev.severity || 'low';
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') {
      buckets[label][s] += 1;
    }
  }
  // Сортируем метки по убыванию (новые слева)
  const labels = Object.keys(buckets).sort((a, b) => {
    const da = new Date(a);
    const db = new Date(b);
    return db - da; // Обратный порядок - новые слева
  });
  return { labels, buckets };
}

function renderEventsByHourChart(data) {
  const canvas = document.getElementById('eventsByHourChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);
  const paddingLeft = 50;
  const paddingBottom = 30;
  const paddingTop = 10;
  const plotWidth = width - paddingLeft - 10;
  const plotHeight = height - paddingTop - paddingBottom;
  const labels = data.labels;
  if (!labels.length) {
    ctx.fillStyle = '#7f8c8d';
    ctx.font = '12px sans-serif';
    ctx.fillText('Событий за последние 24 часа нет', paddingLeft, paddingTop + plotHeight / 2);
    return;
  }
  let maxCount = 0;
  for (const label of labels) {
    const b = data.buckets[label];
    const total = b.critical + b.high + b.medium + b.low;
    if (total > maxCount) maxCount = total;
  }
  if (maxCount === 0) maxCount = 1;
    const barWidth = Math.max(1, plotWidth / (labels.length * 40));
    const gap = barWidth * 5;
  ctx.strokeStyle = '#bdc3c7';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(paddingLeft, paddingTop);
  ctx.lineTo(paddingLeft, paddingTop + plotHeight);
  ctx.lineTo(paddingLeft + plotWidth, paddingTop + plotHeight);
  ctx.stroke();
  ctx.font = '10px sans-serif';
  ctx.fillStyle = '#7f8c8d';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(labels.length / 6));
  labels.forEach((label, i) => {
    if (i % step !== 0 && i !== labels.length - 1) return;
    // Позиция метки соответствует столбцу (справа налево)
    const x = paddingLeft + plotWidth - (i + 1) * (barWidth + gap) + gap + barWidth / 2;
    const text = label;
    ctx.save();
    ctx.translate(x, paddingTop + plotHeight + 12);
    ctx.rotate(-Math.PI / 4);
    ctx.fillText(text, 0, 0);
    ctx.restore();
  });
  labels.forEach((label, i) => {
    const b = data.buckets[label];
    // Рисуем столбцы справа налево (новые слева)
    const x = paddingLeft + plotWidth - (i + 1) * (barWidth + gap) + gap;
    let y = paddingTop + plotHeight;
    function drawStack(count, color) {
      if (!count) return;
      const h = (count / maxCount) * plotHeight;
      y -= h;
      ctx.fillStyle = color;
      ctx.fillRect(x, y, barWidth, h);
    }
    drawStack(b.low, SEVERITY_COLORS.low);
    drawStack(b.medium, SEVERITY_COLORS.medium);
    drawStack(b.high, SEVERITY_COLORS.high);
    drawStack(b.critical, SEVERITY_COLORS.critical);
  });
}

function renderSeverityChart(counts) {
  const container = document.getElementById('chartContainer');
  if (!container) return;
  container.innerHTML = '';
  if (counts.length === 0) {
    container.innerHTML = '<p class="chart-empty">Нет инцидентов для отображения.</p>';
    return;
  }
  
  // Фильтруем только ненулевые значения для диаграммы
  const nonZeroCounts = counts.filter(([, n]) => n > 0);
  
  if (nonZeroCounts.length === 0) {
    container.innerHTML = '<p class="chart-empty">Нет инцидентов для отображения.</p>';
    return;
  }
  
  const total = nonZeroCounts.reduce((s, [, n]) => s + n, 0);
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
  for (const [severity, count] of nonZeroCounts) {
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
  // Показываем все категории в легенде (включая нулевые)
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
  const breadcrumbs = document.getElementById('detailBreadcrumbs');

  drilldownSeverity = severity;
  drilldownQuery = '';

  const label = SEVERITY_LABELS[severity] || severity;
  if (titleEl) titleEl.textContent = `Инциденты: ${label}`;
  if (breadcrumbs) breadcrumbs.textContent = `Панель / Инциденты / ${label}`;

  const searchEl = document.getElementById('detailSearchInput');
  if (searchEl) searchEl.value = '';

  renderDrilldown();

  if (mainView) mainView.classList.add('hidden');
  if (detailView) {
    detailView.classList.remove('hidden');
    detailView.setAttribute('aria-hidden', 'false');
  }
}

function backToChart() {
  const mainView = document.getElementById('mainView');
  const detailView = document.getElementById('detailView');
  if (mainView) mainView.classList.remove('hidden');
  if (detailView) {
    detailView.classList.add('hidden');
    detailView.setAttribute('aria-hidden', 'true');
  }
}

function setActiveDetailTab(severity) {
  const tabs = document.querySelectorAll('.detail-tab');
  for (const t of tabs) {
    const s = (t.getAttribute('data-severity') || '').toLowerCase();
    if (s === severity) {
      t.classList.add('detail-tab-active');
      t.setAttribute('aria-selected', 'true');
    } else {
      t.classList.remove('detail-tab-active');
      t.setAttribute('aria-selected', 'false');
    }
  }
}

function incidentMatchesQuery(inc, query) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return true;
  const details = inc?.details || {};
  const service =
    details.service ||
    details.process ||
    details.program ||
    details.application ||
    '';
  const text = [
    toRussianDescription(inc),
    inc?.description || '',
    inc?.friendly_description || '',
    String(service || ''),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return text.includes(q);
}

function renderDrilldown() {
  const severity = drilldownSeverity || 'unknown';
  setActiveDetailTab(severity);

  const filtered = allIncidents
    .filter((inc) => (inc.severity || 'unknown') === severity)
    .filter((inc) => incidentMatchesQuery(inc, drilldownQuery))
    .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at));

  renderDrilldownList(filtered);
}

function toRussianDescription(incident) {
  const t = incident.incident_type || '';
  const details = incident.details || {};
  if (t === 'multiple_failed_logins') {
    return 'множественные неуспешные попытки входа';
  }
  if (t === 'repeated_network_errors') {
    const count = details.events_count;
    const windowMin = details.window_minutes || 60;
    if (count != null) {
      return `повторяющиеся сетевые ошибки: ${count} событий за последние ${windowMin} минут`;
    }
    return 'повторяющиеся сетевые ошибки';
  }
  if (t === 'service_crash_or_restart') {
    const svc = details.service || details.process || details.program;
    if (svc) {
      return `сбой или перезапуск службы ${svc}`;
    }
    return 'сбой или перезапуск службы';
  }
  if (incident.description) {
    return incident.description;
  }
  if (t) {
    return `инцидент безопасности: ${t}`;
  }
  return 'инцидент безопасности';
}

function renderDrilldownList(incidents) {
  const tbody = document.getElementById('drilldownList');
  const emptyEl = document.getElementById('drilldownEmpty');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (emptyEl) emptyEl.classList.toggle('hidden', incidents.length !== 0);

  for (const inc of incidents) {
    const dt = inc.detected_at ? new Date(inc.detected_at) : null;
    const dateStr = dt ? dt.toLocaleDateString('ru-RU', { dateStyle: 'medium' }) : '—';
    const timeStr = dt ? dt.toLocaleTimeString('ru-RU', { timeStyle: 'medium' }) : '—';

    const details = inc.details || {};
    const program =
      details.service ||
      details.process ||
      details.program ||
      details.application ||
      'Не определено';

    const type = toRussianDescription(inc);
    const sev = (inc.severity || 'unknown').toLowerCase();

    const sevLabel = SEVERITY_LABELS[sev] || sev;
    const sevClass =
      sev === 'critical' ? 'detail-sev-critical' :
      sev === 'high' ? 'detail-sev-high' :
      sev === 'medium' ? 'detail-sev-medium' :
      sev === 'low' ? 'detail-sev-low' :
      '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(dateStr)}</td>
      <td>${escapeHtml(timeStr)}</td>
      <td>${escapeHtml(type)}</td>
      <td><span class="detail-sev-badge ${sevClass}">${escapeHtml(sevLabel)}</span></td>
      <td>${escapeHtml(program)}</td>
      <td>${escapeHtml(inc.friendly_description || inc.description || '')}</td>
    `;
    tbody.appendChild(tr);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Event type statistics
function renderEventTypesStats(events) {
  const container = document.getElementById('eventTypesContainer');
  if (!container) return;
  
  const typeCounts = {};
  events.forEach(ev => {
    const type = ev.event_type || 'unknown';
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  });
  
  container.innerHTML = '';
  Object.entries(typeCounts).forEach(([type, count]) => {
    const item = document.createElement('div');
    item.className = 'event-type-item';

    // Translate event types to Russian
    const translatedType = {
      'auth_failed': 'Аутентификация',
      'auth_success': 'Аутентификация',
      'authentication': 'Аутентификация',
      'network_error': 'Сеть',
      'network': 'Сеть',
      'service_crash': 'Сервис',
      'service': 'Сервис',
      'process': 'Процесс',
      'unknown': 'Неизвестно'
    }[type] || type;

    item.innerHTML = `
      <div class="event-type-count">${count}</div>
      <div class="event-type-label">${translatedType}</div>
    `;
    container.appendChild(item);
  });
}

// Recent events table
function renderRecentEvents(events) {
  const tbody = document.getElementById('recentEventsList');
  if (!tbody) return;

  tbody.innerHTML = '';
  events.slice(0, 20).forEach(ev => {
    const dt = ev.ts ? new Date(ev.ts) : null;
    const timeStr = dt ? dt.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
    const type = ev.event_type || '—';
    const severity = ev.severity || 'unknown';
    const source = ev.source_category || '—';
    const status = ev.status === 'resolved' ? 'resolved' : 'active';

    // Translate event types to Russian
    const translatedType = {
      'auth_failed': 'Аутентификация',
      'auth_success': 'Аутентификация',
      'authentication': 'Аутентификация',
      'network_error': 'Сеть',
      'network': 'Сеть',
      'service_crash': 'Сервис',
      'service': 'Сервис',
      'process': 'Процесс',
      'unknown': 'Неизвестно'
    }[type] || type;

    // Translate source categories to Russian
    const translatedSource = {
      'service': 'Сервис',
      'user_process': 'Приложение',
      'os': 'ОС'
    }[source] || source;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(timeStr)}</td>
      <td>${escapeHtml(translatedType)}</td>
      <td><span class="detail-sev-badge detail-sev-${severity}">${escapeHtml(SEVERITY_LABELS[severity] || severity)}</span></td>
      <td>${escapeHtml(translatedSource)}</td>
      <td><span class="event-status ${status}">${status === 'resolved' ? 'Решено' : 'Активно'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// View switching
function switchView(viewName) {
  const views = ['dashboard', 'map', 'reports', 'settings', 'employee'];
  const navItems = document.querySelectorAll('.topbar-nav-item');

  views.forEach(v => {
    const viewEl = document.getElementById(v + 'View');
    if (viewEl) {
      viewEl.classList.toggle('hidden', v !== viewName);
    }
  });

  navItems.forEach(item => {
    const itemView = item.getAttribute('data-view');
    if (itemView === viewName) {
      item.classList.add('topbar-nav-item-active');
    } else {
      item.classList.remove('topbar-nav-item-active');
    }
  });
}

async function loadEventsChart() {
  try {
    const events = await apiCall('/api/events/?limit=500&offset=0');
    const data = buildEventsByHour(events || []);
    renderEventsByHourChart(data);
  } catch (_) {
    const canvas = document.getElementById('eventsByHourChart');
    if (canvas) {
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#7f8c8d';
      ctx.font = '12px sans-serif';
      ctx.fillText('Не удалось загрузить события', 20, canvas.height / 2);
    }
  }
}

async function loadIncidentsAndChart() {
  try {
    allIncidents = await fetchIncidents();
    const counts = buildSeverityCounts(allIncidents);
    renderSeverityChart(counts);
    let eventsForStats = [];
    try {
      const events = await apiCall('/api/events/?limit=500&offset=0');
      eventsForStats = Array.isArray(events) ? events : [];
    } catch (_) {
      eventsForStats = [];
    }
    
    renderEventTypesStats(eventsForStats);
    renderRecentEvents(eventsForStats);
    updateDashboardStats({ events: eventsForStats, incidents: allIncidents });

    const eventsData = buildEventsByHour(eventsForStats || []);
    renderEventsByHourChart(eventsData);
    
    // Render app map
    renderAppMap(eventsForStats);
    renderAppErrorsTable(eventsForStats);
    
    await loadHistory();
  } catch (_) {
    const container = document.getElementById('chartContainer');
    if (container) container.innerHTML = '<p class="chart-empty">Не удалось загрузить инциденты.</p>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadSeenIncidentIds();
  
  // Navigation handlers
  document.querySelectorAll('.topbar-nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const view = item.getAttribute('data-view');
      if (view) switchView(view);
    });
  });
  
  const loadEventsBtn = document.getElementById('loadEventsBtn');
  if (loadEventsBtn) loadEventsBtn.addEventListener('click', loadEvents);
  
  const runAnalysisBtn = document.getElementById('runAnalysisBtn');
  if (runAnalysisBtn) runAnalysisBtn.addEventListener('click', runAnalysis);
  
  const generateMockBtn = document.getElementById('generateMockBtn');
  if (generateMockBtn) generateMockBtn.addEventListener('click', collectFileEvents);
  
  const backToChartBtn = document.getElementById('backToChartBtn');
  if (backToChartBtn) backToChartBtn.addEventListener('click', backToChart);

  const detailView = document.getElementById('detailView');
  if (detailView) detailView.setAttribute('aria-hidden', 'true');

  const tabs = document.querySelectorAll('.detail-tab');
  for (const t of tabs) {
    t.addEventListener('click', () => {
      const sev = (t.getAttribute('data-severity') || '').toLowerCase();
      if (!sev) return;
      openDrilldown(sev);
    });
  }

  const searchEl = document.getElementById('detailSearchInput');
  if (searchEl) {
    searchEl.addEventListener('input', () => {
      drilldownQuery = searchEl.value || '';
      renderDrilldown();
    });
  }

  // Start polling after authentication
  startPolling();
});

// Login page logic
if (window.location.pathname.endsWith('login.html')) {
  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('loginError');
    const btn = e.target.querySelector('button[type="submit"]');

    btn.disabled = true;
    errorEl.classList.add('hidden');

    try {
      const creds = btoa(username + ':' + password);
      console.log('[DEBUG] Saving credentials:', username, 'password length:', password.length);
      localStorage.setItem(AUTH_CREDS_KEY, creds);
      console.log('[DEBUG] Credentials saved to localStorage');

      // Verify credentials were saved
      const savedCreds = localStorage.getItem(AUTH_CREDS_KEY);
      console.log('[DEBUG] Verification - saved creds:', savedCreds ? 'match' : 'failed');

      // Small delay to ensure localStorage is updated
      await new Promise(resolve => setTimeout(resolve, 100));

      const user = await apiCall('/api/auth/me');
      console.log('[DEBUG] Login success, user:', user);
      currentUser = user;
      console.log('[DEBUG] Redirecting to index.html');
      window.location.href = 'index.html';
    } catch (err) {
      console.error('[DEBUG] Login error:', err);
      errorEl.textContent = 'Неверное имя пользователя или пароль';
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
    }
  });
  
  // Check for stored credentials on login page (auto-login)
  (async () => {
    const storedCreds = localStorage.getItem(AUTH_CREDS_KEY);
    if (storedCreds) {
      try {
        const user = await apiCall('/api/auth/me');
        console.log('[DEBUG] Auto-login success:', user);
        window.location.href = 'index.html';
      } catch (_) {
        console.log('[DEBUG] Auto-login failed, showing login form');
      }
    }
  })();
} else {
  // Main app: check auth and role
  (async () => {
    // Check if we have stored credentials
    const storedCreds = localStorage.getItem(AUTH_CREDS_KEY);
    if (!storedCreds) {
      console.log('[DEBUG] No stored credentials, redirecting to login');
      logout();
      return;
    }
    
    try {
      const user = await apiCall('/api/auth/me');
      currentUser = user;
      // Update topbar
      const usernameEl = document.getElementById('topbarUsername');
      const roleEl = document.getElementById('topbarRole');
      if (usernameEl) usernameEl.textContent = user.username || '—';
      if (roleEl) roleEl.textContent = user.role === 'admin' ? 'Администратор' : 'Сотрудник';
      if (user.role === 'admin') {
        // Show all controls
        document.querySelectorAll('[data-require-admin]').forEach(el => el.style.display = '');
      } else {
        // Hide admin-only controls
        document.querySelectorAll('[data-require-admin]').forEach(el => el.style.display = 'none');
      }

      // Load data after successful auth
      loadIncidentsAndChart();
      checkNewIncidents();

      // Start polling for all users
      startPolling();
    } catch (err) {
      console.error('[DEBUG] Auth check failed:', err);
      // Only logout on 401 (unauthorized), not on network errors
      // User stays logged in if backend is temporarily unavailable
    }
  })();

  // Logout handler
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
}

// Start polling for all authenticated users
function startPolling() {
  // Initial collection for admin users
  if (currentUser && currentUser.role === 'admin') {
    collectFileEventsSilent();
  }

  // Polling every 10 seconds for incidents and chart updates
  setInterval(async () => {
    // Only run if user is authenticated
    if (!currentUser) return;

    // Run analysis only for admins (non-admins get 403)
    if (currentUser.role === 'admin') {
      try {
        await apiCall('/api/analyze/run?since_minutes=60', { method: 'POST' });
      } catch (_) {}

      // Collect new events periodically (for admin only)
      await collectFileEventsSilent();
    }

    // Load data for all users
    checkNewIncidents();
    loadIncidentsAndChart();
  }, POLL_INTERVAL_MS);

  // Schedule chart refresh at midnight (00:00)
  scheduleMidnightRefresh();
}

// Silent file collection (no UI output)
async function collectFileEventsSilent() {
  try {
    await apiCall('/api/collect/file?max_lines=200', { method: 'POST' });
  } catch (_) {
    // Ignore errors in silent mode
  }
}

// Schedule a refresh of the chart at midnight to start a new day
function scheduleMidnightRefresh() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);
  
  const msUntilMidnight = tomorrow.getTime() - now.getTime();
  
  console.log('[DEBUG] Next chart refresh at midnight in', Math.round(msUntilMidnight / 1000), 'seconds');
  
  setTimeout(() => {
    loadIncidentsAndChart();
    // Schedule next midnight refresh
    scheduleMidnightRefresh();
  }, msUntilMidnight);
}

// App Map - visualize applications with errors
function renderAppMap(events) {
  const container = document.getElementById('appsMapContainer');
  if (!container) return;
  
  // Исключаем системные процессы из карты приложений
  const systemProcesses = ['kernel', 'launchd', 'systemd', 'init', 'cron', 'rsyslog', 'journald', 'networkd', 'udev', 'dbus', 'polkit', 'networkd'];
  
  // Filter events with errors/crashes from applications
  const appErrors = events.filter(ev => {
    const msg = (ev.message || '').toLowerCase();
    const type = (ev.event_type || '').toLowerCase();
    const raw = ev.raw_data || {};
    const process = raw.process || raw.service || raw.application || ev.source_category || '';
    
    // Исключаем системные процессы
    if (systemProcesses.some(sys => process.toLowerCase().includes(sys))) {
      return false;
    }
    
    return type === 'service' || 
           msg.includes('crash') || 
           msg.includes('error') || 
           msg.includes('fail') ||
           msg.includes('exit');
  });
  
  // Group by application/service
  const appCounts = {};
  for (const ev of appErrors) {
    // Get app name from raw_data or message
    const raw = ev.raw_data || {};
    let appName = raw.process || raw.service || raw.application || ev.source_category || 'Unknown';
    
    // Try to extract from message if it contains "app.service:" pattern
    if (!appName || appName === 'Unknown') {
      const match = (ev.message || '').match(/([a-zA-Z0-9_-]+)\.service:/);
      if (match) {
        appName = match[1];
      }
    }
    
    if (!appCounts[appName]) {
      appCounts[appName] = { count: 0, severity: 'low', errors: [] };
    }
    appCounts[appName].count++;
    
    // Track highest severity
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (sevOrder[ev.severity] < sevOrder[appCounts[appName].severity]) {
      appCounts[appName].severity = ev.severity;
    }
    
    appCounts[appName].errors.push(ev);
  }
  
  container.innerHTML = '';
  
  const apps = Object.entries(appCounts).sort((a, b) => b[1].count - a[1].count);
  
  if (apps.length === 0) {
    container.innerHTML = '<div class="app-error-empty">Ошибки приложений не обнаружены<br><small>Показываются только ошибки пользовательских приложений (не kernel/launchd)</small></div>';
    return;
  }
  
  // App icon mapping
  const appIcons = {
    'nginx': '🌐',
    'apache': '🌐',
    'mysql': '🗄️',
    'postgres': '🗄️',
    'redis': '🗄️',
    'sshd': '🔐',
    'docker': '🐳',
    'zoom': '📹',
    'slack': '💬',
    'code': '💻',
    'unknown': '⚠️'
  };
  
  for (const [appName, data] of apps) {
    const icon = appIcons[appName.toLowerCase()] || appIcons['unknown'];
    const node = document.createElement('div');
    node.className = `app-node ${data.severity}`;
    node.innerHTML = `
      <div class="app-node-icon ${data.severity}">${icon}</div>
      <div class="app-node-name">${escapeHtml(appName)}</div>
      <div class="app-node-count">${data.count} ош.</div>
    `;
    node.addEventListener('click', () => {
      showAppErrors(data.errors, appName);
    });
    container.appendChild(node);
  }
}

// Show app errors in table
function renderAppErrorsTable(events) {
  const tbody = document.getElementById('appErrorsList');
  if (!tbody) return;
  
  tbody.innerHTML = '';
  
  // Filter and sort recent errors
  const errors = events
    .filter(ev => {
      const msg = (ev.message || '').toLowerCase();
      const type = (ev.event_type || '').toLowerCase();
      return type === 'service' || msg.includes('error') || msg.includes('fail') || msg.includes('crash');
    })
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .slice(0, 20);
  
  if (errors.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="app-error-empty">Нет недавних ошибок</td></tr>';
    return;
  }
  
  for (const ev of errors) {
    const dt = ev.ts ? new Date(ev.ts) : null;
    const timeStr = dt ? dt.toLocaleTimeString('ru-RU', { timeStyle: 'short' }) : '—';
    
    const raw = ev.raw_data || {};
    let appName = raw.process || raw.service || raw.application || ev.source_category || 'Unknown';
    
    // Truncate message
    let errorMsg = ev.message || '';
    if (errorMsg.length > 80) {
      errorMsg = errorMsg.substring(0, 77) + '...';
    }
    
    const sevLabel = SEVERITY_LABELS[ev.severity] || ev.severity;
    const sevClass = `detail-sev-${ev.severity}`;
    
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(timeStr)}</td>
      <td>${escapeHtml(appName)}</td>
      <td>${escapeHtml(errorMsg)}</td>
      <td><span class="detail-sev-badge ${sevClass}">${escapeHtml(sevLabel)}</span></td>
    `;
    tbody.appendChild(tr);
  }
}

// Show errors for specific app
function showAppErrors(errors, appName) {
  // Open detail view filtered by app
  const mainView = document.getElementById('mainView');
  const detailView = document.getElementById('detailView');
  const titleEl = document.getElementById('drilldownTitle');
  const breadcrumbs = document.getElementById('detailBreadcrumbs');
  
  drilldownSeverity = null; // Show all severities
  drilldownQuery = appName.toLowerCase();
  
  if (titleEl) titleEl.textContent = `Ошибки: ${appName}`;
  if (breadcrumbs) breadcrumbs.textContent = `Карта / ${appName}`;
  
  const searchEl = document.getElementById('detailSearchInput');
  if (searchEl) searchEl.value = appName;
  
  // Filter incidents by app name
  const filtered = allIncidents.filter(inc => {
    const details = inc.details || {};
    const service = details.service || details.process || details.application || '';
    return service.toLowerCase().includes(drilldownQuery);
  });
  
  renderDrilldownList(filtered);

  if (mainView) mainView.classList.add('hidden');
  if (detailView) {
    detailView.classList.remove('hidden');
    detailView.setAttribute('aria-hidden', 'false');
  }
}

// Save state before app closes
window.addEventListener('beforeunload', () => {
  // Credentials are already in localStorage, but ensure they're saved
  if (currentUser) {
    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    if (creds) {
      localStorage.setItem(AUTH_CREDS_KEY, creds);
    }
  }
});