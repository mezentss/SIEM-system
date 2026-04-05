const API_BASE = 'http://127.0.0.1:8000';

const SEEN_INCIDENTS_KEY = 'siem_seen_incident_ids';
const POLL_INTERVAL_MS = 10000;

const AUTH_CREDS_KEY = 'siem_auth_creds';

let allIncidents = [];
let seenIncidentIds = new Set();
let drilldownSeverity = null;
let drilldownQuery = '';

let currentUser = null;

let fastPollingUntil = 0;
const FAST_POLL_INTERVAL_MS = 10000;
const SLOW_POLL_INTERVAL_MS = 5 * 60 * 1000;
const FAST_POLL_DURATION_MS = 60 * 1000;

function getAuthHeaders() {
  const creds = localStorage.getItem(AUTH_CREDS_KEY);
  if (!creds) return {};
  const [username, password] = atob(creds).split(':');
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
  
  // Проверяем, это обычный fetch Response или electronAPI response object
  const isResponseObject = resp && typeof resp === 'object' && (resp.status || resp.ok !== undefined);
  
  if (!isResponseObject) {
    // electronAPI.fetch уже вернул распарсенный JSON (старый формат)
    return resp;
  }
  
  const status = resp.status || 200;
  const statusText = resp.statusText || '';
  
  if (!resp.ok) {
    if (status === 401) {
      logout();
    }
    // Пытаемся получить текст ошибки
    try {
      const errorText = await resp.text();
      let errorDetail = statusText || `HTTP ${status}`;
      try {
        const errorJson = JSON.parse(errorText);
        if (errorJson.detail) {
          errorDetail = typeof errorJson.detail === 'string' 
            ? errorJson.detail 
            : JSON.stringify(errorJson.detail);
        }
      } catch (_) {}
      throw new Error(errorDetail);
    } catch (err) {
      throw new Error(`HTTP ${status}: ${statusText || err.message}`);
    }
  }
  
  const text = await resp.text();
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
  const activeIncidentsEl = document.getElementById('statActiveIncidents');
  const alertsTodayEl = document.getElementById('statAlertsToday');
  const healthEl = document.getElementById('statSystemHealth');

  // Считаем только активные инциденты (не решённые)
  const activeIncidents = (Array.isArray(incidents) ? incidents : []).filter(
    (inc) => (inc.status || 'active') === 'active'
  );
  const totalIncidents = activeIncidents.length;

  const now = new Date();
  const incidentsToday = activeIncidents.filter((inc) => {
    const ts = inc?.detected_at;
    return ts ? isSameDay(ts, now) : false;
  }).length;

  // Проверка наличия критических или высоких активных инцидентов
  const hasCriticalOrHigh = activeIncidents.some(
    (inc) => {
      const sev = (inc?.severity || '').toLowerCase();
      return sev === 'critical' || sev === 'high';
    }
  );

  if (activeIncidentsEl) activeIncidentsEl.textContent = formatNumberRu(totalIncidents);
  if (alertsTodayEl) alertsTodayEl.textContent = formatNumberRu(incidentsToday);

  if (healthEl) {
    if (totalIncidents === 0) {
      // Нет активных инцидентов — всё в порядке
      healthEl.textContent = 'Всё в порядке';
      healthEl.style.color = '#08df70'; // зелёный
    } else if (hasCriticalOrHigh) {
      // Есть критические или высокие активные инциденты — требует внимания
      healthEl.textContent = 'Требует внимания';
      healthEl.style.color = '#fa7415'; // оранжевый
    } else {
      // Есть только medium/low активные инциденты — критическое
      healthEl.textContent = 'Критическое';
      healthEl.style.color = '#ed4246'; // красный
    }
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
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) {
    const s = (inc.severity || 'unknown').toLowerCase();
    if (s in counts) {
      counts[s] = (counts[s] || 0) + 1;
    } else {
      counts.unknown = (counts.unknown || 0) + 1;
    }
  }
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
  const now = new Date();
  const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const buckets = {};
  for (const ev of events) {
    if (!ev.ts) continue;
    const ts = new Date(ev.ts);
    if (ts < cutoff) continue;
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
  const labels = Object.keys(buckets).sort((a, b) => {
    const da = new Date(a);
    const db = new Date(b);
    return db - da;
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
    const status = inc.status || 'active';  // Дефолтное значение

    const sevLabel = SEVERITY_LABELS[sev] || sev;
    const sevClass =
      sev === 'critical' ? 'detail-sev-critical' :
      sev === 'high' ? 'detail-sev-high' :
      sev === 'medium' ? 'detail-sev-medium' :
      sev === 'low' ? 'detail-sev-low' :
      '';

    const advice = getAdviceForSeverity(sev);
    const adviceText = advice?.short || 'Нет рекомендаций';

    // Статус инцидента
    const statusLabels = {
      active: 'Активен',
      resolved: 'Решён',
      false_positive: 'Ложное сраб.'
    };
    const statusLabel = statusLabels[status] || status;

    // Кнопка закрытия или открытия
    let actionBtn;
    if (status === 'active') {
      actionBtn = `<button class="btn-resolve" data-incident-id="${inc.id}" data-action="close">Закрыть</button>`;
    } else {
      actionBtn = `<button class="btn-reopen" data-incident-id="${inc.id}" data-action="reopen">Открыть</button>`;
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(dateStr)}</td>
      <td>${escapeHtml(timeStr)}</td>
      <td class="admin-only">${escapeHtml(type)}</td>
      <td><span class="detail-sev-badge ${sevClass}">${escapeHtml(sevLabel)}</span></td>
      <td>${escapeHtml(program)}</td>
      <td><span class="status-badge ${status}">${statusLabel}</span></td>
      <td class="admin-only">${escapeHtml(inc.friendly_description || inc.description || '')}</td>
      <td class="operator-only"><span class="advice-badge ${sev}" title="${escapeHtml(advice?.full || adviceText)}">${advice?.icon || 'ℹ️'} ${escapeHtml(adviceText)}</span></td>
      <td>${actionBtn}</td>
    `;
    tbody.appendChild(tr);
  }

  // Добавляем обработчики кнопок "Закрыть" и "Открыть"
  console.log('[DEBUG] Setting up button handlers, incidents:', incidents.length);
  
  const resolveBtns = tbody.querySelectorAll('.btn-resolve');
  console.log('[DEBUG] Found resolve buttons:', resolveBtns.length);
  resolveBtns.forEach(btn => {
    console.log('[DEBUG] Adding resolve handler for incident:', btn.dataset.incidentId);
    btn.addEventListener('click', () => {
      const incidentId = btn.dataset.incidentId;
      console.log('[DEBUG] Resolve clicked for:', incidentId);
      openResolveModal(incidentId);
    });
  });

  const reopenBtns = tbody.querySelectorAll('.btn-reopen');
  console.log('[DEBUG] Found reopen buttons:', reopenBtns.length);
  reopenBtns.forEach(btn => {
    console.log('[DEBUG] Adding reopen handler for incident:', btn.dataset.incidentId);
    btn.addEventListener('click', () => {
      const incidentId = btn.dataset.incidentId;
      console.log('[DEBUG] Reopen clicked for:', incidentId);
      reopenIncident(incidentId);
    });
  });
}

function getAdviceForSeverity(severity) {
  const advices = {
    'critical': {
      icon: '🆘',
      short: '1. Сохраните файлы → 2. Не выключайте ПК → 3. Звоните: +7 (999) 123-45-67',
      full: 'ЧТО ДЕЛАТЬ НЕМЕДЛЕННО:\n1. Сохраните все открытые файлы\n2. Не выключайте компьютер принудительно\n3. Запишите код ошибки (если есть)\n4. ЗВОНИТЕ: +7 (999) 123-45-67'
    },
    'high': {
      icon: '🚨',
      short: '1. Сохраните файлы → 2. Перезагрузите ПК → 3. Если не помогло — звоните',
      full: 'ПЛАН ДЕЙСТВИЙ:\n1. Сохраните все файлы\n2. Закройте приложение с ошибками\n3. Перезагрузите компьютер\n4. Если проблема повторилась — звоните: +7 (999) 123-45-67'
    },
    'medium': {
      icon: '⚠️',
      short: '1. Перезапустите приложение → 2. Проверьте интернет → 3. Перезагрузите ПК',
      full: 'ПОПРОБУЙТЕ:\n1. Перезапустите приложение\n2. Проверьте подключение к интернету\n3. Перезагрузите компьютер\n\nЕсли повторится — обратитесь в поддержку'
    },
    'low': {
      icon: 'ℹ️',
      short: 'Продолжайте работу. Если повторится — перезапустите приложение',
      full: 'Всё в порядке.\n\nПродолжайте работу в обычном режиме.\n\nЕсли ошибка повторится несколько раз — перезапустите приложение.'
    },
  };
  return advices[severity] || advices['low'];
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

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
    `;
    tbody.appendChild(tr);
  });
}

function switchView(viewName) {
  const views = ['dashboard', 'map', 'settings', 'employee'];
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

    renderRecentEvents(eventsForStats);
    updateDashboardStats({ events: eventsForStats, incidents: allIncidents });

    const eventsData = buildEventsByHour(eventsForStats || []);
    renderEventsByHourChart(eventsData);

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

  // startPolling() вызывается позже, после инициализации currentUser
});

if (window.location.pathname.endsWith('login.html')) {
  // Auth tabs switching
  const authTabs = document.querySelectorAll('.auth-tab');
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  
  authTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.getAttribute('data-tab');
      
      authTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      if (tabName === 'login') {
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
      } else {
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
      }
    });
  });

  // Login form handler
  document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');
    const btn = e.target.querySelector('button[type="submit"]');

    btn.disabled = true;
    errorEl.classList.add('hidden');

    try {
      const creds = btoa(username + ':' + password);
      localStorage.setItem(AUTH_CREDS_KEY, creds);

      await new Promise(resolve => setTimeout(resolve, 100));

      const user = await apiCall('/api/auth/me');
      currentUser = user;
      window.location.href = 'index.html';
    } catch (err) {
      errorEl.textContent = 'Неверное имя пользователя или пароль';
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
    }
  });

  // Register form handler
  document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const fullName = document.getElementById('regFullName').value;
    const email = document.getElementById('regEmail').value;
    const phone = document.getElementById('regPhone').value;
    
    const errorEl = document.getElementById('registerError');
    const successEl = document.getElementById('registerSuccess');
    const btn = e.target.querySelector('button[type="submit"]');

    btn.disabled = true;
    errorEl.classList.add('hidden');
    successEl.classList.add('hidden');

    try {
      const fetchFn = window.electronAPI?.fetch || window.fetch;
      const resp = await fetchFn(API_BASE + '/api/profile/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username,
          password: password,
          full_name: fullName || null,
          email: email || null,
          phone: phone || null,
        }),
      });

      // electronAPI.fetch returns parsed JSON, regular fetch returns Response
      let result;
      if (resp && typeof resp === 'object' && !resp.status) {
        result = resp;
      } else {
        if (!resp.ok) {
          result = await resp.json().catch(() => ({ detail: 'Registration failed' }));
          throw new Error(result.detail || 'Registration failed');
        }
        result = await resp.json();
      }

      successEl.textContent = '✓ Регистрация успешна! Теперь войдите.';
      successEl.classList.remove('hidden');
      
      // Clear form
      document.getElementById('regUsername').value = '';
      document.getElementById('regPassword').value = '';
      document.getElementById('regFullName').value = '';
      document.getElementById('regEmail').value = '';
      document.getElementById('regPhone').value = '';
      
      // Switch to login tab after 2 seconds
      setTimeout(() => {
        document.querySelector('[data-tab="login"]')?.click();
      }, 2000);
      
    } catch (err) {
      console.error('[REGISTER] Error:', err);
      errorEl.textContent = err.message || 'Ошибка регистрации';
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
    }
  });

  // Auto-login check
  (async () => {
    const storedCreds = localStorage.getItem(AUTH_CREDS_KEY);
    if (storedCreds) {
      try {
        const user = await apiCall('/api/auth/me');
        window.location.href = 'index.html';
      } catch (_) {
      }
    }
  })();
} else {
  (async () => {
    const storedCreds = localStorage.getItem(AUTH_CREDS_KEY);
    if (!storedCreds) {
      logout();
      return;
    }

    try {
      const user = await apiCall('/api/auth/me');
      currentUser = user;
      const usernameEl = document.getElementById('topbarUsername');
      const roleEl = document.getElementById('topbarRole');
      if (usernameEl) usernameEl.textContent = user.username || '—';
      if (roleEl) roleEl.textContent = user.role === 'admin' ? 'Администратор' : 'Сотрудник';

      document.body.classList.add(user.role === 'admin' ? 'admin' : 'operator');

      if (user.role === 'admin') {
        document.querySelectorAll('[data-require-admin]').forEach(el => el.style.display = '');
      } else {
        document.querySelectorAll('[data-require-admin]').forEach(el => el.style.display = 'none');
      }

      loadIncidentsAndChart();
      checkNewIncidents();

      startPolling();
    } catch (err) {
    }
  })();

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }

  // Employee profile form handler
  const employeeForm = document.getElementById('employeeProfileForm');
  if (employeeForm) {
    employeeForm.addEventListener('submit', saveEmployeeProfile);
  }

  // Load profile when switching to employee view
  document.querySelector('[data-view="employee"]')?.addEventListener('click', () => {
    loadEmployeeProfile();
  });

  // Users management handlers (admin only)
  const addUserBtn = document.getElementById('addUserBtn');
  if (addUserBtn) {
    addUserBtn.addEventListener('click', () => openUserModal());
  }

  const modalClose = document.getElementById('modalClose');
  if (modalClose) {
    modalClose.addEventListener('click', closeUserModal);
  }

  const modalCancel = document.getElementById('modalCancel');
  if (modalCancel) {
    modalCancel.addEventListener('click', closeUserModal);
  }

  const userForm = document.getElementById('userForm');
  if (userForm) {
    userForm.addEventListener('submit', saveUser);
  }

  // Load users when switching to settings view
  document.querySelector('[data-view="settings"]')?.addEventListener('click', () => {
    if (currentUser && currentUser.role === 'admin') {
      loadUsersList();
    }
  });
}

function startPolling() {
  let pollingInterval = null;

  function startInterval(intervalMs) {
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }
    pollingInterval = setInterval(runPoll, intervalMs);
  }

  function runPoll() {
    if (!currentUser) return;

    const now = Date.now();
    const isFastPolling = now < fastPollingUntil;

    if (currentUser.role === 'admin' && isFastPolling) {
      try {
        apiCall('/api/analyze/run?since_minutes=60', { method: 'POST' })
          .catch(() => {});
      } catch (_) {}
    }

    checkNewIncidents();
    loadIncidentsAndChart();

    if (!isFastPolling && currentUser.role === 'admin') {
      fastPollingUntil = Date.now() + FAST_POLL_DURATION_MS;
      startInterval(FAST_POLL_INTERVAL_MS);
    }
  }

  // Проверяем наличие currentUser перед запуском
  if (!currentUser) {
    console.warn('startPolling: currentUser is null, skipping polling');
    return;
  }

  if (currentUser.role === 'admin') {
    fastPollingUntil = Date.now() + FAST_POLL_DURATION_MS;
    startInterval(FAST_POLL_INTERVAL_MS);
  } else {
    startInterval(SLOW_POLL_INTERVAL_MS);
  }

  scheduleMidnightRefresh();
}

async function collectFileEventsSilent() {
  try {
    await apiCall('/api/collect/file?max_lines=200', { method: 'POST' });
  } catch (_) {
  }
}

function scheduleMidnightRefresh() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);

  const msUntilMidnight = tomorrow.getTime() - now.getTime();

  setTimeout(() => {
    loadIncidentsAndChart();
    scheduleMidnightRefresh();
  }, msUntilMidnight);
}

function renderAppMap(events) {
  const container = document.getElementById('appsMapContainer');
  if (!container) return;

  const systemProcesses = ['kernel', 'launchd', 'systemd', 'init', 'cron', 'rsyslog', 'journald', 'networkd', 'udev', 'dbus', 'polkit', 'networkd'];

  const appErrors = events.filter(ev => {
    const msg = (ev.message || '').toLowerCase();
    const type = (ev.event_type || '').toLowerCase();
    const raw = ev.raw_data || {};
    const process = raw.process || raw.service || raw.application || ev.source_category || '';

    if (systemProcesses.some(sys => process.toLowerCase().includes(sys))) {
      return false;
    }

    return type === 'service' ||
           msg.includes('crash') ||
           msg.includes('error') ||
           msg.includes('fail') ||
           msg.includes('exit');
  });

  const appCounts = {};
  for (const ev of appErrors) {
    const raw = ev.raw_data || {};
    let appName = raw.process || raw.service || raw.application || ev.source_category || 'Unknown';

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

function renderAppErrorsTable(events) {
  const tbody = document.getElementById('appErrorsList');
  if (!tbody) return;

  tbody.innerHTML = '';

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

function showAppErrors(errors, appName) {
  const mainView = document.getElementById('mainView');
  const detailView = document.getElementById('detailView');
  const titleEl = document.getElementById('drilldownTitle');
  const breadcrumbs = document.getElementById('detailBreadcrumbs');

  drilldownSeverity = null;
  drilldownQuery = appName.toLowerCase();

  if (titleEl) titleEl.textContent = `Ошибки: ${appName}`;
  if (breadcrumbs) breadcrumbs.textContent = `Карта / ${appName}`;

  const searchEl = document.getElementById('detailSearchInput');
  if (searchEl) searchEl.value = appName;

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

// Employee profile management
async function loadEmployeeProfile() {
  try {
    const profile = await apiCall('/api/profile/me');
    
    // Display profile info
    const profileUsernameEl = document.getElementById('profileUsername');
    const profileRoleEl = document.getElementById('profileRole');
    
    if (profileUsernameEl) profileUsernameEl.textContent = profile.username || '—';
    if (profileRoleEl) {
      const roleText = profile.role === 'admin' ? 'Администратор' : 'Оператор';
      profileRoleEl.textContent = roleText;
    }
    
    // Fill form fields
    const fullNameEl = document.getElementById('fullName');
    const emailEl = document.getElementById('email');
    const phoneEl = document.getElementById('phone');
    
    if (fullNameEl) fullNameEl.value = profile.full_name || '';
    if (emailEl) emailEl.value = profile.email || '';
    if (phoneEl) phoneEl.value = profile.phone || '';
  } catch (err) {
    console.error('[PROFILE] Failed to load profile:', err);
  }
}

async function saveEmployeeProfile(event) {
  event.preventDefault();

  const saveStatusEl = document.getElementById('saveStatus');

  try {
    const profile = {
      full_name: document.getElementById('fullName').value,
      email: document.getElementById('email').value,
      phone: document.getElementById('phone').value,
    };

    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    const headers = {
      'Content-Type': 'application/json',
    };

    if (creds) {
      const [username, password] = atob(creds).split(':');
      headers['Authorization'] = 'Basic ' + btoa(username + ':' + password);
    }

    const fetchFn = window.electronAPI?.fetch || window.fetch;
    const resp = await fetchFn(API_BASE + '/api/profile/me', {
      method: 'PUT',
      headers: headers,
      body: JSON.stringify(profile),
    });

    // electronAPI.fetch возвращает распарсенный JSON, обычный fetch — Response
    let updatedProfile;
    if (resp && typeof resp === 'object' && !resp.status) {
      updatedProfile = resp;
    } else {
      if (!resp.ok) {
        throw new Error('Failed to save profile');
      }
      updatedProfile = await resp.json();
    }

    // Обновляем currentUser и UI
    if (currentUser && updatedProfile) {
      currentUser.full_name = updatedProfile.full_name || currentUser.full_name;
      currentUser.email = updatedProfile.email || currentUser.email;
      currentUser.phone = updatedProfile.phone || currentUser.phone;
      
      // Обновляем отображение имени в шапке
      const usernameEl = document.getElementById('topbarUsername');
      if (usernameEl) {
        usernameEl.textContent = updatedProfile.full_name || currentUser.username;
      }
    }

    if (saveStatusEl) {
      saveStatusEl.textContent = '✓ Профиль сохранён';
      saveStatusEl.classList.remove('error');
      setTimeout(() => { saveStatusEl.textContent = ''; }, 3000);
    }
  } catch (err) {
    console.error('[PROFILE] Failed to save profile:', err);
    if (saveStatusEl) {
      saveStatusEl.textContent = '✗ Ошибка сохранения';
      saveStatusEl.classList.add('error');
      setTimeout(() => { saveStatusEl.textContent = ''; }, 3000);
    }
  }
}

window.addEventListener('beforeunload', () => {
  if (currentUser) {
    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    if (creds) {
      localStorage.setItem(AUTH_CREDS_KEY, creds);
    }
  }
});

// Users management
async function loadUsersList() {
  const tbody = document.getElementById('usersList');
  if (!tbody) return;
  
  try {
    const users = await apiCall('/api/users');
    tbody.innerHTML = '';
    
    for (const user of users) {
      const tr = document.createElement('tr');
      const roleText = user.role === 'admin' ? 'Администратор' : 'Оператор';
      const canDelete = user.username !== currentUser.username;
      
      tr.innerHTML = `
        <td>${escapeHtml(user.username)}</td>
        <td>${roleText}</td>
        <td>${escapeHtml(user.full_name || '—')}</td>
        <td>${escapeHtml(user.email || '—')}</td>
        <td>${escapeHtml(user.phone || '—')}</td>
        <td class="user-actions">
          <button class="btn-edit" data-user-id="${user.id}">Ред.</button>
          ${canDelete ? `<button class="btn-delete" data-user-id="${user.id}">Удал.</button>` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    }
    
    // Add event listeners
    tbody.querySelectorAll('.btn-edit').forEach(btn => {
      btn.addEventListener('click', () => openUserModal(btn.dataset.userId));
    });
    
    tbody.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', () => deleteUser(btn.dataset.userId));
    });
  } catch (err) {
    console.error('[USERS] Failed to load users:', err);
  }
}

function openUserModal(userId = null) {
  const modal = document.getElementById('userModal');
  const form = document.getElementById('userForm');
  const title = document.getElementById('modalTitle');
  const errorEl = document.getElementById('userFormError');
  
  form.reset();
  errorEl.classList.add('hidden');
  document.getElementById('editUserId').value = '';
  
  if (userId) {
    title.textContent = 'Редактировать пользователя';
    document.getElementById('editUserId').value = userId;
    // Load user data (simplified - would need to fetch user details)
  } else {
    title.textContent = 'Добавить пользователя';
  }
  
  modal.classList.remove('hidden');
}

function closeUserModal() {
  const modal = document.getElementById('userModal');
  modal.classList.add('hidden');
}

async function saveUser(event) {
  event.preventDefault();

  const userId = document.getElementById('editUserId').value;
  const errorEl = document.getElementById('userFormError');
  errorEl.classList.add('hidden');

  try {
    const userData = {
      username: document.getElementById('modalUsername').value,
      password: document.getElementById('modalPassword').value || undefined,
      role: document.getElementById('modalRole').value,
      full_name: document.getElementById('modalFullName').value || null,
      email: document.getElementById('modalEmail').value || null,
      phone: document.getElementById('modalPhone').value || null,
    };

    if (!userId && !userData.password) {
      throw new Error('Пароль обязателен для нового пользователя');
    }

    const url = userId ? `/api/users/${userId}` : '/api/users';
    const method = userId ? 'PUT' : 'POST';

    // Используем fetch напрямую с правильными заголовками
    const fetchFn = window.electronAPI?.fetch || window.fetch;
    const headers = {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    };

    const resp = await fetchFn(API_BASE + url, {
      method: method,
      headers: headers,
      body: JSON.stringify(userData),
    });

    // electronAPI.fetch возвращает распарсенный JSON, обычный fetch — Response
    let result;
    if (resp && typeof resp === 'object' && !resp.status) {
      result = resp;
    } else {
      if (!resp.ok) {
        const error = await resp.json().catch(() => ({ detail: 'Operation failed' }));
        throw new Error(error.detail || 'Operation failed');
      }
      result = await resp.json();
    }

    closeUserModal();
    loadUsersList();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  }
}

async function deleteUser(userId) {
  if (!confirm('Вы уверены, что хотите удалить этого пользователя?')) {
    return;
  }
  
  try {
    const fetchFn = window.electronAPI?.fetch || window.fetch;
    const headers = { 'Content-Type': 'application/json' };
    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    if (creds) {
      const [username, password] = atob(creds).split(':');
      headers['Authorization'] = 'Basic ' + btoa(username + ':' + password);
    }
    
    const resp = await fetchFn(API_BASE + `/api/users/${userId}`, {
      method: 'DELETE',
      headers: headers,
    });
    
    // electronAPI.fetch returns parsed JSON, regular fetch returns Response
    let result;
    if (resp && typeof resp === 'object' && !resp.status) {
      result = resp;
    } else {
      if (!resp.ok) {
        result = await resp.json().catch(() => ({ detail: 'Delete failed' }));
        throw new Error(result.detail || 'Delete failed');
      }
      result = await resp.json();
    }

    loadUsersList();
  } catch (err) {
    console.error('[USERS] Failed to delete user:', err);
    alert('Ошибка удаления: ' + err.message);
  }
}

// Incident resolution modal
function openResolveModal(incidentId) {
  const modal = document.getElementById('resolveModal');
  const form = document.getElementById('resolveForm');
  
  form.reset();
  document.getElementById('resolveIncidentId').value = incidentId;
  modal.classList.remove('hidden');
}

function closeResolveModal() {
  const modal = document.getElementById('resolveModal');
  modal.classList.add('hidden');
}

async function submitResolveIncident(event) {
  event.preventDefault();
  
  const incidentId = document.getElementById('resolveIncidentId').value;
  const notes = document.getElementById('resolveNotes').value;
  
  try {
    const fetchFn = window.electronAPI?.fetch || window.fetch;
    const headers = { 'Content-Type': 'application/json' };
    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    if (creds) {
      const [username, password] = atob(creds).split(':');
      headers['Authorization'] = 'Basic ' + btoa(username + ':' + password);
    }
    
    const resp = await fetchFn(API_BASE + `/api/incidents/${incidentId}/resolve`, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ notes: notes || null }),
    });

    // Проверка: electronAPI.fetch возвращает объект с данными
    // Обычный fetch возвращает Response объект (есть status)
    let result;
    if (resp.id !== undefined || resp.incident_type !== undefined) {
      // Это уже распарсенный JSON от electronAPI
      result = resp;
    } else if (resp.status === 200 || resp.status === 201) {
      // Это Response объект от обычного fetch
      result = await resp.json();
    } else {
      // Ошибка
      const errorData = await resp.json().catch(() => ({ detail: 'Resolve failed' }));
      throw new Error(errorData.detail || 'Resolve failed');
    }
    
    closeResolveModal();

    // Обновляем статус в allIncidents
    const incident = allIncidents.find(inc => inc.id === parseInt(incidentId));
    if (incident) {
      incident.status = 'resolved';
    }

    // Обновляем таблицу инцидентов
    const currentSeverity = drilldownSeverity;
    if (currentSeverity) {
      const filtered = allIncidents.filter(inc =>
        (inc.severity || 'unknown').toLowerCase() === currentSeverity
      );
      renderDrilldownList(filtered);
    }

    // Показываем уведомление
    const toast = document.createElement('div');
    toast.className = 'toast toast-visible';
    toast.textContent = '✓ Инцидент закрыт';
    document.getElementById('toastContainer').appendChild(toast);
    setTimeout(() => toast.remove(), 3000);

  } catch (err) {
    console.error('[RESOLVE] Failed to resolve incident:', err);
    alert('Ошибка закрытия инцидента: ' + err.message);
  }
}

// Add event listeners for resolve modal
const resolveModalClose = document.getElementById('resolveModalClose');
if (resolveModalClose) {
  resolveModalClose.addEventListener('click', closeResolveModal);
}

const resolveModalCancel = document.getElementById('resolveModalCancel');
if (resolveModalCancel) {
  resolveModalCancel.addEventListener('click', closeResolveModal);
}

const resolveForm = document.getElementById('resolveForm');
if (resolveForm) {
  resolveForm.addEventListener('submit', submitResolveIncident);
}

// Reopen incident function
async function reopenIncident(incidentId) {
  if (!confirm('Открыть этот инцидент снова?')) {
    return;
  }
  
  try {
    const fetchFn = window.electronAPI?.fetch || window.fetch;
    const headers = { 'Content-Type': 'application/json' };
    const creds = localStorage.getItem(AUTH_CREDS_KEY);
    if (creds) {
      const [username, password] = atob(creds).split(':');
      headers['Authorization'] = 'Basic ' + btoa(username + ':' + password);
    }
    
    const resp = await fetchFn(API_BASE + `/api/incidents/${incidentId}/reopen`, {
      method: 'POST',
      headers: headers,
    });
    
    // Проверка: electronAPI.fetch возвращает объект с данными
    // Обычный fetch возвращает Response объект (есть status)
    if (resp.id !== undefined || resp.incident_type !== undefined) {
      // Это уже распарсенный JSON от electronAPI
      result = resp;
    } else if (resp.status === 200 || resp.status === 201) {
      // Это Response объект от обычного fetch
      result = await resp.json();
    } else {
      // Ошибка
      const errorData = await resp.json().catch(() => ({ detail: 'Reopen failed' }));
      throw new Error(errorData.detail || 'Reopen failed');
    }
    
    // Обновляем статус в allIncidents
    const incident = allIncidents.find(inc => inc.id === parseInt(incidentId));
    if (incident) {
      incident.status = 'active';
    }
    
    // Обновляем таблицу инцидентов
    const currentSeverity = drilldownSeverity;
    if (currentSeverity) {
      const filtered = allIncidents.filter(inc => 
        (inc.severity || 'unknown').toLowerCase() === currentSeverity
      );
      renderDrilldownList(filtered);
    }
    
    // Показываем уведомление
    const toast = document.createElement('div');
    toast.className = 'toast toast-visible';
    toast.textContent = '✓ Инцидент открыт';
    document.getElementById('toastContainer').appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
    
  } catch (err) {
    console.error('[REOPEN] Failed to reopen incident:', err);
    alert('Ошибка открытия инцидента: ' + err.message);
  }
}
