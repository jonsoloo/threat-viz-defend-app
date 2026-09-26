const apiBase = (window.THREAT_VIZ_API_BASE || '').replace(/\/$/, '');
const screens = [...document.querySelectorAll('.screen')];
const logoutButton = document.getElementById('header-action');
let session = { authenticated: false, approved: false };
let activeRun = null;
let updateTimer = null;
let updateBusy = false;

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${apiBase}${path}`, {
      credentials: 'include',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    });
  } catch {
    throw new Error('Cannot reach the server yet. Please try again later.');
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || (response.status === 429 ? 'Too many attempts. Try again later.' : 'Something went wrong. Please try again.'));
    error.status = response.status;
    throw error;
  }
  return data;
}

function show(view) {
  if (view === 'workspace' && !session.approved) view = session.authenticated ? 'access' : 'login';
  if (view === 'access' && !session.authenticated) view = 'login';
  for (const screen of screens) screen.hidden = screen.id !== view;
  if (view !== 'workspace') stopUpdates();
  logoutButton.hidden = !session.authenticated;
  if (location.hash !== `#${view}`) history.replaceState(null, '', `#${view}`);
  window.scrollTo(0, 0);
  document.title = `${view === 'home' ? 'Threat Viz Defend' : view[0].toUpperCase() + view.slice(1) + ' · Threat Viz Defend'}`;
}

function setMessage(form, message, success = false) {
  const element = form.querySelector('.form-message');
  element.textContent = message;
  element.classList.toggle('success', success);
}

async function submitForm(form, path, values, next) {
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  setMessage(form, '');
  try {
    await request(path, { method: 'POST', body: JSON.stringify(values) });
    const current = await request('/api/session');
    session = { authenticated: current.authenticated === true, approved: current.approved === true };
    form.reset();
    show(next === 'auto' ? (session.approved ? 'workspace' : session.authenticated ? 'access' : 'login') : next);
  } catch (error) {
    setMessage(form, error.message);
  } finally {
    button.disabled = false;
  }
}

document.querySelectorAll('[data-view]').forEach(button => {
  button.addEventListener('click', () => show(button.dataset.view));
});

document.getElementById('signup-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  submitForm(form, '/api/auth/signup', {
    username: form.elements.username.value.trim(),
    password: form.elements.password.value,
  }, 'auto');
});

document.getElementById('login-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  submitForm(form, '/api/auth/login', {
    username: form.elements.username.value.trim(),
    password: form.elements.password.value,
  }, 'auto');
});

document.getElementById('access-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  submitForm(form, '/api/access/redeem', { code: form.elements.code.value.trim() }, 'auto');
});

logoutButton.addEventListener('click', async () => {
  logoutButton.disabled = true;
  try {
    await request('/api/auth/logout', { method: 'POST', body: '{}' });
    session = { authenticated: false, approved: false };
    stopUpdates();
    document.getElementById('results').replaceChildren();
    document.getElementById('threat-diagram').replaceChildren(element('p', 'activity-empty', 'The threat diagram will appear after a scan.'));
    document.getElementById('diagram-status').textContent = 'Waiting for code';
    show('home');
  } catch {
    alert('Could not log out. Please try again.');
  } finally {
    logoutButton.disabled = false;
  }
});

function element(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = content;
  return node;
}

function stopUpdates() {
  if (updateTimer) clearInterval(updateTimer);
  updateTimer = null;
  activeRun = null;
}

function renderFindings(data) {
  if (!Array.isArray(data.findings)) return;
  const results = document.getElementById('results');
  results.className = '';
  results.replaceChildren(element('p', 'results-intro', String(data.summary || (data.findings.length ? 'Possible risks to review:' : 'No findings returned.')).slice(0, 1000)));
  for (const finding of data.findings.slice(0, 30)) {
    if (!finding || typeof finding !== 'object') continue;
    const card = element('article', 'finding', '');
    card.append(element('p', 'severity', String(finding.severity || 'Review').slice(0, 30)), element('h3', '', String(finding.title || 'Finding').slice(0, 140)), element('p', '', String(finding.description || '').slice(0, 1000)), element('p', 'defense', `Defense: ${String(finding.mitigation || 'Review with your team.').slice(0, 1000)}`));
    results.append(card);
  }
}

function renderDiagram(diagram) {
  if (!diagram || !Array.isArray(diagram.nodes) || !Array.isArray(diagram.edges)) return;
  const host = document.getElementById('threat-diagram');
  const nodes = diagram.nodes.slice(0, 20).filter(node => node && typeof node.id === 'string' && node.id.length <= 100);
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const edges = diagram.edges.slice(0, 40).filter(edge => edge && nodeMap.has(edge.from) && nodeMap.has(edge.to));
  if (!nodes.length) {
    host.replaceChildren(element('p', 'activity-empty', 'No threat path was returned for this scan.'));
    return;
  }
  const ranks = new Map(nodes.map(node => [node.id, 0]));
  const incoming = new Map(nodes.map(node => [node.id, 0]));
  const outgoing = new Map(nodes.map(node => [node.id, []]));
  for (const edge of edges) { incoming.set(edge.to, incoming.get(edge.to) + 1); outgoing.get(edge.from).push(edge.to); }
  const queue = nodes.filter(node => incoming.get(node.id) === 0).map(node => node.id);
  for (let i = 0; i < queue.length; i++) {
    for (const next of outgoing.get(queue[i])) {
      ranks.set(next, Math.min(5, Math.max(ranks.get(next), ranks.get(queue[i]) + 1)));
      incoming.set(next, incoming.get(next) - 1);
      if (incoming.get(next) === 0) queue.push(next);
    }
  }
  const columns = [];
  for (const node of nodes) {
    const rank = ranks.get(node.id);
    (columns[rank] ||= []).push(node);
  }
  const width = Math.max(340, columns.length * 220 + 30);
  const height = Math.max(190, Math.max(...Array.from({ length: columns.length }, (_, i) => columns[i]?.length || 0)) * 105 + 35);
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Threat diagram. Connections are also listed below.');
  const make = (tag, attrs = {}) => {
    const item = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, String(value));
    return item;
  };
  const defs = make('defs');
  const marker = make('marker', { id: 'threat-arrow', markerWidth: 8, markerHeight: 8, refX: 7, refY: 4, orient: 'auto' });
  marker.append(make('path', { d: 'M0 0 L8 4 L0 8 Z', fill: '#a8c68d' }));
  defs.append(marker);
  svg.append(defs);
  const positions = new Map();
  columns.forEach((column, col) => column?.forEach((node, row) => positions.set(node.id, { x: 20 + col * 220, y: 22 + row * 105 + (height - 35 - column.length * 105) / 2 })));
  for (const edge of edges) {
    const from = positions.get(edge.from), to = positions.get(edge.to);
    const x1 = from.x + 174, y1 = from.y + 34, x2 = to.x, y2 = to.y + 34;
    svg.append(make('path', { d: `M${x1} ${y1} C${x1 + 25} ${y1},${x2 - 25} ${y2},${x2} ${y2}`, fill: 'none', stroke: '#a8c68d', 'stroke-width': 2, 'marker-end': 'url(#threat-arrow)' }));
  }
  for (const node of nodes) {
    const { x, y } = positions.get(node.id);
    const risk = node.kind === 'risk';
    const group = make('g');
    group.append(make('rect', { x, y, width: 174, height: 68, rx: 3, fill: risk ? '#3a3028' : '#193238', stroke: risk ? '#e7ad69' : '#5a8376', 'stroke-width': 1.5 }));
    const kind = make('text', { x: x + 12, y: y + 22, fill: risk ? '#f3c88e' : '#d3ff6a', 'font-size': 10, 'font-family': 'sans-serif' });
    kind.textContent = String(node.kind || 'step').toUpperCase().slice(0, 18);
    const label = make('text', { x: x + 12, y: y + 47, fill: '#eef5f2', 'font-size': 12, 'font-family': 'sans-serif' });
    const name = String(node.label || node.id).slice(0, 32);
    label.textContent = name.length > 23 ? `${name.slice(0, 22)}…` : name;
    const title = make('title'); title.textContent = String(node.label || node.id).slice(0, 140);
    group.append(title, kind, label); svg.append(group);
  }
  const details = element('ul', 'diagram-details', '');
  for (const edge of edges) {
    const from = String(nodeMap.get(edge.from).label || edge.from).slice(0, 100);
    const to = String(nodeMap.get(edge.to).label || edge.to).slice(0, 100);
    details.append(element('li', '', `${from} → ${to}${edge.label ? `: ${String(edge.label).slice(0, 180)}` : ''}`));
  }
  host.replaceChildren(svg, details);
}

function renderSnapshot(data) {
  renderFindings(data);
  renderDiagram(data.diagram);
  document.getElementById('diagram-status').textContent = data.status === 'complete' ? 'Review complete' : data.status === 'failed' ? 'Review stopped' : activeRun ? 'Watching for updates' : 'Scan complete';
  if (data.status === 'complete' || data.status === 'failed') stopUpdates();
}

async function pollUpdates(runId) {
  if (updateBusy || activeRun !== runId || document.getElementById('workspace').hidden) return;
  updateBusy = true;
  try {
    const data = await request(`/api/runs/${encodeURIComponent(runId)}/state`);
    if (activeRun === runId) renderSnapshot(data);
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      stopUpdates();
      session = { authenticated: error.status !== 401, approved: false };
      show(session.authenticated ? 'access' : 'login');
    } else {
      document.getElementById('diagram-status').textContent = 'Updates unavailable';
      stopUpdates();
    }
  } finally {
    updateBusy = false;
  }
}

document.getElementById('analyze-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  setMessage(form, '');
  stopUpdates();
  document.getElementById('results').className = 'results-empty';
  document.getElementById('results').replaceChildren(element('p', '', 'Reviewing the submitted code…'));
  document.getElementById('diagram-status').textContent = 'Scanning code';
  document.getElementById('threat-diagram').replaceChildren(element('p', 'activity-empty', 'Building a threat diagram…'));
  try {
    const data = await request('/api/analyze', { method: 'POST', body: JSON.stringify({ code: form.elements.code.value }) });
    if (!data.diagram || !Array.isArray(data.diagram.nodes) || !Array.isArray(data.diagram.edges)) throw new Error('The server did not return a threat diagram.');
    if (data.runId != null && String(data.runId).length < 200) activeRun = String(data.runId);
    renderSnapshot(data);
    if (activeRun) {
      const runId = activeRun;
      updateTimer = setInterval(() => pollUpdates(runId), 3000);
    }
  } catch (error) {
    document.getElementById('diagram-status').textContent = 'Scan unavailable';
    if (error.status === 401 || error.status === 403) {
      session = { authenticated: error.status !== 401, approved: false };
      show(session.authenticated ? 'access' : 'login');
    } else setMessage(form, error.message);
  } finally {
    button.disabled = false;
  }
});

async function initialize() {
  try {
    const current = await request('/api/session');
    session = { authenticated: current.authenticated === true, approved: current.approved === true };
  } catch { /* Public screens stay available when the API has not been connected. */ }
  const requested = location.hash.slice(1);
  show(['home', 'signup', 'login', 'access', 'workspace'].includes(requested) ? requested : 'home');
}

window.addEventListener('hashchange', () => {
  const requested = location.hash.slice(1);
  show(['home', 'signup', 'login', 'access', 'workspace'].includes(requested) ? requested : 'home');
});
initialize();
