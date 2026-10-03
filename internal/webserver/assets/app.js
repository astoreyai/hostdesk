'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const list = (value) => Array.isArray(value) ? value : [];
  const text = (value) => value === undefined || value === null ? '' : String(value);
  const views = ['overview', 'services', 'ports', 'projects', 'audit'];
  const resource = () => ({ value: null, loading: false, error: '', inFlight: null, generation: 0 });
  const state = {
    session: null, epoch: 0, view: 'overview',
    snapshot: resource(), network: resource(), audit: resource(),
    refreshing: null, poll: null, preview: null, previewBusy: false,
    previewOpener: null, draft: null, draftRevision: '', draftDirty: false,
    draftSerial: 0, draftPendingToken: '', pendingBusy: false, lastPendingToken: '',
  };

  function node(tag, className, content) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (content !== undefined) element.textContent = text(content);
    return element;
  }

  function button(label, onClick, className = 'button small') {
    const element = node('button', className, label);
    element.type = 'button';
    element.addEventListener('click', onClick);
    return element;
  }

  function reveal(element, visible) { element.hidden = !visible; }
  function say(message) { $('announcer').textContent = message; }
  function message(content, kind = 'info') {
    const element = $('global-message');
    element.className = `notice ${kind}`;
    element.textContent = content;
    reveal(element, Boolean(content));
  }
  function errorText(id, content) {
    const element = $(id);
    element.textContent = content;
    reveal(element, Boolean(content));
  }
  function date(value) {
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) && parsed.getFullYear() > 1 ? parsed.toLocaleString() : 'Time unavailable';
  }
  function timeNode(value) {
    const element = node('time', '', date(value));
    const parsed = new Date(value);
    if (Number.isFinite(parsed.getTime()) && parsed.getFullYear() > 1) element.dateTime = parsed.toISOString();
    return element;
  }
  function badge(label, kind = '') { return node('span', `badge ${kind}`, label); }
  function stateBadge(value) {
    const kind = ['active', 'running'].includes(value) ? 'good' : ['failed', 'dead', 'unhealthy'].includes(value) ? 'bad' : ['activating', 'deactivating', 'restarting'].includes(value) ? 'warn' : '';
    return badge(value || 'Unknown', kind);
  }
  function facts(entries) {
    const element = node('dl', 'facts');
    entries.forEach(([label, value]) => {
      if (value === '' || value === null || value === undefined) return;
      element.append(node('dt', '', label), node('dd', '', value));
    });
    return element;
  }
  function details(title, content) {
    const element = node('details');
    element.append(node('summary', '', title), content);
    return element;
  }

  function retainContext(container) {
    const active = container.contains(document.activeElement) ? document.activeElement : null;
    const key = (element) => element.id || element.dataset.focusKey || `${element.tagName}:${element.getAttribute('aria-label') || element.getAttribute('href') || element.textContent}`;
    const activeKey = active ? key(active) : '';
    const openDetails = new Set([...container.querySelectorAll('details[open]')].map((element) => element.dataset.contextKey || element.querySelector('summary').textContent));
    const scrolls = [...container.querySelectorAll('.table-wrap')].map((element) => [element.getAttribute('aria-label'), element.scrollLeft]);
    return () => {
      container.querySelectorAll('details').forEach((element) => {
        if (openDetails.has(element.dataset.contextKey || element.querySelector('summary').textContent)) element.open = true;
      });
      container.querySelectorAll('.table-wrap').forEach((element) => {
        const previous = scrolls.find(([label]) => label === element.getAttribute('aria-label'));
        if (previous) element.scrollLeft = previous[1];
      });
      if (active && !active.isConnected) {
        const replacement = [...container.querySelectorAll('a, button, input, select, summary, [tabindex]')].find((element) => key(element) === activeKey && !element.disabled);
        const target = replacement || $(`${state.view}-heading`);
        if (target.matches('h1')) target.tabIndex = -1;
        target.focus({ preventScroll: true });
      }
    };
  }
  function warningBox(title, warnings, kind = 'warning') {
    const element = node('div', `notice ${kind}`);
    element.append(node('strong', '', title));
    if (warnings.length) {
      const items = node('ul');
      warnings.forEach((warning) => items.append(node('li', '', warning)));
      element.append(items);
    }
    return element;
  }
  function empty(title, explanation, action, label = 'Refresh inventory') {
    const element = node('div', 'empty-state');
    element.append(node('h3', '', title), node('p', '', explanation));
    if (action) element.append(button(label, action));
    return element;
  }
  function skeleton(label, cards = false) {
    const element = node('div', cards ? 'loading-grid' : 'loading-table');
    element.setAttribute('role', 'status');
    element.append(node('span', 'sr-only', label));
    for (let index = 0; index < 4; index += 1) {
      const row = node('div');
      row.setAttribute('aria-hidden', 'true');
      row.append(node('div', 'skeleton skeleton-title'), node('div', 'skeleton skeleton-wide'));
      element.append(row);
    }
    return element;
  }
  function table(headers, caption, className) {
    const wrap = node('div', 'table-wrap');
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', `${caption}; scroll horizontally if needed`);
    const element = node('table', className);
    element.append(node('caption', 'sr-only', caption));
    const head = node('thead');
    const row = node('tr');
    headers.forEach((header) => {
      const cell = node('th', '', header);
      cell.scope = 'col';
      row.append(cell);
    });
    head.append(row);
    const body = node('tbody');
    element.append(head, body);
    wrap.append(element);
    return { wrap, body };
  }
  function cell(row, content, className = '') {
    const element = node('td', className);
    if (content instanceof Node) element.append(content);
    else element.textContent = text(content);
    row.append(element);
    return element;
  }
  function matches(query, values) {
    return values.map(text).join(' ').toLocaleLowerCase().includes(query.trim().toLocaleLowerCase());
  }
  function populateOptions(id, values, first) {
    const select = $(id);
    const previous = select.value;
    const options = [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
    select.replaceChildren(new Option(first, ''));
    options.forEach((value) => select.add(new Option(value, value)));
    if (options.includes(previous)) select.value = previous;
  }

  class APIError extends Error {
    constructor(message, status, code) { super(message); this.status = status; this.code = code; }
  }
  async function api(path, options = {}) {
    const controller = new AbortController();
    const requestEpoch = state.epoch;
    const timeout = setTimeout(() => controller.abort(), 45000);
    const method = options.method || 'GET';
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      if (state.session?.csrf) headers['X-CSRF-Token'] = state.session.csrf;
    }
    try {
      const response = await fetch(path, {
        method, headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        ...(method === 'GET' ? {} : { body: JSON.stringify(options.body || {}) }),
      });
      let result;
      try { result = await response.json(); }
      catch { throw new APIError(`The server returned an unreadable response (${response.status}). Retry the request.`, response.status, 'invalid_response'); }
      if (!response.ok) {
        if (response.status === 401 && !options.public && requestEpoch === state.epoch) expireSession('Your session ended. Sign in again to continue.');
        throw new APIError(result.error || `Request failed (${response.status}).`, response.status, result.code);
      }
      return result;
    } catch (error) {
      if (error instanceof APIError) throw error;
      if (error.name === 'AbortError') throw new APIError('The request timed out. The result may be unknown; refresh before trying a change again.', 0, 'timeout');
      throw new APIError('Cannot reach Hostdesk. Check the connection and try again. A pending policy still rolls back on the host when its timer expires.', 0, 'connection');
    } finally { clearTimeout(timeout); }
  }

  function expireSession(reason = '') {
    state.epoch += 1;
    state.session = null;
    clearTimeout(state.poll);
    state.poll = null;
    state.snapshot = resource();
    state.network = resource();
    state.audit = resource();
    state.refreshing = null;
    state.draft = null;
    state.draftDirty = false;
    state.previewBusy = false;
    state.pendingBusy = false;
    state.lastPendingToken = '';
    closePreview();
    reveal($('app'), false);
    reveal($('skip-link'), false);
    reveal($('session-loading'), false);
    reveal($('login-screen'), true);
    $('owner-token').value = '';
    errorText('login-error', reason);
    // Remove host-derived content, not merely the visible shell, when a session ends.
    ['overview-content', 'services-content', 'listeners-content', 'routes-content', 'projects-content', 'audit-content', 'network-summary', 'interface-rows', 'preview-body', 'confirmation-text', 'snapshot-notice', 'network-notice', 'audit-notice', 'global-message'].forEach((id) => $(id).replaceChildren());
    $('host-name').textContent = 'Host inventory';
    $('actor').textContent = '';
    ['snapshot-time', 'service-count', 'listener-count', 'project-count', 'pending-error', 'policy-error', 'preview-error', 'announcer'].forEach((id) => { $(id).textContent = ''; });
    message('');
    $('refresh-button').disabled = false;
    $('refresh-button').textContent = 'Refresh';
    ['service-search', 'listener-search', 'project-search', 'audit-search', 'confirmation-input'].forEach((id) => { $(id).value = ''; });
    ['service-manager', 'service-scope', 'service-state', 'listener-exposure'].forEach((id) => { while ($(id).options.length > 1) $(id).remove(1); });
    reveal($('pending-policy'), false);
    $('owner-token').focus();
  }
  async function checkSession() {
    $('session-retry').disabled = true;
    errorText('login-error', '');
    try {
      const session = await api('/api/session', { public: true });
      if (!session.authenticated) { expireSession(); return; }
      state.epoch += 1;
      state.session = session;
      reveal($('session-loading'), false);
      reveal($('login-screen'), false);
      reveal($('app'), true);
      reveal($('skip-link'), true);
      $('actor').textContent = session.actor || 'Authenticated owner';
      reveal($('broker-notice'), !session.capabilities?.broker);
      setView(true);
      await refreshAll(false);
    } catch (error) {
      expireSession(error.status === 401 ? '' : error.message);
    } finally { $('session-retry').disabled = false; }
  }

  function setView(focus = true) {
    const requested = location.hash.slice(1);
    state.view = views.includes(requested) ? requested : 'overview';
    views.forEach((view) => reveal($(`view-${view}`), view === state.view));
    document.querySelectorAll('nav [data-view]').forEach((link) => {
      if (link.dataset.view === state.view) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    const title = $(`${state.view}-heading`);
    document.title = `${title.textContent} · Hostdesk`;
    if (focus && state.session) {
      title.tabIndex = -1;
      title.focus();
    }
  }
  function showService(id) {
    clearServiceFilters(false);
    $('service-search').value = id;
    renderServices();
    location.hash = 'services';
    if (state.view === 'services') $('service-search').focus();
  }
  function serviceName(id) { return list(state.snapshot.value?.services).find((service) => service.id === id)?.name || id; }

  function unavailableInventory(container, cards = false) {
    if (state.snapshot.value) return false;
    container.replaceChildren(state.snapshot.error
      ? empty('Inventory could not be loaded', state.snapshot.error, () => refreshAll(true), 'Retry inventory')
      : skeleton('Loading live inventory…', cards));
    return true;
  }
  function renderSnapshotNotice() {
    const container = $('snapshot-notice');
    container.replaceChildren();
    const snapshot = state.snapshot.value;
    if (state.snapshot.error && snapshot) {
      const notice = warningBox('Refresh failed. Showing the last successful inventory.', [state.snapshot.error], 'error');
      notice.append(button('Retry inventory', () => refreshAll(true)));
      container.append(notice);
    }
    if (snapshot) {
      const missing = list(snapshot.sources).filter((source) => !source.available);
      if (missing.length) {
        const warnings = missing.map((source) => `${source.name}: ${source.error || 'Unavailable; this source may be missing from inventory.'}`);
        const notice = warningBox(`Partial inventory · ${missing.length} unavailable ${missing.length === 1 ? 'source' : 'sources'}`, []);
        const lines = node('ul');
        warnings.forEach((warning) => lines.append(node('li', '', warning)));
        notice.append(details('Source details', lines));
        container.append(notice);
      }
    }
    reveal(container, container.childElementCount > 0);
  }
  function renderOverview() {
    const container = $('overview-content');
    if (unavailableInventory(container, true)) return;
    const snapshot = state.snapshot.value;
    const services = list(snapshot.services);
    const listeners = list(snapshot.listeners);
    const routes = list(snapshot.routes);
    const projects = list(snapshot.projects);
    const running = services.filter((service) => ['active', 'running'].includes(service.state)).length;
    const metrics = node('div', 'metrics');
    [
      ['Services observed', services.length, `${running} active or running`, 'services'],
      ['Listening sockets', listeners.length, `${listeners.filter((listener) => !listener.serviceId).length} without a service match`, 'ports'],
      ['Published routes', routes.length, `${routes.filter((route) => route.public).length} marked public by provider`, 'ports'],
      ['Projects discovered', projects.length, 'From configured local roots', 'projects'],
    ].forEach(([label, value, note, view]) => {
      const metric = node('a', 'metric');
      metric.href = `#${view}`;
      metric.append(node('div', 'metric-label', label), node('div', 'metric-value', value), node('div', 'metric-note', note));
      metrics.append(metric);
    });
    const grid = node('div', 'overview-grid');
    const host = node('section', 'panel');
    host.append(node('h2', '', 'This host'), facts([
      ['Name', snapshot.host?.name || 'Not reported'], ['Operating system', snapshot.host?.os || 'Not reported'],
      ['Kernel', snapshot.host?.kernel || 'Not reported'], ['Architecture', snapshot.host?.architecture || 'Not reported'],
      ['Collected', date(snapshot.generatedAt)],
    ]));
    const states = new Map();
    services.forEach((service) => { const key = service.state || 'unknown'; states.set(key, (states.get(key) || 0) + 1); });
    if (states.size) {
      const strip = node('div', 'state-strip');
      [...states].sort((a, b) => b[1] - a[1]).forEach(([name, count]) => strip.append(badge(`${count} ${name}`)));
      host.append(strip);
    }
    const sources = node('section', 'panel');
    const header = node('div', 'panel-header');
    header.append(node('h2', '', 'Source health'), node('span', 'meta', `${list(snapshot.sources).filter((source) => source.available).length} / ${list(snapshot.sources).length} available`));
    sources.append(header);
    if (!list(snapshot.sources).length) sources.append(node('p', 'muted', 'No discovery source results were returned. Refresh to request a new collection.'));
    const sourceList = node('ul', 'source-list');
    list(snapshot.sources).forEach((source) => {
      const item = node('li', 'source-item');
      const heading = node('div', 'source-heading');
      heading.append(node('span', 'source-name', source.name), badge(source.available ? 'Available' : 'Unavailable', source.available ? 'good' : 'warn'));
      item.append(heading);
      if (source.error) item.append(node('p', source.available ? 'muted breakable' : 'error-text', source.error));
      item.append(node('p', 'meta', `Checked ${date(source.checkedAt)}`));
      sourceList.append(item);
    });
    sources.append(sourceList);
    grid.append(host, sources);
    container.replaceChildren(metrics);
    if (list(snapshot.warnings).length) container.append(warningBox('Observations that need context', snapshot.warnings));
    container.append(grid);
  }

  function clearServiceFilters(render = true) {
    ['service-search', 'service-manager', 'service-scope', 'service-state'].forEach((id) => { $(id).value = ''; });
    if (render) { renderServices(); $('service-search').focus(); }
  }
  function renderServices() {
    const container = $('services-content');
    if (unavailableInventory(container)) return;
    const all = list(state.snapshot.value.services);
    const services = all.filter((service) =>
      (!$('service-manager').value || service.manager === $('service-manager').value) &&
      (!$('service-scope').value || service.scope === $('service-scope').value) &&
      (!$('service-state').value || service.state === $('service-state').value) &&
      matches($('service-search').value, [service.id, service.name, service.description, service.manager, service.scope, service.state, service.workingDirectory, service.path, ...list(service.ports)]));
    $('service-count').textContent = `${services.length} of ${all.length} observed`;
    if (!services.length) {
      container.replaceChildren(all.length
        ? empty('No services match these filters', 'Try a different search or clear the manager, scope, and state filters.', () => clearServiceFilters(), 'Clear filters')
        : empty('No services were discovered', 'Check source health on Overview. An unavailable source is not evidence that the host has no services.', () => refreshAll(true)));
      return;
    }
    const { wrap, body } = table(['Service', 'Manager / scope', 'State', 'Ports', 'Controls'], 'Discovered services', 'service-table');
    services.forEach((service) => {
      const row = node('tr');
      const nameCell = cell(row, node('span', 'service-name', service.name));
      if (service.description) nameCell.append(node('div', 'cell-subtitle', service.description));
      const metadata = facts([
        ['Identity', service.id], ['PID', service.pid || ''], ['Working directory', service.workingDirectory],
        ['Unit / image path', service.path], ['Enabled', service.enabled],
      ]);
      const disclosure = details('Details', metadata);
      disclosure.className = 'service-details';
      disclosure.dataset.contextKey = service.id;
      disclosure.querySelector('summary').dataset.focusKey = `details:${service.id}`;
      nameCell.append(disclosure);
      const manager = cell(row, node('span', 'cell-title', service.manager));
      manager.append(node('div', 'cell-subtitle', service.scope));
      const status = cell(row, stateBadge(service.state));
      if (service.substate) status.append(node('div', 'cell-subtitle', service.substate));
      cell(row, list(service.ports).length ? service.ports.join(', ') : 'None observed', 'mono');
      const controls = node('div', 'button-row');
      const actions = list(service.actions).filter((operation) => ['start', 'stop', 'restart'].includes(operation));
      actions.forEach((operation) => {
        const label = operation[0].toUpperCase() + operation.slice(1);
        const control = button(label, () => previewAction(service, operation, control));
        control.setAttribute('aria-label', `${label} ${service.name}`);
        controls.append(control);
      });
      const actionCell = cell(row, actions.length ? controls : node('span', 'cell-subtitle', 'Read-only'));
      if (service.protectionReason) actionCell.append(node('div', 'cell-subtitle', service.protectionReason));
      body.append(row);
    });
    container.replaceChildren(wrap);
  }

  function renderListeners() {
    const container = $('listeners-content');
    if (unavailableInventory(container)) return;
    const all = list(state.snapshot.value.listeners);
    const listeners = all.filter((listener) =>
      (!$('listener-exposure').value || listener.exposure === $('listener-exposure').value) &&
      matches($('listener-search').value, [listener.address, listener.port, listener.protocol, listener.process, listener.exposure, listener.policyState, serviceName(listener.serviceId)]));
    $('listener-count').textContent = `${listeners.length} of ${all.length} observed`;
    if (!listeners.length) {
      container.replaceChildren(all.length
        ? empty('No listeners match', 'Change the search or binding filter to see other sockets.', () => { $('listener-search').value = ''; $('listener-exposure').value = ''; renderListeners(); $('listener-search').focus(); }, 'Clear filters')
        : empty('No listening sockets were discovered', 'Refresh discovery and review source availability before assuming there are no listeners.', () => refreshAll(true)));
      return;
    }
    const { wrap, body } = table(['Socket', 'Binding', 'Owner', 'Host-policy evidence'], 'Listening sockets', 'listener-table');
    listeners.forEach((listener) => {
      const row = node('tr');
      const socket = cell(row, node('span', 'cell-title mono', `${listener.address.includes(':') ? `[${listener.address}]` : listener.address}:${listener.port}`));
      socket.append(node('div', 'cell-subtitle', `${listener.protocol.toUpperCase()} · ${listener.family}`));
      cell(row, badge(listener.exposure || 'Unknown'));
      const owner = cell(row, node('span', 'cell-title', listener.process || 'Owner unavailable'));
      if (listener.pid) owner.append(node('div', 'cell-subtitle', `PID ${listener.pid}`));
      if (listener.serviceId) {
        const link = node('a', 'cell-subtitle', serviceName(listener.serviceId));
        link.href = '#services';
        link.addEventListener('click', (event) => { event.preventDefault(); showService(listener.serviceId); });
        owner.append(link);
      } else owner.append(node('div', 'cell-subtitle', 'No matching managed service'));
      const policy = cell(row, badge(listener.policyState || 'Not determined'));
      if (listener.note) policy.append(node('div', 'cell-subtitle', listener.note));
      body.append(row);
    });
    container.replaceChildren(wrap);
  }
  function renderRoutes() {
    const container = $('routes-content');
    if (unavailableInventory(container)) return;
    const routes = list(state.snapshot.value.routes);
    if (!routes.length) {
      container.replaceChildren(empty('No published routes were discovered', 'This inventory reads supported proxy sources. Unavailable sources or external proxies can still provide access; check source health.', () => refreshAll(true)));
      return;
    }
    const { wrap, body } = table(['Provider / audience', 'Published address', 'Backend target', 'Observed status'], 'Published proxy routes', 'route-table');
    routes.forEach((route) => {
      const row = node('tr');
      const provider = cell(row, node('span', 'cell-title', route.provider));
      provider.append(badge(route.public ? 'Public route' : 'Not marked public', route.public ? 'warn' : ''));
      cell(row, route.address, 'mono breakable');
      cell(row, route.target, 'mono breakable');
      const status = cell(row, stateBadge(route.status));
      if (route.error) status.append(node('div', 'error-text', route.error));
      body.append(row);
    });
    container.replaceChildren(wrap);
  }
  function renderProjects() {
    const container = $('projects-content');
    if (unavailableInventory(container)) return;
    const all = list(state.snapshot.value.projects);
    const projects = all.filter((project) => matches($('project-search').value, [project.name, project.path, project.kind, ...list(project.serviceIds).map(serviceName)]));
    $('project-count').textContent = `${projects.length} of ${all.length} discovered`;
    if (!projects.length) {
      container.replaceChildren(all.length
        ? empty('No projects match', 'Search by project name, path, kind, or an associated service.', () => { $('project-search').value = ''; renderProjects(); $('project-search').focus(); }, 'Clear search')
        : empty('No projects were discovered', 'Discovery inspects configured project roots and known service working directories. Check configured roots on the installation host, then refresh.', () => refreshAll(true)));
      return;
    }
    const grid = node('div', 'project-list');
    projects.forEach((project) => {
      const card = node('article', 'project-card');
      const heading = node('div', 'project-title');
      heading.append(node('h2', '', project.name), badge(project.kind || 'Project'));
      card.append(heading, node('code', 'path', project.path));
      const kinds = node('div', 'button-row');
      if (project.git) kinds.append(badge('Git repository', 'accent'));
      kinds.append(node('span', 'meta', `${list(project.serviceIds).length} associated ${list(project.serviceIds).length === 1 ? 'service' : 'services'}`));
      card.append(kinds);
      if (list(project.serviceIds).length) {
        const services = node('ul');
        project.serviceIds.forEach((id) => {
          const item = node('li');
          const link = node('a', 'breakable', serviceName(id));
          link.href = '#services';
          link.addEventListener('click', (event) => { event.preventDefault(); showService(id); });
          item.append(link);
          services.append(item);
        });
        card.append(services);
      }
      grid.append(card);
    });
    container.replaceChildren(grid);
  }
  function renderAudit() {
    const notice = $('audit-notice');
    notice.replaceChildren();
    const value = state.audit.value;
    if (state.audit.error && value) notice.append(warningBox('Audit refresh failed. Showing previously received records.', [state.audit.error], 'error'));
    if (list(value?.warnings).length) notice.append(warningBox('Audit may be incomplete', value.warnings));
    const container = $('audit-content');
    if (!value) {
      container.replaceChildren(state.audit.error
        ? empty('Audit could not be loaded', state.audit.error, () => refreshResource('audit'), 'Retry audit')
        : skeleton('Loading recent audit records…'));
      return;
    }
    const all = list(value.entries);
    const entries = all.filter((entry) =>
      (!$('audit-result').value || (entry.success ? 'success' : 'unconfirmed') === $('audit-result').value) &&
      matches($('audit-search').value, [entry.actor, entry.operation, entry.target, entry.detail])).sort((a, b) => new Date(b.time) - new Date(a.time));
    if (!entries.length) {
      container.replaceChildren(all.length
        ? empty('No audit records match', 'Change the search or result filter.', () => { $('audit-search').value = ''; $('audit-result').value = ''; renderAudit(); $('audit-search').focus(); }, 'Clear filters')
        : empty('No recorded changes yet', 'This view shows the bounded recent audit history returned by the server. Discovery alone does not create a control action.', () => refreshResource('audit'), 'Reload audit'));
      return;
    }
    const { wrap, body } = table(['When', 'Actor', 'Operation / target', 'Result'], 'Recent audit history', 'audit-table');
    entries.forEach((entry) => {
      const row = node('tr');
      cell(row, timeNode(entry.time));
      cell(row, entry.actor, 'breakable');
      const operation = cell(row, node('span', 'cell-title', entry.operation));
      operation.append(node('div', 'cell-subtitle mono', entry.target));
      const result = cell(row, badge(entry.success ? 'Succeeded' : 'Not confirmed', entry.success ? 'good' : 'warn'));
      if (entry.detail) result.append(node('div', 'cell-subtitle', entry.detail));
      body.append(row);
    });
    container.replaceChildren(wrap);
  }

  function renderSnapshot() {
    const snapshot = state.snapshot.value;
    $('host-name').textContent = snapshot?.host?.name || 'Host inventory';
    $('snapshot-time').textContent = snapshot ? `Collected ${date(snapshot.generatedAt)}` : '';
    if (snapshot) {
      populateOptions('service-manager', list(snapshot.services).map((service) => service.manager), 'All managers');
      populateOptions('service-scope', list(snapshot.services).map((service) => service.scope), 'All scopes');
      populateOptions('service-state', list(snapshot.services).map((service) => service.state), 'All states');
      populateOptions('listener-exposure', list(snapshot.listeners).map((listener) => listener.exposure), 'All bindings');
    }
    renderSnapshotNotice();
    renderOverview();
    renderServices();
    renderListeners();
    renderRoutes();
    renderProjects();
    renderFreshness();
  }
  function renderFreshness() {
    const element = $('freshness');
    const snapshot = state.snapshot.value;
    if (!snapshot) { element.textContent = state.snapshot.loading ? 'Collecting inventory…' : 'Inventory unavailable'; return; }
    const generated = new Date(snapshot.generatedAt).getTime();
    const seconds = Math.max(0, Math.floor((Date.now() - generated) / 1000));
    const valid = Number.isFinite(seconds) && new Date(snapshot.generatedAt).getFullYear() > 1;
    const stale = !valid || seconds > 120 || Boolean(state.snapshot.error);
    element.classList.toggle('stale', stale);
    element.textContent = state.snapshot.loading ? 'Refreshing inventory…' : !valid ? 'Collection time unavailable' : `${stale ? 'Stale · ' : ''}${seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m`} since collection`;
    element.title = `Collected ${date(snapshot.generatedAt)}`;
  }

  function networkLocked() {
    return !state.network.value?.available || Boolean(state.network.value?.pending) || Boolean(state.network.error) || state.pendingBusy || state.previewBusy;
  }
  function resetDraft() {
    const network = state.network.value;
    if (!network) return;
    state.draft = list(network.policy?.interfaces).map((entry) => ({
      key: ++state.draftSerial, name: entry.name, tcp: list(entry.tcpPorts).join(', '),
      udp: list(entry.udpPorts).join(', '), peer: Boolean(entry.allowTailscalePeerAPI),
    }));
    state.draftRevision = network.revision;
    state.draftPendingToken = network.pending?.token || '';
    state.draftDirty = false;
    errorText('policy-error', '');
    renderEditor();
  }
  function draftChanged() {
    state.draftDirty = true;
    errorText('policy-error', '');
    updateEditorControls();
  }
  function renderEditor() {
    const container = $('interface-rows');
    container.replaceChildren();
    if (!state.draft?.length) {
      container.append(empty('No interfaces in this policy', 'Hostdesk does not restrict new inbound ports on unlisted interfaces. Add an exact interface name to create an explicit allowlist; other host firewall rules remain independent.'));
    }
    list(state.draft).forEach((entry, index) => {
      const fieldset = node('fieldset', 'interface-row');
      fieldset.append(node('legend', '', `Interface ${index + 1}`));
      fieldset.setAttribute('aria-describedby', 'policy-help');
      const fields = node('div', 'interface-fields');
      [['name', 'Interface name', 'text'], ['tcp', 'Allowed TCP ports', 'text'], ['udp', 'Allowed UDP ports', 'text']].forEach(([key, label, type]) => {
        const group = node('div');
        const input = node('input');
        input.type = type;
        input.id = `interface-${entry.key}-${key}`;
        input.value = entry[key];
        input.autocomplete = 'off';
        input.spellcheck = false;
        if (key === 'name') { input.maxLength = 15; input.required = true; }
        const labelNode = node('label', '', label);
        labelNode.htmlFor = input.id;
        input.addEventListener('input', () => { entry[key] = input.value; input.removeAttribute('aria-invalid'); draftChanged(); });
        group.append(labelNode, input);
        fields.append(group);
      });
      const foot = node('div', 'interface-foot');
      const label = node('label', 'check-label');
      const checkbox = node('input');
      checkbox.type = 'checkbox';
      checkbox.checked = entry.peer;
      checkbox.addEventListener('change', () => { entry.peer = checkbox.checked; draftChanged(); });
      label.append(checkbox, document.createTextNode('Allow runtime-discovered Tailscale Peer API ports'));
      const remove = button('Remove interface', () => {
        state.draft = state.draft.filter((candidate) => candidate.key !== entry.key);
        draftChanged();
        renderEditor();
        $('add-interface').focus();
      }, 'button quiet danger small');
      remove.setAttribute('aria-label', `Remove interface ${index + 1}${entry.name ? `, ${entry.name}` : ''}`);
      foot.append(label, remove);
      fieldset.append(fields, foot);
      container.append(fieldset);
    });
    updateEditorControls();
  }
  function updateEditorControls() {
    const locked = networkLocked();
    const stale = state.draft !== null && state.network.value && state.draftRevision !== state.network.value.revision;
    $('interface-rows').querySelectorAll('fieldset').forEach((fieldset) => { fieldset.disabled = locked || stale; });
    $('add-interface').disabled = locked || stale;
    $('preview-policy').disabled = locked || stale || state.draft === null;
    $('discard-policy').disabled = locked || (!state.draftDirty && !stale);
    $('policy-draft-status').textContent = stale ? 'The policy revision changed on the host. Discard edits to load the current policy before previewing.'
      : state.network.value?.pending ? 'Editing is paused until the pending policy is confirmed or rolled back.'
        : state.draftDirty ? 'Unsaved edits · Preview validates the change without applying it.'
          : 'Showing the current host policy. Changes require a preview and exact typed confirmation.';
  }
  function renderNetwork(forceDraft = false) {
    const network = state.network.value;
    const notice = $('network-notice');
    notice.replaceChildren();
    $('reload-network').disabled = state.network.loading;
    if (state.network.error) {
      const failure = warningBox(network ? 'Policy refresh failed. The last received policy is read-only.' : 'Network policy could not be loaded.', [state.network.error], 'error');
      if (!state.network.loading) failure.append(button('Retry policy', () => refreshResource('network')));
      notice.append(failure);
    } else if (!network) notice.append(skeleton('Loading current network policy…'));
    $('network-summary').replaceChildren();
    if (network) {
      if (!network.available) notice.append(warningBox('Network controls unavailable', [network.error || 'The privileged broker or firewall capability is unavailable. No policy change can be applied.']));
      const summary = node('div', 'policy-summary');
      summary.append(node('span', '', `Revision: ${network.revision || 'Not reported'}`), node('span', '', `Protected management TCP ports: ${list(network.protectedTCPPorts).length ? network.protectedTCPPorts.join(', ') : 'None reported'}`));
      $('network-summary').append(summary);
      if (network.rules) $('network-summary').append(details('Current Hostdesk rules', node('pre', '', network.rules)));
      if (forceDraft || state.draft === null || (!state.draftDirty && (state.draftRevision !== network.revision || state.draftPendingToken !== (network.pending?.token || '')))) resetDraft();
    }
    reveal($('policy-editor'), Boolean(network));
    updateEditorControls();
    renderPending();
  }
  function readPolicy() {
    const seen = new Set();
    const interfaces = list(state.draft).map((entry) => {
      const name = entry.name.trim();
      const fail = (key, message) => {
        const input = $(`interface-${entry.key}-${key}`);
        input.setAttribute('aria-invalid', 'true');
        input.setAttribute('aria-describedby', 'policy-error');
        input.focus();
        throw new Error(message);
      };
      if (!name || name.length > 15 || /[\s\/:\x00-\x1f\x7f]/.test(name)) fail('name', 'Enter an exact Linux interface name, up to 15 characters, without whitespace, slash, colon, or control characters.');
      if (seen.has(name)) fail('name', `Interface ${name} appears more than once. Keep one allowlist per interface.`);
      seen.add(name);
      const ports = (key) => {
        if (!entry[key].trim()) return [];
        const pieces = entry[key].split(',').map((part) => part.trim());
        if (pieces.some((part) => !/^\d+$/.test(part) || Number(part) < 1 || Number(part) > 65535)) fail(key, `The ${key.toUpperCase()} list for ${name} must contain individual ports from 1 to 65535, separated by commas. Ranges and empty entries are not accepted.`);
        return [...new Set(pieces.map(Number))].sort((a, b) => a - b);
      };
      return { name, tcpPorts: ports('tcp'), udpPorts: ports('udp'), allowTailscalePeerAPI: entry.peer };
    });
    return { interfaces };
  }

  function renderPending() {
    const pending = state.network.value?.pending;
    reveal($('pending-policy'), Boolean(pending));
    if (!pending) {
      if (state.lastPendingToken && !state.pendingBusy) message('The host reports no pending policy. The current policy has been reloaded; check Audit for the recorded outcome.');
      state.lastPendingToken = '';
      return;
    }
    if (state.lastPendingToken !== pending.token) {
      state.lastPendingToken = pending.token;
      errorText('pending-error', '');
      say('An access policy is pending. Confirm it over this connection or the host will roll back automatically.');
    }
    const remaining = Math.max(0, Math.ceil((new Date(pending.expiresAt).getTime() - Date.now()) / 1000));
    const expired = !Number.isFinite(remaining) || remaining <= 0;
    $('pending-countdown').textContent = expired
      ? 'Rollback deadline reached. Waiting for the host to report the result.'
      : `${remaining} seconds until automatic rollback`;
    $('confirm-policy').disabled = expired || state.pendingBusy;
    $('rollback-policy').disabled = state.pendingBusy;
    $('confirm-policy').textContent = state.pendingBusy ? 'Working…' : 'Keep this policy';
  }

  function renderResource(name) {
    const restore = retainContext($('main'));
    if (name === 'snapshot') renderSnapshot();
    else if (name === 'network') renderNetwork();
    else { $('reload-audit').disabled = state.audit.loading; renderAudit(); }
    restore();
  }
  function fetchResource(name, force = false) {
    const epoch = state.epoch;
    const target = state[name];
    if (target.inFlight) return target.inFlight;
    const generation = target.generation;
    target.loading = true;
    if (!target.value) renderResource(name);
    if (name === 'snapshot') renderFreshness();
    if (name === 'network') $('reload-network').disabled = true;
    if (name === 'audit') $('reload-audit').disabled = true;
    target.inFlight = (async () => {
      try {
        const result = await api(name === 'snapshot' ? force ? '/api/refresh' : '/api/snapshot' : `/api/${name}`, name === 'snapshot' && force ? { method: 'POST' } : {});
        if (!state.session || epoch !== state.epoch || generation !== target.generation) return;
        target.value = result;
        target.error = '';
      } catch (error) {
        if (!state.session || epoch !== state.epoch || generation !== target.generation) return;
        target.error = error.message;
      } finally {
        target.loading = false;
        target.inFlight = null;
        if (state.session && epoch === state.epoch) renderResource(name);
      }
    })();
    return target.inFlight;
  }
  function invalidateReads() {
    // A read begun before a mutation must not overwrite the mutation's newer host state.
    ['snapshot', 'network', 'audit'].forEach((name) => { state[name].generation += 1; });
  }
  async function refreshAfterChange() {
    await Promise.all([state.refreshing, state.snapshot.inFlight, state.network.inFlight, state.audit.inFlight]);
    await refreshAll(true);
  }
  function schedulePoll() {
    clearTimeout(state.poll);
    if (!state.session || document.hidden) return;
    if (!state.network.value?.pending && !$('auto-refresh').checked) return;
    state.poll = setTimeout(async () => {
      if (state.network.value?.pending) await refreshResource('network');
      else await refreshAll(false);
    }, state.network.value?.pending ? 4000 : 30000);
  }
  async function refreshResource(name) {
    if (!state.session) return;
    await fetchResource(name);
    schedulePoll();
  }
  async function refreshAll(force = false) {
    if (!state.session) return;
    if (state.refreshing) return state.refreshing;
    const epoch = state.epoch;
    clearTimeout(state.poll);
    $('refresh-button').disabled = true;
    $('refresh-button').textContent = 'Refreshing…';
    const work = Promise.all([fetchResource('snapshot', force), fetchResource('network'), fetchResource('audit')]);
    state.refreshing = work;
    try {
      await work;
      if (force && state.session && epoch === state.epoch) say(state.snapshot.error ? 'Inventory refresh failed. The last received data is retained.' : 'Live inventory refreshed.');
    } finally {
      if (epoch === state.epoch) {
        state.refreshing = null;
        $('refresh-button').disabled = false;
        $('refresh-button').textContent = 'Refresh';
        schedulePoll();
      }
    }
  }

  async function previewAction(service, operation, opener) {
    if (state.previewBusy || state.preview) return;
    state.previewBusy = true;
    opener.disabled = true;
    const original = opener.textContent;
    opener.textContent = 'Previewing…';
    const epoch = state.epoch;
    try {
      const preview = await api('/api/actions/preview', { method: 'POST', body: { id: service.id, operation } });
      if (!state.session || epoch !== state.epoch) return;
      openPreview(preview, 'action', opener, { target: service.name, id: service.id, operation });
    } catch (error) { if (state.session && epoch === state.epoch) message(`Could not preview ${operation}: ${error.message}`, 'error'); }
    finally {
      opener.disabled = false;
      opener.textContent = original;
      if (epoch === state.epoch) { state.previewBusy = false; updatePreviewControls(); }
    }
  }
  async function previewPolicy() {
    if (networkLocked() || state.preview) return;
    errorText('policy-error', '');
    let policy;
    try { policy = readPolicy(); }
    catch (error) { errorText('policy-error', error.message); return; }
    state.previewBusy = true;
    updateEditorControls();
    $('preview-policy').textContent = 'Validating…';
    const epoch = state.epoch;
    try {
      const preview = await api('/api/network/preview', { method: 'POST', body: { revision: state.draftRevision, policy } });
      if (!state.session || epoch !== state.epoch) return;
      openPreview(preview, 'network', $('preview-policy'), { policy });
    } catch (error) {
      if (state.session && epoch === state.epoch) {
        errorText('policy-error', error.message);
        if (error.status === 409) await refreshResource('network');
      }
    } finally {
      if (epoch === state.epoch) {
        state.previewBusy = false;
        $('preview-policy').textContent = 'Preview policy';
        updatePreviewControls();
        updateEditorControls();
      }
    }
  }
  function openPreview(preview, kind, opener, context) {
    state.preview = { ...preview, kind, context, invalid: false };
    state.previewOpener = opener;
    $('preview-title').textContent = kind === 'network' ? 'Review access policy' : `${context.operation[0].toUpperCase() + context.operation.slice(1)} service`;
    const body = $('preview-body');
    body.replaceChildren(node('p', '', preview.summary));
    if (kind === 'action') body.append(facts([['Operation', context.operation], ['Target', context.target], ['Identity', context.id]]));
    else {
      body.append(warningBox('Applying starts a timed rollback window.', ['Keep this page open. The change is not permanent until you choose Keep this policy over the live connection.']));
      if (!context.policy.interfaces.length) body.append(node('p', '', 'No interfaces will have a Hostdesk port allowlist. Other firewall rules are unchanged.'));
      context.policy.interfaces.forEach((entry) => body.append(facts([
        ['Interface', entry.name], ['Allowed TCP', entry.tcpPorts.join(', ') || 'None'], ['Allowed UDP', entry.udpPorts.join(', ') || 'None'], ['Peer API', entry.allowTailscalePeerAPI ? 'Runtime ports permitted' : 'Not added'],
      ])));
    }
    if (list(preview.warnings).length) body.append(warningBox('Review these warnings', preview.warnings));
    if (preview.rules) body.append(details('Proposed firewall rules', node('pre', '', preview.rules)));
    $('confirmation-text').textContent = preview.confirmation;
    $('confirmation-input').value = '';
    $('confirmation-input').disabled = false;
    $('apply-preview').textContent = kind === 'network' ? 'Apply with rollback timer' : 'Apply change';
    $('cancel-preview').disabled = false;
    errorText('preview-error', '');
    updatePreviewControls();
    $('preview-dialog').showModal();
    $('cancel-preview').focus();
  }
  function updatePreviewControls() {
    const preview = state.preview;
    if (!preview) return;
    const remaining = Math.max(0, Math.ceil((new Date(preview.expiresAt).getTime() - Date.now()) / 1000));
    const expired = !Number.isFinite(remaining) || remaining <= 0;
    $('preview-expiry').textContent = preview.invalid ? 'This preview can no longer be applied. Close it, refresh, and request a new preview.' : expired ? 'This preview expired. Cancel and request a new preview.' : `Preview expires in ${remaining} seconds.`;
    $('apply-preview').disabled = state.previewBusy || preview.invalid || expired || !preview.confirmation || $('confirmation-input').value !== preview.confirmation;
  }
  function closePreview() {
    if ($('preview-dialog').open) $('preview-dialog').close();
    state.preview = null;
    const opener = state.previewOpener;
    state.previewOpener = null;
    $('confirmation-input').value = '';
    if (!state.session) return;
    const equivalent = opener?.getAttribute('aria-label')
      ? [...$('services-content').querySelectorAll('button[aria-label]')].find((element) => element.getAttribute('aria-label') === opener.getAttribute('aria-label'))
      : null;
    const target = opener?.isConnected && !opener.disabled ? opener : equivalent || $(`${state.view}-heading`);
    target.tabIndex = target.matches('h1') ? -1 : target.tabIndex;
    target.focus();
  }
  async function applyPreview() {
    const preview = state.preview;
    if (!preview || state.previewBusy || $('apply-preview').disabled) return;
    state.previewBusy = true;
    $('confirmation-input').disabled = true;
    $('cancel-preview').disabled = true;
    $('apply-preview').textContent = 'Applying…';
    updatePreviewControls();
    const epoch = state.epoch;
    try {
      const result = await api(preview.kind === 'network' ? '/api/network/apply' : '/api/actions/apply', {
        method: 'POST', body: { token: preview.token, confirmation: $('confirmation-input').value },
      });
      if (!state.session || epoch !== state.epoch) return;
      invalidateReads();
      state.previewBusy = false;
      closePreview();
      if (preview.kind === 'network') {
        state.network.value = result;
        state.network.error = '';
        renderNetwork(true);
        message('Policy applied provisionally. Review the countdown above and confirm access or roll back.', 'warning');
        $('rollback-policy').focus();
      } else message(`${preview.context.operation[0].toUpperCase() + preview.context.operation.slice(1)} completed for ${preview.context.target}. Refreshing observed state.`);
    } catch (error) {
      if (state.session && epoch === state.epoch) {
        invalidateReads();
        preview.invalid = true;
        errorText('preview-error', `${error.message} The one-use preview will not be retried. Refresh the host state before requesting another.`);
      }
    } finally {
      if (epoch === state.epoch) {
        state.previewBusy = false;
        $('cancel-preview').disabled = false;
        $('confirmation-input').disabled = false;
        $('apply-preview').textContent = preview.kind === 'network' ? 'Apply with rollback timer' : 'Apply change';
        updatePreviewControls();
        updateEditorControls();
        schedulePoll();
      }
    }
    if (state.session && epoch === state.epoch) await refreshAfterChange();
  }
  async function resolvePolicy(operation) {
    const pending = state.network.value?.pending;
    if (!pending || state.pendingBusy) return;
    state.pendingBusy = true;
    errorText('pending-error', '');
    renderPending();
    updateEditorControls();
    const epoch = state.epoch;
    try {
      const network = await api(`/api/network/${operation}`, { method: 'POST', body: { token: pending.token } });
      if (!state.session || epoch !== state.epoch) return;
      invalidateReads();
      state.network.value = network;
      state.network.error = '';
      renderNetwork(true);
      message(operation === 'confirm' ? 'Access policy confirmed and saved on the host.' : 'The previous access policy was restored.');
      $('reload-network').focus();
    } catch (error) {
      if (state.session && epoch === state.epoch) {
        invalidateReads();
        errorText('pending-error', error.message);
        message(`Could not ${operation === 'confirm' ? 'confirm' : 'roll back'} the policy: ${error.message}`, 'error');
      }
    } finally {
      if (epoch === state.epoch) {
        state.pendingBusy = false;
        renderPending();
        updateEditorControls();
        schedulePoll();
      }
    }
    if (state.session && epoch === state.epoch) await refreshAfterChange();
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const token = $('owner-token').value.trim();
    if (!token) return;
    $('owner-token').value = '';
    $('login-button').disabled = true;
    $('login-button').textContent = 'Signing in…';
    errorText('login-error', '');
    try {
      await api('/api/login', { method: 'POST', body: { token }, public: true });
      await checkSession();
    } catch (error) { errorText('login-error', error.message); $('owner-token').focus(); }
    finally { $('login-button').disabled = false; $('login-button').textContent = 'Sign in'; }
  });
  $('session-retry').addEventListener('click', checkSession);
  $('logout-button').addEventListener('click', async () => {
    $('logout-button').disabled = true;
    try {
      await api('/api/logout', { method: 'POST' });
      expireSession('Signed out. If this host uses a trusted proxy identity, checking the session may sign you in again.');
    } catch (error) { if (state.session) message(`Sign out failed: ${error.message}`, 'error'); }
    finally { $('logout-button').disabled = false; }
  });
  $('refresh-button').addEventListener('click', () => refreshAll(true));
  $('auto-refresh').addEventListener('change', () => { schedulePoll(); say($('auto-refresh').checked ? 'Automatic inventory refresh enabled, every 30 seconds while visible.' : 'Automatic inventory refresh paused. Pending policy status will still be checked.'); });
  $('reload-network').addEventListener('click', () => refreshResource('network'));
  $('reload-audit').addEventListener('click', () => refreshResource('audit'));
  $('service-search').addEventListener('input', renderServices);
  ['service-manager', 'service-scope', 'service-state'].forEach((id) => $(id).addEventListener('change', renderServices));
  $('clear-service-filters').addEventListener('click', () => clearServiceFilters());
  $('listener-search').addEventListener('input', renderListeners);
  $('listener-exposure').addEventListener('change', renderListeners);
  $('project-search').addEventListener('input', renderProjects);
  $('audit-search').addEventListener('input', renderAudit);
  $('audit-result').addEventListener('change', renderAudit);
  $('add-interface').addEventListener('click', () => {
    if (networkLocked()) return;
    const entry = { key: ++state.draftSerial, name: '', tcp: '', udp: '', peer: false };
    state.draft.push(entry);
    draftChanged();
    renderEditor();
    $(`interface-${entry.key}-name`).focus();
  });
  $('discard-policy').addEventListener('click', () => { resetDraft(); $('add-interface').focus(); });
  $('preview-policy').addEventListener('click', previewPolicy);
  $('confirmation-input').addEventListener('input', updatePreviewControls);
  $('confirmation-input').addEventListener('keydown', (event) => { if (event.key === 'Enter') event.preventDefault(); });
  $('cancel-preview').addEventListener('click', closePreview);
  $('preview-dialog').addEventListener('cancel', (event) => { event.preventDefault(); if (!state.previewBusy) closePreview(); });
  $('preview-dialog').addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const controls = [...event.currentTarget.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], summary, [tabindex="0"]')]
      .filter((element) => element.getClientRects().length);
    if (!controls.length) { event.preventDefault(); return; }
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
  $('apply-preview').addEventListener('click', applyPreview);
  $('confirm-policy').addEventListener('click', () => resolvePolicy('confirm'));
  $('rollback-policy').addEventListener('click', () => resolvePolicy('rollback'));
  $('skip-link').addEventListener('click', (event) => { event.preventDefault(); $('main').focus(); });
  window.addEventListener('hashchange', () => setView());
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) clearTimeout(state.poll);
    else if (state.session) {
      if (state.network.value?.pending) refreshResource('network');
      else if ($('auto-refresh').checked) refreshAll(false);
    }
  });
  window.addEventListener('beforeunload', (event) => {
    if (state.draftDirty || state.network.value?.pending) { event.preventDefault(); event.returnValue = ''; }
  });
  setInterval(() => {
    if (!state.session || document.hidden) return;
    renderFreshness();
    renderPending();
    updatePreviewControls();
  }, 1000);
  checkSession();
})();
