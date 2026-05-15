/* whichway dashboard. No framework. Token comes from the meta tag the
 * server injects at /. We pass it on every /api/* call as ?token=. Sorting
 * and filtering are client-side over the JSON payload. */

(function () {
  const tokenMeta = document.querySelector('meta[name="whichway-token"]');
  const TOKEN = tokenMeta ? tokenMeta.getAttribute('content') : '';
  const state = {
    summary: null,
    sockets: null,
    throughput: null,
    pf: null,
    sort: {},        // table id -> { col, dir }
    filter: {},      // table id -> string
    autoTimer: null,
  };

  async function api(path, params) {
    const u = new URL(path, window.location.origin);
    u.searchParams.set('token', TOKEN);
    if (params) for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    const r = await fetch(u, { headers: { 'X-Whichway-Token': TOKEN } });
    return { status: r.status, body: r.ok ? await r.json() : await r.json().catch(() => ({})) };
  }

  function setStatus(t) { document.getElementById('status').textContent = t; }
  function setError(id, e) {
    const n = document.getElementById('err-' + id);
    if (n) n.textContent = e ? '(' + e + ')' : '';
  }

  /* ---------- table rendering ---------- */
  function renderTable(id, cols, rows) {
    const table = document.getElementById(id);
    const thead = table.querySelector('thead');
    const tbody = table.querySelector('tbody');
    thead.innerHTML = '';
    const tr = document.createElement('tr');
    for (const c of cols) {
      const th = document.createElement('th');
      th.textContent = c.label;
      th.addEventListener('click', () => {
        const cur = state.sort[id] || {};
        const dir = cur.col === c.key && cur.dir === 'asc' ? 'desc' : 'asc';
        state.sort[id] = { col: c.key, dir };
        renderTable(id, cols, rows);
      });
      tr.appendChild(th);
    }
    thead.appendChild(tr);

    let view = rows.slice();
    const f = (state.filter[id] || '').toLowerCase();
    if (f) view = view.filter(r => cols.some(c => String(r[c.key] ?? '').toLowerCase().includes(f)));
    const s = state.sort[id];
    if (s) {
      view.sort((a, b) => {
        const av = a[s.col], bv = b[s.col];
        if (typeof av === 'number' && typeof bv === 'number') return s.dir === 'asc' ? av - bv : bv - av;
        return s.dir === 'asc' ? String(av ?? '').localeCompare(String(bv ?? '')) : String(bv ?? '').localeCompare(String(av ?? ''));
      });
    }
    tbody.innerHTML = '';
    for (const r of view) {
      const tr = document.createElement('tr');
      for (const c of cols) {
        const td = document.createElement('td');
        if (c.render) c.render(td, r); else td.textContent = r[c.key] ?? '';
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  function badge(td, label) {
    const span = document.createElement('span');
    span.className = 'badge badge-' + label.replace(/[^A-Za-z]/g, '');
    span.textContent = label;
    td.appendChild(span);
  }

  /* ---------- summary ---------- */
  async function loadSummary() {
    setStatus('loading…');
    const r = await api('/api/summary');
    if (r.status !== 200) { setStatus('error: ' + r.status); return; }
    state.summary = r.body;
    document.getElementById('priv').textContent = r.body.privileged ? 'root: yes' : 'root: no';
    setStatus('updated ' + r.body.collected_at);

    setError('routes', r.body.routes.error);
    setError('tunnels', r.body.tunnels.error);
    setError('dns', r.body.dns.error);
    setError('services', r.body.services.error);

    renderTable('tunnels',
      [
        { key: 'interface', label: 'interface' },
        { key: 'label', label: 'label', render: (td, r) => badge(td, r.label) },
        { key: 'local_ip', label: 'local_ip' },
        { key: 'peer_or_gateway', label: 'peer' },
        { key: 'mtu', label: 'mtu' },
        { key: 'description', label: 'description' },
      ],
      r.body.tunnels.data || []);

    renderTable('routes',
      [
        { key: 'family', label: 'fam' },
        { key: 'destination', label: 'destination' },
        { key: 'gateway', label: 'gateway' },
        { key: 'flags', label: 'flags' },
        { key: 'interface', label: 'netif' },
        { key: 'label', label: 'label', render: (td, r) => r.label ? badge(td, r.label) : (td.textContent = '') },
      ],
      r.body.routes.data || []);

    const dnsRows = (r.body.dns.data || []).map(d => ({
      number: d.number,
      scope: d.scope,
      interface: d.interface || '',
      nameservers: (d.nameservers || []).join(', '),
      domain: d.domain || (d.search || []).join(','),
      flags: d.flags || '',
      order: d.order || '',
    }));
    renderTable('dns',
      [
        { key: 'number', label: '#' },
        { key: 'scope', label: 'scope' },
        { key: 'interface', label: 'iface' },
        { key: 'nameservers', label: 'nameservers' },
        { key: 'domain', label: 'match' },
        { key: 'flags', label: 'flags' },
        { key: 'order', label: 'order' },
      ],
      dnsRows);

    const svc = r.body.services.data;
    if (svc) {
      renderTable('services',
        [
          { key: 'interface', label: 'interface' },
          { key: 'family', label: 'fam' },
          { key: 'address', label: 'address' },
          { key: 'reach', label: 'reach' },
        ],
        svc.services || []);
    }
  }

  async function lookup(target) {
    setStatus('looking up…');
    const r = await api('/api/lookup', { target });
    if (r.status !== 200) { setStatus('lookup error'); return; }
    const l = r.body;
    const card = document.getElementById('lookup-card');
    card.classList.remove('hidden');
    const resolved = (l.resolved || []).join(', ') || '(no answer)';
    const route = l.destination && l.interface ? `${l.destination} → ${l.interface}` : '(no route)';
    const label = l.label ? `<span class="badge badge-${l.label.replace(/[^A-Za-z]/g, '')}">${escape(l.label)}</span>` : '';
    card.innerHTML =
      `<div><span class="label">Target:</span> ${escape(l.target)}</div>` +
      `<div><span class="label">Resolved:</span> ${escape(resolved)}` +
        (l.resolver_number ? ` <span class="muted">(resolver #${l.resolver_number}${l.resolver_match ? ', match ' + escape(l.resolver_match) : ''}${l.resolver_nameservers && l.resolver_nameservers.length ? ', ns ' + escape(l.resolver_nameservers.join(',')) : ''})</span>` : '') +
        `</div>` +
      `<div><span class="label">Route:</span> ${escape(route)} ${label}</div>` +
      (l.gateway ? `<div><span class="label">Gateway:</span> ${escape(l.gateway)}</div>` : '') +
      `<pre>${escape(l.verdict)}</pre>`;
    setStatus('lookup done');
  }
  function escape(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;" }[c])); }

  /* ---------- privileged tabs ---------- */
  async function loadSockets() {
    const r = await api('/api/sockets');
    const sock = document.getElementById('tab-sockets');
    if (r.status === 401) {
      sock.querySelector('table').classList.add('hidden');
      sock.querySelector('p').textContent = 'run with sudo to enable';
      return;
    }
    const data = (r.body && r.body.data) || [];
    renderTable('sockets',
      [
        { key: 'command', label: 'command' },
        { key: 'pid', label: 'pid' },
        { key: 'user', label: 'user' },
        { key: 'kind', label: 'kind' },
        { key: 'protocol', label: 'proto' },
        { key: 'local', label: 'local' },
        { key: 'remote', label: 'remote' },
        { key: 'state', label: 'state' },
      ],
      data);
  }

  async function loadThroughput() {
    const r = await api('/api/throughput');
    const t = document.getElementById('tab-throughput');
    if (r.status === 401) {
      t.querySelector('table').classList.add('hidden');
      t.querySelector('p').textContent = 'run with sudo to enable';
      return;
    }
    const data = (r.body && r.body.data) || [];
    renderTable('throughput',
      [
        { key: 'process', label: 'process' },
        { key: 'interface', label: 'iface' },
        { key: 'bytes_in', label: 'bytes_in' },
        { key: 'bytes_out', label: 'bytes_out' },
      ],
      data);
  }

  async function loadPf() {
    const r = await api('/api/pf');
    const t = document.getElementById('tab-pf');
    if (r.status === 401) {
      t.querySelector('p').textContent = 'run with sudo to enable';
      return;
    }
    const d = (r.body && r.body.data) || { rules: [], anchors: [] };
    document.getElementById('pf-anchors').textContent = (d.anchors || []).join('\n');
    document.getElementById('pf-rules').textContent = (d.rules || []).join('\n');
  }

  /* ---------- wiring ---------- */
  function init() {
    document.getElementById('refresh').addEventListener('click', loadSummary);
    document.getElementById('lookup').addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target.value.trim()) lookup(e.target.value.trim());
    });
    document.getElementById('auto').addEventListener('change', e => {
      if (state.autoTimer) clearInterval(state.autoTimer);
      const n = parseInt(e.target.value, 10);
      if (n > 0) state.autoTimer = setInterval(loadSummary, n * 1000);
    });
    for (const btn of document.querySelectorAll('.tabs button')) {
      btn.addEventListener('click', () => {
        for (const b of document.querySelectorAll('.tabs button')) b.classList.remove('active');
        for (const s of document.querySelectorAll('.tab')) s.classList.remove('active');
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      });
    }
    for (const inp of document.querySelectorAll('.filter')) {
      inp.addEventListener('input', () => {
        state.filter[inp.dataset.target] = inp.value;
        // Just re-render last loaded data for that table by re-running the
        // owning loader. Simpler: trigger summary reload only for summary tables.
        if (['routes', 'tunnels', 'dns', 'services'].includes(inp.dataset.target) && state.summary) {
          loadSummaryRefresh();
        } else if (inp.dataset.target === 'sockets' && state.sockets) {
          loadSockets();
        } else if (inp.dataset.target === 'throughput' && state.throughput) {
          loadThroughput();
        }
      });
    }
    document.getElementById('load-sockets').addEventListener('click', loadSockets);
    document.getElementById('load-throughput').addEventListener('click', loadThroughput);
    document.getElementById('load-pf').addEventListener('click', loadPf);
    loadSummary();
  }
  function loadSummaryRefresh() {
    // Re-render from cached state.summary without an extra fetch.
    if (!state.summary) return;
    // Cheapest path: just call loadSummary, which re-fetches. Filter input
    // typing is rare and fast.
    loadSummary();
  }
  init();
})();
