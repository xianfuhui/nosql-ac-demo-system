(() => {
  'use strict';

  // ---------- Tiện ích ----------
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const nf = (n, d = 1) => (n === null || n === undefined ? '–' : new Intl.NumberFormat('vi-VN', { maximumFractionDigits: d }).format(n));

  async function api(url, opts) {
    let r;
    try { r = await fetch(url, opts); } catch { throw new Error('Không kết nối được máy chủ'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Lỗi ${r.status}`);
    return j;
  }

  const C = { ink: '#14213d', pencil: '#2f5fd0', teal: '#14877b', hl: '#ffe066', red: '#d9484a', grid: '#e3ebf6', sub: '#4a5873' };
  const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  Chart.defaults.font.family = '"Instrument Sans", system-ui, sans-serif';
  Chart.defaults.color = C.sub;
  if (reduce) Chart.defaults.animation = false;

  const ROLE_VN = { admin: 'Quản trị', teacher: 'Giáo viên', counselor: 'Tư vấn viên' };
  const GROUP_VN = { academic: 'học tập', personal: 'cá nhân', family: 'gia đình', other: 'khác' };
  const GROUP_COLOR = { academic: C.pencil, personal: C.teal, family: C.hl, other: '#9aa6ba' };
  const COND_VN = { trained: 'đã tập huấn bảo mật', at_risk: 'học sinh có G2 dưới 10' };
  const PASS_COLS = ['G1', 'G2', 'G3'];

  const state = {
    datasets: [], id: null, stats: null, policies: [],
    role: 'admin', school: '*', trained: false, page: 1, q: '', charts: {},
    nb: { shown: null, visible: false, info: null, poll: null },
  };

  function draw(id, config) {
    if (state.charts[id]) state.charts[id].destroy();
    state.charts[id] = new Chart(document.getElementById(id), config);
  }
  function destroyCharts(prefix) {
    for (const k of Object.keys(state.charts)) if (k.startsWith(prefix)) { state.charts[k].destroy(); delete state.charts[k]; }
  }
  const baseOpts = { maintainAspectRatio: false, plugins: { legend: { display: false } } };

  // ---------- Nhập dữ liệu ----------
  const msg = (text, kind = '') => { const m = $('#importMsg'); m.textContent = text; m.className = `msg ${kind}`; };

  function setupTabs() {
    const tabs = [$('#tab-file'), $('#tab-url')];
    const panes = [$('#pane-file'), $('#pane-url')];
    const pick = (i) => {
      tabs.forEach((t, j) => { t.setAttribute('aria-selected', String(i === j)); t.tabIndex = i === j ? 0 : -1; panes[j].hidden = i !== j; });
      msg('');
    };
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => pick(i));
      t.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { const n = 1 - i; pick(n); tabs[n].focus(); }
      });
    });
    return pick;
  }

  function setupImport(pickTab) {
    const input = $('#fileInput'), drop = $('#drop');
    const showFile = () => {
      const f = input.files[0];
      $('#dropTitle').textContent = f ? f.name : 'Kéo file vào đây hoặc bấm để chọn';
      $('#dropHint').textContent = f ? `${nf(f.size / 1024, 0)} KB, sẵn sàng nhập` : 'CSV, TSV, JSON hoặc ZIP, tối đa 50 MB';
    };
    input.addEventListener('change', showFile);
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; showFile(); }
    });

    $('#pane-file').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!input.files[0]) return msg('Hãy chọn một file trước.', 'err');
      const fd = new FormData();
      fd.append('name', $('#fileName').value);
      fd.append('file', input.files[0]);
      await runImport('#fileBtn', 'Đang nhập vào MongoDB…', () => api('/api/datasets/upload', { method: 'POST', body: fd }));
    });

    $('#pane-url').addEventListener('submit', async (e) => {
      e.preventDefault();
      await runImport('#urlBtn', 'Đang tải link và nhập vào MongoDB…', () => api('/api/datasets/url', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: $('#urlInput').value.trim(), name: $('#urlName').value }),
      }));
    });

    $('#presetBtn').addEventListener('click', () => {
      $('#urlInput').value = 'https://archive.ics.uci.edu/static/public/320/student+performance.zip';
      $('#urlName').value = 'Student Performance (UCI)';
      pickTab(1);
      $('#urlInput').focus();
    });
  }

  async function runImport(btnSel, wait, job) {
    const btn = $(btnSel);
    btn.disabled = true;
    msg(wait);
    try {
      const r = await job();
      msg(`Đã nhập "${r.name}": ${nf(r.rowCount, 0)} dòng, ${r.colCount} cột.`, 'ok');
      await refreshDatasets(r.id);
      $('#overview').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
    } catch (err) {
      msg(err.message, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  // ---------- Danh sách dataset ----------
  async function refreshDatasets(selectId) {
    state.datasets = await api('/api/datasets');
    const sel = $('#dsSelect');
    sel.innerHTML = state.datasets.map((d) => `<option value="${esc(d.id)}">${esc(d.name)} (${nf(d.rowCount, 0)} dòng)</option>`).join('');
    const has = state.datasets.length > 0;
    $('#dsPick').hidden = !has;
    $('#empty').hidden = has;
    $('#workspace').hidden = !has;
    if (!has) { state.id = null; destroyCharts(''); loadNotebookInfo(); return; }
    const id = selectId && state.datasets.some((d) => d.id === selectId) ? selectId : state.datasets[0].id;
    sel.value = id;
    await openDataset(id);
  }

  async function openDataset(id) {
    state.id = id; state.page = 1; state.q = ''; $('#q').value = '';
    state.stats = await api(`/api/datasets/${id}/stats`);
    renderOverview();
    renderExplore();
    setupRecordControls();
    await loadRecords();
    loadNotebookInfo();
  }

  // ---------- Tổng quan ----------
  function sourceText(src) {
    if (!src) return '–';
    let t = src.value;
    if (src.type === 'url') { try { t = new URL(src.value).host; } catch { /* giữ nguyên */ } }
    return src.entry && src.entry !== src.value ? `${t} / ${src.entry}` : t;
  }

  function histConfig(col) {
    const h = col.hist;
    const colored = PASS_COLS.includes(col.name) && h.integer;
    return {
      type: 'bar',
      data: { labels: h.labels, datasets: [{ data: h.counts, borderRadius: 2, maxBarThickness: 40,
        backgroundColor: h.labels.map((l) => (colored && Number(l) < 10 ? C.red : C.pencil)) }] },
      options: { ...baseOpts, plugins: { legend: { display: false },
        tooltip: { callbacks: { title: (i) => `${col.name}: ${i[0].label}`, label: (i) => `${i.raw} dòng` } } },
        scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: C.grid }, ticks: { precision: 0 } } } },
    };
  }

  function catConfig(col) {
    const top = col.top.slice(0, 8);
    return {
      type: 'bar',
      data: { labels: top.map((t) => t.value), datasets: [{ data: top.map((t) => t.count), backgroundColor: C.teal, borderRadius: 2, maxBarThickness: 22 }] },
      options: { ...baseOpts, indexAxis: 'y',
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (i) => `${i.raw} dòng` } } },
        scales: { x: { beginAtZero: true, grid: { color: C.grid }, ticks: { precision: 0 } }, y: { grid: { display: false } } } },
    };
  }

  function passInfo(col) {
    if (!PASS_COLS.includes(col.name) || !col.hist.integer) return '';
    const total = col.hist.counts.reduce((a, b) => a + b, 0);
    const pass = col.hist.labels.reduce((s, l, i) => s + (Number(l) >= 10 ? col.hist.counts[i] : 0), 0);
    return `<p class="passline"><span><i class="swatch" style="background:${C.red}"></i>Dưới 10</span>` +
      `<span><i class="swatch" style="background:${C.pencil}"></i>Từ 10 trở lên (đạt): ${nf((pass / total) * 100, 0)}%</span></p>`;
  }

  function renderOverview() {
    const st = state.stats, ds = st.dataset;
    $('#dsTitle').textContent = ds.name;
    $('#dsFacts').innerHTML = [
      ['Số dòng', nf(ds.rowCount, 0)], ['Số cột', ds.colCount], ['Nguồn', esc(sourceText(ds.source))],
      ['Nhập lúc', new Date(ds.createdAt).toLocaleString('vi-VN')],
    ].map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('');

    destroyCharts('ov-');
    const numeric = st.columns.filter((c) => c.type === 'numeric' && c.hist);
    const cats = st.columns.filter((c) => c.type === 'category' && c.distinct >= 2 && c.distinct <= 12).slice(0, 4);
    const primary = numeric.find((c) => c.name === st.primary) || numeric[0];
    const others = numeric.filter((c) => c !== primary && c.distinct > 2).slice(0, 3);
    const box = $('#charts');
    box.innerHTML = '';

    if (primary) {
      const opts = numeric.map((c) => `<option value="${esc(c.name)}"${c === primary ? ' selected' : ''}>${esc(c.name)}</option>`).join('');
      box.insertAdjacentHTML('beforeend', `
        <article class="chart big">
          <div class="chart-head"><h4>Phân bố của <select id="primSel" aria-label="Chọn cột số">${opts}</select></h4><span id="primStat"></span></div>
          <div class="canvas-wrap"><canvas id="ov-primary" role="img" aria-label="Phân bố cột số chính"></canvas></div>
          <div id="primPass"></div>
        </article>`);
      const show = (name) => {
        const col = numeric.find((c) => c.name === name);
        $('#primStat').textContent = `TB ${nf(col.mean, 2)}, trung vị ${nf(col.median, 1)}, từ ${nf(col.min, 1)} đến ${nf(col.max, 1)}`;
        $('#primPass').innerHTML = passInfo(col);
        draw('ov-primary', histConfig(col));
      };
      show(primary.name);
      $('#primSel').addEventListener('change', (e) => show(e.target.value));
    }
    others.forEach((c, i) => box.insertAdjacentHTML('beforeend', `
      <article class="chart">
        <div class="chart-head"><h4>${esc(c.name)}</h4><span>TB ${nf(c.mean, 2)}</span></div>
        <div class="canvas-wrap"><canvas id="ov-n${i}" role="img" aria-label="Phân bố ${esc(c.name)}"></canvas></div>
      </article>`));
    others.forEach((c, i) => draw(`ov-n${i}`, histConfig(c)));
    cats.forEach((c, i) => box.insertAdjacentHTML('beforeend', `
      <article class="chart">
        <div class="chart-head"><h4>${esc(c.name)}</h4><span>${c.distinct} giá trị</span></div>
        <div class="canvas-wrap"><canvas id="ov-c${i}" role="img" aria-label="Số dòng theo ${esc(c.name)}"></canvas></div>
      </article>`));
    cats.forEach((c, i) => draw(`ov-c${i}`, catConfig(c)));
    if (!primary && !cats.length) box.innerHTML = '<p class="empty">Dataset này không có cột nào phù hợp để vẽ biểu đồ tự động.</p>';
  }

  // ---------- So sánh và tương quan ----------
  const opt = (v, label, sel) => `<option value="${esc(v)}"${sel ? ' selected' : ''}>${esc(label)}</option>`;

  function renderExplore() {
    const st = state.stats;
    const cats = st.columns.filter((c) => c.type === 'category' && c.distinct >= 2 && c.distinct <= 30);
    const nums = st.columns.filter((c) => c.type === 'numeric');
    const exp = $('#explore');
    exp.hidden = !(cats.length || nums.length > 1);

    $('#gbBy').innerHTML = cats.map((c) => opt(c.name, c.name, c.name === 'school')).join('');
    $('#gbMetric').innerHTML = opt('', '(đếm số dòng)') + nums.map((c) => opt(c.name, c.name, c.name === st.primary)).join('');
    $('#scX').innerHTML = nums.map((c) => opt(c.name, c.name, c.name === (nums.find((n) => n.name === 'G1') || nums[0]).name)).join('');
    $('#scY').innerHTML = nums.map((c) => opt(c.name, c.name, c.name === st.primary)).join('');
    destroyCharts('cGroup'); destroyCharts('cScatter');
    if (cats.length) loadGroup(); else if (state.charts.cGroup) state.charts.cGroup.destroy();
    if (nums.length > 1) loadScatter();
    renderCorrelation();
  }

  async function loadGroup() {
    const by = $('#gbBy').value, metric = $('#gbMetric').value;
    if (!by) return;
    const r = await api(`/api/datasets/${state.id}/groupby?by=${encodeURIComponent(by)}&metric=${encodeURIComponent(metric)}`);
    const useMean = !!r.metric;
    draw('cGroup', {
      type: 'bar',
      data: { labels: r.groups.map((g) => g.key), datasets: [{
        data: r.groups.map((g) => (useMean ? g.mean : g.count)), backgroundColor: C.ink, borderRadius: 2, maxBarThickness: 44 }] },
      options: { ...baseOpts,
        plugins: { legend: { display: false }, tooltip: { callbacks: {
          label: (i) => `${useMean ? 'Trung bình ' + r.metric : 'Số dòng'}: ${nf(i.raw, 2)} (n = ${r.groups[i.dataIndex].count})` } } },
        scales: { x: { grid: { display: false }, title: { display: true, text: by } },
          y: { beginAtZero: true, grid: { color: C.grid }, title: { display: true, text: useMean ? `Trung bình ${r.metric}` : 'Số dòng' } } } },
    });
  }

  async function loadScatter() {
    const x = $('#scX').value, y = $('#scY').value;
    if (!x || !y) return;
    const r = await api(`/api/datasets/${state.id}/scatter?x=${encodeURIComponent(x)}&y=${encodeURIComponent(y)}`);
    draw('cScatter', {
      type: 'bubble',
      data: { datasets: [{ data: r.points.map((p) => ({ x: p.x, y: p.y, r: Math.min(3 + Math.sqrt(p.n) * 2.2, 20), n: p.n })),
        backgroundColor: 'rgba(47,95,208,.4)', borderColor: C.pencil, borderWidth: 1 }] },
      options: { ...baseOpts,
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (i) => `${x} = ${i.raw.x}, ${y} = ${i.raw.y}: ${i.raw.n} dòng` } } },
        scales: { x: { grid: { color: C.grid }, title: { display: true, text: x } }, y: { grid: { color: C.grid }, title: { display: true, text: y } } } },
    });
    $('#scNote').textContent = r.r === null ? '' : `Hệ số tương quan r = ${nf(r.r, 2)} trên ${nf(r.total, 0)} dòng. Bong bóng càng to càng nhiều dòng trùng toạ độ.`;
  }

  function renderCorrelation() {
    const c = state.stats.correlation;
    $('#corrPanel').hidden = !c;
    if (!c) return;
    $('#corrTitle').textContent = `Ma trận tương quan (các cột liên quan nhất tới ${c.target})`;
    const cell = (r) => {
      if (r === null) return '<td style="background:#f1f4f9" title="Không đủ dữ liệu">–</td>';
      const a = Math.min(Math.abs(r), 1);
      const bg = r >= 0 ? `rgba(47,95,208,${a})` : `rgba(217,72,74,${a})`;
      return `<td style="background:${bg};color:${a > 0.5 ? '#fff' : C.ink}">${nf(r, 2)}</td>`;
    };
    $('#corr').innerHTML = `<thead><tr><th></th>${c.cols.map((n) => `<th scope="col">${esc(n)}</th>`).join('')}</tr></thead><tbody>` +
      c.cols.map((n, i) => `<tr><th scope="row">${esc(n)}</th>${c.matrix[i].map(cell).join('')}</tr>`).join('') + '</tbody>';
  }

  // ---------- Hồ sơ theo vai trò ----------
  function setupRecordControls() {
    const school = state.stats.columns.find((c) => c.name === 'school' && c.top);
    const wrap = $('#schoolSel').closest('label');
    wrap.hidden = !school;
    state.schools = school ? school.top.map((t) => t.value) : [];
    syncSchoolOptions();
    $('#legend').innerHTML =
      Object.entries(GROUP_VN).map(([g, n]) => `<span><i style="background:${GROUP_COLOR[g]}"></i>Nhóm ${n}</span>`).join('') +
      '<span><i class="lk"></i>Bị che với vai trò này</span>';
    renderRules();
  }

  function syncSchoolOptions() {
    const sel = $('#schoolSel');
    const list = state.role === 'admin' ? ['*', ...state.schools] : state.schools;
    if (!list.includes(state.school)) state.school = list[0] ?? '*';
    sel.innerHTML = list.map((s) => opt(s, s === '*' ? 'Tất cả trường' : `Trường ${s}`, s === state.school)).join('');
    $('#trainedWrap').hidden = state.role !== 'teacher';
  }

  async function renderRules() {
    if (!state.policies.length) {
      try { state.policies = (await api('/api/policies')).policies; } catch { state.policies = []; }
    }
    const items = state.policies.map((p) => {
      const g = p.groups.map((x) => GROUP_VN[x]).join(', ');
      const cond = p.cond ? `, khi ${COND_VN[p.cond] || p.cond}` : '';
      return `<li class="${p.role === state.role ? 'me' : ''}">${ROLE_VN[p.role] || esc(p.role)} xem nhóm ${g}${cond}</li>`;
    });
    $('#rules').innerHTML = '<li>Mặc định từ chối. Chỉ trường nào có luật cho phép mới được xem, và chỉ trong trường học của vai trò đó.</li>' + items.join('');
  }

  async function loadRecords() {
    const p = new URLSearchParams({ role: state.role, school: state.school, trained: String(state.trained), page: state.page, limit: 15, q: state.q });
    let r;
    try { r = await api(`/api/datasets/${state.id}/records?${p}`); }
    catch (e) { $('#sumline').textContent = e.message; return; }
    state.page = r.page;

    const { visibleCells: v, lockedCells: l } = r.summary;
    const pct = v + l ? Math.round((l / (v + l)) * 100) : 0;
    const who = ROLE_VN[state.role];
    let line;
    if (!r.total) line = state.q ? 'Không có ô nào được phép xem khớp với từ khoá.' : `${who} không có hồ sơ nào trong phạm vi này.`;
    else if (!v) line = `${who}${state.role === 'teacher' && !state.trained ? ' chưa tập huấn nên' : ''} chưa xem được ô nào. ${r.total} hồ sơ đều bị che hoàn toàn.`;
    else line = `${nf(r.total, 0)} hồ sơ trong phạm vi của ${who}. ${pct}% số ô bị che.`;
    $('#sumline').textContent = line;

    renderGrid(r);
    $('#pageInfo').textContent = `Trang ${r.page} trên ${r.pages}`;
    $('#prev').disabled = r.page <= 1;
    $('#next').disabled = r.page >= r.pages;
    loadAudit();
  }

  function renderGrid(r) {
    const head = `<thead><tr><th class="idx" scope="col">#</th>${r.columns.map((c) =>
      `<th class="g-${c.group}" scope="col" title="Nhóm ${GROUP_VN[c.group]}">${esc(c.name)}</th>`).join('')}</tr></thead>`;
    const body = r.rows.map((row) => `<tr><td class="idx">${row.rid}</td>${r.columns.map((c) => {
      if (!(c.name in row.data)) return '<td class="locked" title="Vai trò này không được xem ô này"><span class="sr">bị che</span></td>';
      const v = row.data[c.name];
      if (v === null) return '<td class="nul">–</td>';
      return `<td class="${typeof v === 'number' ? 'n' : ''}">${esc(v)}</td>`;
    }).join('')}</tr>`).join('');
    $('#grid').innerHTML = head + `<tbody>${body}</tbody>`;
  }

  async function loadAudit() {
    let list;
    try { list = await api('/api/audit'); } catch { return; }
    const t = (d) => new Date(d).toLocaleString('vi-VN', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    $('#audit').innerHTML = '<thead><tr><th>Thời gian</th><th>Vai trò</th><th>Trường</th><th>Số dòng</th><th>Ô bị che</th><th>Dataset</th></tr></thead><tbody>' +
      list.map((a) => {
        const tot = a.visibleCells + a.lockedCells;
        const pct = tot ? Math.round((a.lockedCells / tot) * 100) : 0;
        const role = (ROLE_VN[a.role] || a.role) + (a.role === 'teacher' ? (a.trained ? ' (đã tập huấn)' : ' (chưa tập huấn)') : '');
        return `<tr><td>${t(a.ts)}</td><td>${esc(role)}</td><td>${esc(a.school === '*' ? 'Tất cả' : a.school || '–')}</td>` +
          `<td>${nf(a.rows, 0)}</td><td><span class="bar"><b style="width:${pct}%"></b></span>${pct}%</td><td>${esc(a.dataset)}</td></tr>`;
      }).join('') + '</tbody>';
  }

  function setupRecordEvents() {
    document.querySelectorAll('input[name="role"]').forEach((r) => r.addEventListener('change', () => {
      state.role = r.value; state.page = 1; syncSchoolOptions(); renderRules(); loadRecords();
    }));
    $('#schoolSel').addEventListener('change', (e) => { state.school = e.target.value; state.page = 1; loadRecords(); });
    $('#trained').addEventListener('change', (e) => { state.trained = e.target.checked; state.page = 1; loadRecords(); });
    let timer;
    $('#q').addEventListener('input', (e) => { clearTimeout(timer); timer = setTimeout(() => { state.q = e.target.value; state.page = 1; loadRecords(); }, 250); });
    $('#prev').addEventListener('click', () => { state.page--; loadRecords(); });
    $('#next').addEventListener('click', () => { state.page++; loadRecords(); });
  }


  // ---------- Sổ tay (notebook .ipynb) ----------
  // Markdown tối giản: escape trước rồi mới thêm thẻ, nên nội dung từ notebook không chèn được HTML.
  function fmtInline(t) {
    return t
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*\w])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  }
  const inline = (t) => t.split('`').map((seg, i) => (i % 2 ? `<code>${esc(seg)}</code>` : fmtInline(esc(seg)))).join('');
  const cells = (ln) => ln.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());

  function md(src, toc, ctr) {
    const L = src.split('\n'), out = [];
    let para = [], i = 0;
    const flush = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
    while (i < L.length) {
      const ln = L[i];
      let m;
      if (!ln.trim()) { flush(); i++; continue; }
      if ((m = /^(#{1,4})\s+(.*)$/.exec(ln))) {
        flush();
        const lv = m[1].length;
        if (lv === 1) out.push(`<h3 class="nb-h1">${inline(m[2])}</h3>`);
        else if (lv === 2) { const id = `nb-h-${ctr.n++}`; toc.push({ id, text: m[2] }); out.push(`<h3 class="nb-h2" id="${id}">${inline(m[2])}</h3>`); }
        else out.push(`<h${lv + 1}>${inline(m[2])}</h${lv + 1}>`);
        i++; continue;
      }
      if (ln.trim().startsWith('|') && i + 1 < L.length && /^\s*\|?\s*:?-{2,}/.test(L[i + 1])) {
        flush();
        const head = cells(ln); i += 2;
        const rows = [];
        while (i < L.length && L[i].trim().startsWith('|')) { rows.push(cells(L[i])); i++; }
        out.push(`<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>` +
          rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`).join('') + '</tbody></table>');
        continue;
      }
      if (/^\s*([-*]|\d+\.)\s+/.test(ln)) {
        flush();
        const ordered = /^\s*\d+\./.test(ln), items = [];
        while (i < L.length && /^\s*([-*]|\d+\.)\s+/.test(L[i])) { items.push(L[i].replace(/^\s*([-*]|\d+\.)\s+/, '')); i++; }
        const tag = ordered ? 'ol' : 'ul';
        out.push(`<${tag}>${items.map((x) => `<li>${inline(x)}</li>`).join('')}</${tag}>`);
        continue;
      }
      para.push(ln.trim()); i++;
    }
    flush();
    return out.join('');
  }

  function outputHtml(o) {
    if (o.kind === 'stream' || o.kind === 'text') return `<pre class="nb-out">${esc(o.text)}</pre>`;
    if (o.kind === 'error') return `<pre class="nb-out err">${esc(o.text)}</pre>`;
    if (o.kind === 'image') return `<img class="nb-img" alt="Biểu đồ do notebook vẽ" src="data:image/png;base64,${o.png.replace(/[^A-Za-z0-9+/=]/g, '')}">`;
    if (o.kind === 'table') {
      const note = o.total > o.rows.length ? `<p class="nb-note">Hiển thị ${o.rows.length} trên ${nf(o.total, 0)} dòng.</p>` : '';
      return `<div class="nb-tablewrap" tabindex="0"><table class="nb-table"><thead><tr>${o.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>` +
        o.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('') + `</tbody></table></div>${note}`;
    }
    return '';
  }

  function renderNotebook(res) {
    const toc = [], ctr = { n: 0 };
    $('#nbBody').innerHTML = res.cells.map((c) => {
      if (c.type === 'markdown') return `<div class="nb-md">${md(c.source, toc, ctr)}</div>`;
      const lines = c.source.split('\n').length;
      return `<div class="nb-cell"><div class="nb-num">[${c.n}]</div><div class="nb-main">` +
        `<details class="nb-code"><summary>Mã nguồn, ${lines} dòng${c.ms != null ? `, ${c.ms} ms` : ''}</summary><pre><code>${esc(c.source)}</code></pre></details>` +
        `${(c.outputs || []).map(outputHtml).join('')}</div></div>`;
    }).join('');
    $('#nbToc').innerHTML = toc.map((t) => `<a href="#${t.id}">${esc(t.text.split(' — ')[0])}</a>`).join('');
    const m = res.meta;
    $('#nbMeta').innerHTML = `Nguồn: <b>${esc(m.label || 'không rõ')}</b>. ${m.rows != null ? `${nf(m.rows, 0)} dòng dữ liệu. ` : ''}` +
      `Chạy trong ${m.duration} giây, ${new Date(m.finishedAt).toLocaleString('vi-VN')}.${m.ok ? '' : ' <b>Có lỗi khi chạy, xem cell cuối.</b>'}`;
    $('#nbToggle').textContent = 'Hiện toàn bộ mã';
  }

  const nbMsg = (t, kind = '') => { const e = $('#nbMsg'); e.textContent = t; e.className = `msg ${kind}`; };

  async function showNotebook() {
    const info = state.nb.info;
    const jobId = info && info.latest ? info.latest.jobId : null;
    const key = jobId || 'example';
    $('#nbDlRun').href = `/api/notebook/download${jobId ? `?jobId=${jobId}` : ''}`;
    if (state.nb.shown === key) return;
    try {
      const res = await api(`/api/notebook/result${jobId ? `?jobId=${jobId}` : ''}`);
      renderNotebook(res);
      state.nb.shown = key;
    } catch (e) {
      $('#nbBody').innerHTML = `<p class="empty">${esc(e.message)}</p>`;
    }
  }

  function updateRunUi() {
    const info = state.nb.info; if (!info) return;
    const busy = !!info.running;
    let why = '';
    if (!state.id) why = 'Nhập hoặc chọn một dataset để chạy notebook trên dữ liệu của bạn. Đang xem kết quả mẫu.';
    else if (!info.python.ok) why = `${info.python.error}. Đang xem kết quả mẫu.`;
    else if (info.eligible && !info.eligible.ok) why = `Dataset này thiếu cột ${info.eligible.missing.join(', ')} nên chưa chạy được notebook (notebook viết cho dữ liệu học sinh kiểu UCI). Đang xem kết quả mẫu.`;
    $('#nbRun').disabled = busy || !!why;
    $('#nbRun').textContent = busy ? 'Đang chạy…' : 'Chạy notebook với dataset này';
    if (!busy && why) nbMsg(why, 'hint');
    else if (!busy && $('#nbMsg').classList.contains('hint')) nbMsg(''); // chỉ xoá gợi ý, không xoá thông báo kết quả
  }

  async function loadNotebookInfo() {
    try {
      state.nb.info = await api(`/api/notebook/info${state.id ? `?datasetId=${state.id}` : ''}`);
    } catch (e) { nbMsg(e.message, 'err'); return; }
    updateRunUi();
    if (state.nb.visible) await showNotebook();
    if (state.nb.info.running) pollJob(state.nb.info.running.jobId);
  }

  function pollJob(jobId) {
    clearInterval(state.nb.poll);
    const tick = async () => {
      let j;
      try { j = await api(`/api/notebook/jobs/${jobId}`); } catch (e) { clearInterval(state.nb.poll); nbMsg(e.message, 'err'); return; }
      if (j.status === 'running') { nbMsg(`Đang chạy notebook trên dữ liệu trong MongoDB… ${Math.round(j.seconds)} giây`); $('#nbRun').disabled = true; return; }
      clearInterval(state.nb.poll);
      if (j.status === 'done') { nbMsg('Đã chạy xong, kết quả bên dưới.', 'ok'); state.nb.shown = null; await loadNotebookInfo(); await showNotebook(); }
      else { nbMsg(`Notebook chạy lỗi: ${j.message}`, 'err'); await loadNotebookInfo(); }
    };
    tick(); state.nb.poll = setInterval(tick, 1500);
  }

  function setupNotebook() {
    $('#nbRun').addEventListener('click', async () => {
      $('#nbRun').disabled = true; nbMsg('Đang khởi động Python…');
      try {
        const j = await api('/api/notebook/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ datasetId: state.id }) });
        pollJob(j.jobId);
      } catch (e) { nbMsg(e.message, 'err'); updateRunUi(); }
    });
    $('#nbToggle').addEventListener('click', () => {
      const ds = [...document.querySelectorAll('#nbBody details')];
      const open = ds.some((d) => !d.open);
      ds.forEach((d) => { d.open = open; });
      $('#nbToggle').textContent = open ? 'Ẩn toàn bộ mã' : 'Hiện toàn bộ mã';
    });
    if ('IntersectionObserver' in window) {
      new IntersectionObserver((es) => {
        if (es.some((e) => e.isIntersecting) && !state.nb.visible) { state.nb.visible = true; showNotebook(); }
      }, { rootMargin: '600px 0px' }).observe($('#notebook'));
    } else { state.nb.visible = true; }
  }

  // ---------- Khởi động ----------
  async function init() {
    const pick = setupTabs();
    setupImport(pick);
    setupRecordEvents();
    setupNotebook();
    ['gbBy', 'gbMetric'].forEach((id) => $(`#${id}`).addEventListener('change', loadGroup));
    ['scX', 'scY'].forEach((id) => $(`#${id}`).addEventListener('change', loadScatter));
    $('#dsSelect').addEventListener('change', (e) => openDataset(e.target.value).catch((err) => msg(err.message, 'err')));
    $('#delBtn').addEventListener('click', async () => {
      const d = state.datasets.find((x) => x.id === state.id);
      if (!d || !confirm(`Xoá dataset "${d.name}" khỏi MongoDB?`)) return;
      try { await api(`/api/datasets/${state.id}`, { method: 'DELETE' }); msg(`Đã xoá "${d.name}".`, 'ok'); await refreshDatasets(); }
      catch (err) { msg(err.message, 'err'); }
    });

    const pill = $('#mongoPill');
    try {
      const h = await api('/api/health');
      pill.textContent = `MongoDB đã kết nối (${h.db})`; pill.className = 'pill ok';
    } catch { pill.textContent = 'MongoDB chưa kết nối'; pill.className = 'pill bad'; }

    try { await refreshDatasets(); } catch (err) { msg(err.message, 'err'); $('#empty').hidden = false; }
  }
  init();
})();
