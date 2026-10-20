import * as THREE from '/static/three.module.min.js';

const $ = (id) => document.getElementById(id);
const TOKEN = window.__SENTINEL__?.token || '';
const VERSION = window.__SENTINEL__?.version || '';
const ACCENTS = {
  ready: '#34d399',
  caution: '#22d3ee',
  high_caution: '#f59e0b',
  do_not_start: '#f43f5e',
  blocked_region: '#f43f5e',
  blocked_account: '#f43f5e',
  blocked_service: '#f59e0b',
  blocked_clock: '#f59e0b',
  unknown: '#6b8299',
};
const AXES = [
  ['ip', '出口信誉'],
  ['stability', '稳定性'],
  ['identity', '身份一致性'],
  ['client', '客户端'],
  ['account', '账号'],
  ['behavior', '行为'],
];
const SHORT_VERDICT = {
  '不可发起对话': '不可发起',
  '可以，但建议先处理': '可发起*',
  '谨慎发起': '谨慎',
  '不建议发起': '不建议',
  '暂不可发起对话': '暂不可',
  '先校准系统时间': '需校时',
  '无法判断': '未知',
};
const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const GAUGE_LEN = 2 * Math.PI * 82;

let accent = ACCENTS.caution;
let currentReport = null;
let hasReport = false;
let sceneApi = null;
let stages = [];
let streaming = false;

// ---------------------------------------------------------------- utilities
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
};
const setText = (id, value) => {
  const node = $(id);
  if (node) node.textContent = value;
};
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, REDUCED ? 0 : ms));

function chip(label, value) {
  const node = el('span', 'chip');
  node.append(el('span', '', label + ' '));
  node.append(el('b', '', value));
  return node;
}

function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

// Deterministic pseudo-random so blips look organic but reproducible.
function seeded(seed) {
  let state = seed % 2147483647;
  if (state <= 0) state += 2147483646;
  return () => {
    state = (state * 16807) % 2147483647;
    return (state - 1) / 2147483646;
  };
}

async function api(path, options = {}) {
  const headers = { Accept: 'application/json', ...(options.headers || {}) };
  if ((options.method || 'GET').toUpperCase() === 'POST') headers['X-Sentinel-Token'] = TOKEN;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

// ------------------------------------------------------------------- scene
function initScene() {
  const canvas = $('scene');
  if (!canvas) return;
  try {
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(window.innerWidth, window.innerHeight, false);
    renderer.setClearColor(0x000000, 0);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 120);
    camera.position.set(0, 0, 7.2);

    const group = new THREE.Group();
    scene.add(group);

    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(2.25, 44, 28),
      new THREE.MeshBasicMaterial({ color: accent, wireframe: true, transparent: true, opacity: 0.11 })
    );
    group.add(sphere);

    const rings = [];
    for (let i = 0; i < 3; i += 1) {
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(2.66 + i * 0.23, 0.006, 6, 170),
        new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.32 - i * 0.07 })
      );
      ring.rotation.x = Math.PI / 2 + i * 0.33;
      ring.rotation.y = i * 0.55;
      group.add(ring);
      rings.push(ring);
    }

    // Orbiting satellite ring: fast, visible motion for the camera.
    const orbit = new THREE.Group();
    orbit.rotation.x = Math.PI / 2.6;
    const satellites = [];
    for (let i = 0; i < 5; i += 1) {
      const dot = new THREE.Mesh(
        new THREE.SphereGeometry(0.032, 8, 8),
        new THREE.MeshBasicMaterial({ color: accent, transparent: true, opacity: 0.95 })
      );
      const radius = 2.95 + (i % 2) * 0.22;
      dot.position.set(Math.cos((i / 5) * Math.PI * 2) * radius, 0, Math.sin((i / 5) * Math.PI * 2) * radius);
      orbit.add(dot);
      satellites.push({ mesh: dot, angle: (i / 5) * Math.PI * 2, radius });
    }
    group.add(orbit);

    const nodeCount = 80;
    const nodePos = new Float32Array(nodeCount * 3);
    const points = [];
    const rand = seeded(20261020);
    for (let i = 0; i < nodeCount; i += 1) {
      const theta = rand() * Math.PI * 2;
      const phi = Math.acos(2 * rand() - 1);
      const r = 2.25;
      const x = r * Math.sin(phi) * Math.cos(theta);
      const y = r * Math.cos(phi);
      const z = r * Math.sin(phi) * Math.sin(theta);
      nodePos[i * 3] = x;
      nodePos[i * 3 + 1] = y;
      nodePos[i * 3 + 2] = z;
      points.push(new THREE.Vector3(x, y, z));
    }
    const nodeGeo = new THREE.BufferGeometry();
    nodeGeo.setAttribute('position', new THREE.BufferAttribute(nodePos, 3));
    const nodes = new THREE.Points(
      nodeGeo,
      new THREE.PointsMaterial({ color: accent, size: 0.058, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false })
    );
    group.add(nodes);

    const lineMaterials = [];
    for (let i = 0; i < 16; i += 1) {
      const a = points[Math.floor(rand() * points.length)];
      const b = points[Math.floor(rand() * points.length)];
      if (!a || !b) continue;
      const mid = a.clone().add(b).multiplyScalar(0.5).normalize().multiplyScalar(3.1);
      const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
      const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(36));
      const material = new THREE.LineBasicMaterial({ color: accent, transparent: true, opacity: 0.15 });
      group.add(new THREE.Line(geometry, material));
      lineMaterials.push(material);
    }

    const starCount = 1600;
    const starPos = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i += 1) {
      const r = 3.6 + rand() * 4.8;
      const theta = rand() * Math.PI * 2;
      const phi = Math.acos(2 * rand() - 1);
      starPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      starPos[i * 3 + 1] = r * Math.cos(phi);
      starPos[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    }
    const starGeo = new THREE.BufferGeometry();
    starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    const stars = new THREE.Points(
      starGeo,
      new THREE.PointsMaterial({ color: accent, size: 0.018, transparent: true, opacity: 0.64, blending: THREE.AdditiveBlending, depthWrite: false })
    );
    scene.add(stars);

    let mouseX = 0;
    let mouseY = 0;
    let t = 0;
    let speed = 1;
    let pulseEnergy = 0;

    const resize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight, false);
    };
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', (event) => {
      mouseX = (event.clientX / window.innerWidth - 0.5) * 2;
      mouseY = (event.clientY / window.innerHeight - 0.5) * 2;
    });

    const animate = () => {
      requestAnimationFrame(animate);
      const scanningNow = document.body.classList.contains('scanning');
      t += 0.0035;
      speed += ((scanningNow ? 3.6 : 1) - speed) * 0.04;
      pulseEnergy *= 0.94;

      group.rotation.y += 0.0026 * speed;
      group.rotation.x = Math.sin(t * 0.6) * 0.07;
      orbit.rotation.z += 0.012 * speed;
      for (const item of satellites) {
        item.angle += 0.008 * speed;
        item.mesh.position.set(Math.cos(item.angle) * item.radius, 0, Math.sin(item.angle) * item.radius);
      }
      stars.rotation.y -= 0.0007 * (1 + pulseEnergy);
      stars.rotation.x += 0.00015;

      const targetScale = 1 + pulseEnergy * 0.06;
      group.scale.setScalar(group.scale.x + (targetScale - group.scale.x) * 0.08);
      sphere.material.opacity = 0.11 + pulseEnergy * 0.12;

      camera.position.x += (mouseX * 0.38 - camera.position.x) * 0.02;
      camera.position.y += (-mouseY * 0.26 - camera.position.y) * 0.02;
      camera.lookAt(0, 0, 0);
      renderer.render(scene, camera);
    };

    const setSceneAccent = (color) => {
      const threeColor = new THREE.Color(color);
      sphere.material.color.copy(threeColor);
      nodes.material.color.copy(threeColor);
      stars.material.color.copy(threeColor);
      rings.forEach((ring) => ring.material.color.copy(threeColor));
      lineMaterials.forEach((material) => material.color.copy(threeColor));
      satellites.forEach((item) => item.mesh.material.color.copy(threeColor));
    };

    if (REDUCED) {
      renderer.render(scene, camera);
    } else {
      animate();
    }
    sceneApi = { setAccent: setSceneAccent, pulse: (energy = 1) => { pulseEnergy = energy; } };
  } catch (error) {
    canvas.style.display = 'none';
  }
}

function applyAccent(color) {
  accent = color;
  document.documentElement.style.setProperty('--accent', color);
  document.documentElement.style.setProperty('--accent-soft', `color-mix(in srgb, ${color} 14%, transparent)`);
  if (sceneApi) sceneApi.setAccent(color);
}

// -------------------------------------------------------------------- gauge
function buildGaugeTicks() {
  const group = $('gauge-ticks');
  if (!group || group.childElementCount) return;
  for (let i = 0; i < 60; i += 1) {
    const angle = (i / 60) * Math.PI * 2;
    const major = i % 5 === 0;
    const r1 = major ? 70 : 74;
    const r2 = 78;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', String(110 + Math.cos(angle) * r1));
    line.setAttribute('y1', String(110 + Math.sin(angle) * r1));
    line.setAttribute('x2', String(110 + Math.cos(angle) * r2));
    line.setAttribute('y2', String(110 + Math.sin(angle) * r2));
    line.setAttribute('opacity', major ? '0.55' : '0.22');
    group.append(line);
  }
}

const gauge = {
  reset() {
    const arc = $('gauge-arc');
    if (arc) arc.style.strokeDashoffset = String(GAUGE_LEN);
    const head = $('gauge-head');
    if (head) head.classList.remove('on');
    setText('score', '—');
    const node = $('gauge');
    node?.classList.remove('gated');
  },
  // score == null means a hard gate short-circuited the risk bands.
  async animateTo(score, duration = 1100) {
    const arc = $('gauge-arc');
    const head = $('gauge-head');
    const scoreNode = $('score');
    const marker = $('band-marker');
    const gaugeNode = $('gauge');
    const gated = score == null;
    gaugeNode?.classList.toggle('gated', gated);
    const target = score == null ? 100 : clamp(score, 0, 100);
    const offset = GAUGE_LEN * (1 - target / 100);
    if (arc) {
      arc.style.transitionDuration = `${duration / 1000}s`;
      arc.style.strokeDashoffset = String(offset);
    }
    if (marker) marker.style.left = `${gated ? 100 : target}%`;
    if (head) {
      const angle = (target / 100) * Math.PI * 2 - Math.PI / 2;
      head.setAttribute('cx', String(110 + Math.cos(angle) * 82));
      head.setAttribute('cy', String(110 + Math.sin(angle) * 82));
      window.setTimeout(() => head.classList.add('on'), REDUCED ? 0 : duration * 0.75);
    }
    if (!scoreNode) return;
    if (score == null) {
      scoreNode.textContent = 'GATE';
      return;
    }
    if (REDUCED) {
      scoreNode.textContent = String(Math.round(target));
      return;
    }
    const started = performance.now();
    await new Promise((resolve) => {
      const step = (now) => {
        const progress = clamp((now - started) / duration, 0, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        scoreNode.textContent = String(Math.round(target * eased));
        if (progress < 1) requestAnimationFrame(step);
        else resolve();
      };
      requestAnimationFrame(step);
    });
  },
};

// ------------------------------------------------------------------ render
function renderChips(report) {
  const target = $('chips');
  target.replaceChildren();
  const verdict = report.verdict || {};
  const env = report.environment || {};
  const items = [
    ['SAFETY', report.score == null ? '—' : `${Math.round(report.score)}/100`],
    ['COVERAGE', `${Math.round((report.coverage || 0) * 100)}%`],
    ['CONFIDENCE', String(report.confidence || '—').toUpperCase()],
    ['GATE', verdict.gate || 'NONE'],
    ['REGION', env.country_code || '—'],
  ];
  if (!report.account) items.push(['MODE', 'REFERENCE']);
  items.forEach(([label, value], index) => {
    const node = chip(label, value);
    node.style.animationDelay = `${index * 55}ms`;
    target.append(node);
  });
}

function renderStats(report) {
  const target = $('stats');
  target.replaceChildren();
  const env = report.environment || {};
  const region = report.observations?.['official.region_gate']?.value || {};
  const gate = region.available === true ? 'OK' : region.available === false ? 'BLOCKED' : 'UNKNOWN';
  const account = report.account?.state || 'UNVERIFIED';
  const stats = [
    { k: '出口', v: env.ip || '—', h: `${env.country_code || '?'} · ${env.asn || '—'}` },
    { k: '地区闸门', v: gate, h: report.regions?.effective || region.error_code || '—' },
    { k: '账号', v: String(account).toUpperCase(), h: report.account ? (report.account.plan || report.account.organization || '已探测') : '参考模式' },
    { k: '覆盖率', v: `${Math.round((report.coverage || 0) * 100)}%`, h: `置信度 ${report.confidence || '—'}` },
  ];
  stats.forEach((item, index) => {
    const node = el('div', 'stat');
    node.style.animationDelay = `${index * 70}ms`;
    node.append(el('div', 'k', item.k), el('div', 'v', item.v), el('div', 'h', item.h));
    target.append(node);
  });
}

function renderCategories(report) {
  const target = $('categories');
  target.replaceChildren();
  const byKey = new Map((report.categories || []).map((item) => [item.category, item]));
  AXES.forEach(([key, label]) => {
    const item = byKey.get(key);
    const score = item && item.score != null ? item.score : null;
    const node = el('div', 'cat');
    const head = el('div', 'cat-head');
    const value = el('b', '', score == null ? '—' : String(Math.round(score)));
    head.append(el('span', '', label), value);
    const bar = el('div', 'bar');
    const fill = el('i');
    // Colour each bar by its own band, not by the global accent -- otherwise a
    // perfectly clean axis renders red just because the verdict is bad.
    if (score != null) {
      const band = score >= 86 ? 'safe' : score >= 66 ? 'med' : score >= 41 ? 'high' : 'crit';
      fill.classList.add(`band-fill-${band}`);
    }
    bar.append(fill);
    const meta = el('div', 'cat-meta', `权重 ${item?.weight ?? '—'} · 覆盖 ${Math.round((item?.coverage || 0) * 100)}%`);
    node.append(head, bar, meta);
    // No data for this axis: make the empty track read as "not measured", not "0".
    if (score == null) {
      node.classList.add('no-data');
      bar.setAttribute('aria-hidden', 'true');
      fill.style.display = 'none';
    }
    target.append(node);
    const targetWidth = `${score == null ? 0 : clamp(score, 0, 100)}%`;
    requestAnimationFrame(() => {
      window.setTimeout(() => { fill.style.width = targetWidth; }, 60);
    });
    if (score != null && !REDUCED) {
      const from = performance.now();
      const tick = (now) => {
        const p = clamp((now - from) / 800, 0, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        value.textContent = String(Math.round(score * eased));
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }
  });
}

function findingNode(finding) {
  const node = el('article', 'finding');
  node.dataset.status = finding.status || 'unknown';
  const statusLabel = finding.is_gate ? 'GATE' : finding.status === 'high' ? '高危' : finding.status === 'warn' ? '提醒' : '未知';
  const sev = el('div', 'sev', statusLabel);
  const body = el('div');
  body.append(el('h3', '', finding.title || finding.rule_id || '未命名'));
  body.append(el('p', '', finding.evidence || ''));
  if (finding.fix) body.append(el('p', 'fix', finding.fix));
  const tags = el('div', 'tags');
  for (const value of [finding.rule_id, finding.visibility, finding.confidence ? `置信 ${finding.confidence}` : null]) {
    if (value) tags.append(el('span', 'tag', value));
  }
  for (const source of (finding.sources || []).slice(0, 2)) {
    if (!source?.name) continue;
    const tag = el('span', 'tag');
    if (source.url && /^https?:/i.test(source.url)) {
      const anchor = el('a', '', source.name);
      anchor.href = source.url;
      anchor.target = '_blank';
      anchor.rel = 'noreferrer noopener';
      tag.append(anchor);
    } else {
      tag.textContent = source.name;
    }
    tags.append(tag);
  }
  body.append(tags);
  const points = el('div', 'pts', finding.is_gate ? '—' : `${Math.round(finding.points || 0)}/${Math.round(finding.max_points || 0)}`);
  node.append(sev, body, points);
  return node;
}

function renderFindings(report) {
  const target = $('findings');
  target.replaceChildren();
  const all = (report.findings || []).filter((item) => item.status !== 'ok');
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...all].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || (b.points || 0) - (a.points || 0));
  setText('finding-count', String(sorted.length));
  if (!sorted.length) {
    target.append(el('div', 'empty', '未发现需要展示的问题。'));
    return;
  }
  sorted.forEach((item, index) => {
    const node = findingNode(item);
    node.style.animationDelay = `${Math.min(index * 55, 600)}ms`;
    target.append(node);
  });
  applyFilter(document.querySelector('.filter.active')?.dataset.filter || 'all');
}

function kvRow(label, value) {
  const row = el('div', 'kv-row');
  row.append(el('span', 'k', label), el('span', 'v', value == null || value === '' ? '—' : String(value)));
  return row;
}

function renderFixes(report) {
  const target = $('fixes');
  target.replaceChildren();
  const fixes = report.verdict?.top_fixes || [];
  if (!fixes.length) {
    target.append(el('li', '', '暂无额外修复项。'));
    return;
  }
  fixes.forEach((fix, index) => {
    const node = el('li', '', fix);
    node.style.animationDelay = `${index * 80}ms`;
    target.append(node);
  });
}

// Which runtime leaves from where. The browser and Node can differ, and
// Claude Code runs on Node -- so this row set is often the real answer.
function renderEgress(report) {
  const target = $('egress');
  if (!target) return;
  target.replaceChildren();
  const rows = [];
  const traces = report.traces || [];
  const order = ['trace.claude', 'trace.anthropic', 'trace.api', 'trace.cf'];
  const labels = {
    'trace.claude': 'claude.ai',
    'trace.anthropic': 'anthropic.com',
    'trace.api': 'api.anthropic.com',
    'trace.cf': 'cloudflare.com',
  };
  for (const key of order) {
    const trace = traces.find((item) => item.key === key);
    if (!trace) continue;
    rows.push({
      label: labels[key] || key,
      value: trace.ok ? `${trace.loc || '?'} · ${trace.ip || '—'}` : '探测失败（网络抖动或不可达）',
      bad: !trace.ok,
    });
  }
  for (const probe of report.runtimes || []) {
    if (!probe.available) continue;
    rows.push({
      label: `${probe.label}`,
      value: probe.ok ? `${probe.loc || '?'} · ${probe.ip || '—'}` : (probe.error || '探测失败'),
      bad: !probe.ok,
    });
  }
  if (!rows.length) {
    target.append(el('div', 'empty', '尚无出口数据。'));
    return;
  }
  // Highlight the split the moment two rows disagree on the country.
  const countries = rows
    .filter((row) => !row.bad)
    .map((row) => (row.value || '').split(' · ')[0])
    .filter(Boolean);
  const split = new Set(countries).size > 1;
  if (split) target.classList.add('split');
  else target.classList.remove('split');
  for (const row of rows) {
    const line = el('div', `egress-row${row.bad ? ' bad' : ''}`);
    line.append(el('span', 'k', row.label), el('span', 'v', row.value));
    target.append(line);
  }
  if (split) {
    target.append(el('div', 'egress-warn', '以上出口不一致：浏览器看到的环境，Claude Code 未必一样'));
  }
}

function renderEnv(report) {
  const target = $('env');
  target.replaceChildren();
  const env = report.environment || {};
  const client = report.client || {};
  const rows = [
    ['出口 IP', env.ip || '—'],
    ['国家 / 城市', `${env.country_code || '—'} · ${env.city || '—'}`],
    ['ASN', env.asn || '—'],
    ['系统时区', env.timezone || '—'],
    ['系统语言', env.locale || '—'],
    ['浏览器', env.browser || '—'],
    ['操作系统', env.os || '—'],
    ['设备指纹', env.fingerprint || '—'],
    ['Claude Code', client.installed ? `v${client.version || '?'}` : '未安装'],
    ['API 端点', client.base_url_kind === 'third_party' ? `第三方 · ${client.relay_hint || '?'}` : (client.base_url_kind || '—')],
    ['数据源覆盖率', `${Math.round((report.coverage || 0) * 100)}%`],
    ['规则版本', report.rules_version || '—'],
  ];
  for (const [key, value] of rows) target.append(kvRow(key, value));
}

function renderHistoryRows(rows) {
  const target = $('history');
  target.replaceChildren();
  if (!rows || !rows.length) {
    target.append(el('div', 'empty', '暂无历史；完成一次检测后会记录环境。'));
    return;
  }
  rows.forEach((row, index) => {
    const node = el('div');
    const line = el('div', 'hrow');
    const verdict = SHORT_VERDICT[row.verdict] || String(row.verdict || '—').slice(0, 6);
    line.append(
      el('span', '', fmtTime(row.started_at)),
      el('span', 'v', verdict),
      el('span', '', row.score == null ? '—' : String(Math.round(row.score))),
      el('span', '', row.country || '—')
    );
    const bar = el('div', 'hbar');
    const fill = el('i');
    bar.append(fill);
    node.append(line, bar);
    target.append(node);
    const width = `${row.score == null ? 0 : clamp(row.score, 0, 100)}%`;
    window.setTimeout(() => { fill.style.width = width; }, 80 + index * 45);
  });
}

async function loadHistory() {
  try {
    const data = await api('/api/history?limit=8');
    renderHistoryRows(data.rows || []);
  } catch (error) {
    $('history').replaceChildren(el('div', 'empty', `历史读取失败：${error.message}`));
  }
}

function applyFilter(want) {
  document.querySelectorAll('.finding').forEach((row) => {
    row.style.display = want === 'all' || row.dataset.status === want ? '' : 'none';
  });
}

function render(report, { animate = true } = {}) {
  currentReport = report;
  hasReport = true;
  const verdict = report.verdict || {};
  const color = ACCENTS[verdict.code] || ACCENTS.unknown;
  applyAccent(color);

  setText('eyebrow', `${verdict.title || 'VERDICT'} / ${String(verdict.code || '').toUpperCase()}`);
  const headline = $('headline');
  headline.textContent = verdict.headline || '—';
  if (animate && !REDUCED) {
    headline.classList.remove('glitch');
    void headline.offsetWidth;
    headline.classList.add('glitch');
  }
  setText('reason', verdict.reason || '');
  setText('coverage', `覆盖率 ${Math.round((report.coverage || 0) * 100)}% · 置信度 ${report.confidence || '—'}`);
  const basisNode = $('score-basis');
  if (basisNode) {
    const basis = report.score_basis || {};
    if (basis.capped && basis.cap != null && basis.averaged != null) {
      basisNode.textContent = `加权平均 ${Math.round(basis.averaged)} → 由 ${basis.cap_rule}（${basis.cap_severity}）封顶 ${Math.round(basis.cap)}`;
      basisNode.hidden = false;
    } else if (basis.averaged != null) {
      basisNode.textContent = `六轴加权平均 ${Math.round(basis.averaged)}`;
      basisNode.hidden = false;
    } else {
      basisNode.hidden = true;
    }
  }
  gauge.animateTo(report.score, animate ? 1200 : 200);

  renderChips(report);
  renderStats(report);
  renderCategories(report);
  renderFindings(report);
  renderFixes(report);
  renderEgress(report);
  renderEnv(report);

  const badge = $('reference-badge');
  badge.className = 'badge';
  if (report.account) {
    const state = String(report.account.state || '').toUpperCase();
    badge.classList.add(state === 'active' ? 'green' : 'red');
    badge.textContent = `ACCOUNT ${state}`;
  } else {
    badge.classList.add('amber');
    badge.textContent = 'REFERENCE MODE';
  }
  setText('status', `UPDATED ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`);
  $('status').className = 'status mono ok';
  document.title = `Claude Sentinel · ${verdict.headline || 'Live'}`;
}

function showEmpty(message = '') {
  hasReport = false;
  setText('eyebrow', 'REFERENCE MODE');
  setText('headline', '尚无报告');
  setText('reason', message || '首次使用会自动尝试检测；也可以点击“重新检测”。');
  setText('coverage', '覆盖率 —');
  gauge.reset();
  const marker = $('band-marker');
  if (marker) marker.style.left = '0%';
  $('chips').replaceChildren(chip('MODE', 'REFERENCE'), chip('STATUS', 'NO REPORT'));
  $('stats').replaceChildren();
  $('categories').replaceChildren(el('div', 'empty', '完成检测后显示六轴分类。'));
  $('findings').replaceChildren(el('div', 'empty', '完成检测后显示发现。'));
  $('fixes').replaceChildren(el('li', '', '完成检测后显示修复顺序。'));
  $('env').replaceChildren(el('div', 'empty', '完成检测后显示环境快照。'));
  $('history').replaceChildren(el('div', 'empty', '暂无历史。'));
  setText('finding-count', '0');
  $('reference-badge').className = 'badge amber';
  $('reference-badge').textContent = 'REFERENCE MODE';
  applyAccent(ACCENTS.unknown);
}

// ---------------------------------------------------------------- scanner
function buildStageRows(list) {
  const target = $('scan-stages');
  target.replaceChildren();
  stages = list.map((stage) => {
    const row = el('li', 'stage-row pending');
    const mark = el('span', 'stage-mark');
    const name = el('span', 'stage-name', stage.label);
    const detail = el('span', 'stage-detail', stage.hint || '');
    row.append(mark, name, detail);
    target.append(row);
    return { ...stage, row, detail, state: 'pending' };
  });
  setText('scan-total', String(stages.length));
}

// Keep the active stage visible: only scroll when it would drift out of the
// comfortable middle band, so the list does not jitter stage to stage.
// Uses client rects, because offsetTop is relative to the nearest positioned
// ancestor (the scanner), not to the scrolling list.
function centerStage(row) {
  const box = $('scan-stages');
  if (!box || !row || REDUCED) return;
  const boxRect = box.getBoundingClientRect();
  const rowRect = row.getBoundingClientRect();
  const rowTop = rowRect.top - boxRect.top + box.scrollTop;
  const rowHeight = rowRect.height || 22;
  const target = rowTop - box.clientHeight / 2 + rowHeight / 2;
  const topGap = rowTop - box.scrollTop;
  const bottomGap = box.scrollTop + box.clientHeight - (rowTop + rowHeight);
  if (topGap >= rowHeight && bottomGap >= rowHeight * 2) return;
  box.scrollTo({ top: Math.max(0, target), behavior: 'smooth' });
}

function stageState(stageId, phase, detail) {
  const stage = stages.find((item) => item.id === stageId);
  if (!stage) return;
  stage.state = phase;
  stage.row.className = `stage-row ${phase === 'start' ? 'active' : phase}`;
  if (detail) stage.detail.textContent = detail;
  const done = stages.filter((item) => ['done', 'warn', 'fail', 'skip'].includes(item.state)).length;
  const active = stages.some((item) => item.state === 'active');
  setText('scan-done', String(done));
  const percent = Math.round((done / Math.max(1, stages.length)) * 100);
  setText('scan-percent', String(percent));
  $('scan-fill').style.width = `${percent}%`;
  if (phase === 'start') {
    const current = $('scan-current');
    current.replaceChildren(document.createTextNode(stage.label), el('span', 'caret'));
    centerStage(stage.row);
  }
  // Radar blip per settled stage: risk-coloured when a hint of trouble exists.
  if (['done', 'warn', 'fail'].includes(phase)) {
    spawnBlip(phase);
  }
  if (!active && done === stages.length) {
    setText('scan-percent', '100');
  }
}

function spawnBlip(phase) {
  const layer = $('radar-blips');
  if (!layer || REDUCED) return;
  const node = el('span', `blip${phase === 'warn' ? ' warn' : phase === 'fail' ? ' high' : ''}`);
  const angle = Math.random() * Math.PI * 2;
  const radius = 22 + Math.random() * 88;
  node.style.left = `${50 + (Math.cos(angle) * radius) / 2.9}%`;
  node.style.top = `${50 + (Math.sin(angle) * radius) / 2.9}%`;
  layer.append(node);
  window.setTimeout(() => node.remove(), 2300);
}

function setScanning(active) {
  document.body.classList.toggle('scanning', active);
  const button = $('scan');
  button.disabled = active;
  setText('scan-label', active ? '扫描中…' : '重新检测');
  if (active) {
    document.body.classList.remove('resolving');
    setText('status', 'SCANNING');
    $('status').className = 'status mono';
  }
}

async function resolveScan(report, durationMs) {
  // Let the audience read the last stage before the reveal.
  await wait(260);
  const flash = $('flash');
  if (!REDUCED) {
    flash.classList.remove('fire');
    void flash.offsetWidth;
    flash.classList.add('fire');
    if (sceneApi) sceneApi.pulse(1.6);
  }
  document.body.classList.add('resolving');
  await wait(140);
  render(report);
  setText('status', `DONE · ${(durationMs / 1000).toFixed(1)}s`);
  $('status').className = 'status mono ok';
  document.body.classList.remove('scanning');
  await wait(520);
  document.body.classList.remove('resolving');
  const button = $('scan');
  button.disabled = false;
  setText('scan-label', '重新检测');
}

function scannerFail(message) {
  document.body.classList.remove('scanning');
  setText('status', `ERROR · ${message}`);
  $('status').className = 'status mono err';
  const button = $('scan');
  button.disabled = false;
  setText('scan-label', '重新检测');
  if (!hasReport) showEmpty(`检测失败：${message}`);
}

// ------------------------------------------------------------- scan stream
function parseSSE(buffer) {
  const events = [];
  for (const block of buffer.split('\n\n')) {
    const lines = block.split('\n');
    let event = 'message';
    const data = [];
    for (const line of lines) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data.push(line.slice(5).trim());
    }
    if (data.length) {
      try {
        events.push({ event, data: JSON.parse(data.join('\n')) });
      } catch (error) {
        /* ignore malformed frame */
      }
    }
  }
  return events;
}

async function runScan() {
  if (streaming) return;
  streaming = true;
  setScanning(true);
  document.body.classList.remove('resolving');
  // The sweep must not wear the previous verdict's colour: cyan until a new
  // verdict lands, so "red everywhere" is never ambiguous on camera.
  applyAccent(ACCENTS.caution);
  buildStageRows(stages.length ? stages : await loadStages());
  const box = $('scan-stages');
  if (box) box.scrollTop = 0;
  setText('scan-percent', '0');
  setText('scan-done', '0');
  $('scan-fill').style.width = '0%';
  setText('scan-current', '正在初始化检测引擎…');
  const startedAt = performance.now();
  const elapsedTimer = window.setInterval(() => {
    setText('scan-elapsed', `${((performance.now() - startedAt) / 1000).toFixed(1)}s`);
  }, 100);

  let sawReport = false;
  try {
    const response = await fetch('/api/scan/stream', {
      method: 'POST',
      headers: { Accept: 'text/event-stream', 'X-Sentinel-Token': TOKEN },
    });
    if (!response.ok || !response.body) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let pendingReport = null;
    let durationMs = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let split = buffer.indexOf('\n\n');
      while (split !== -1) {
        const frame = buffer.slice(0, split);
        buffer = buffer.slice(split + 2);
        for (const { event, data } of parseSSE(frame + '\n\n')) {
          if (event === 'stage') stageState(data.id, data.phase, data.detail);
          else if (event === 'report') {
            sawReport = true;
            pendingReport = data.report;
            durationMs = data.duration_ms || performance.now() - startedAt;
            if (data.history) renderHistoryRows(data.history);
          } else if (event === 'failed') {
            throw new Error(data.error || 'scan failed');
          }
        }
        split = buffer.indexOf('\n\n');
      }
    }
    window.clearInterval(elapsedTimer);
    if (!sawReport || !pendingReport) throw new Error('检测未返回报告');
    setText('scan-elapsed', `${(durationMs / 1000).toFixed(1)}s`);
    await resolveScan(pendingReport, durationMs);
    if (!document.querySelector('#history .hrow')) await loadHistory();
  } catch (error) {
    window.clearInterval(elapsedTimer);
    // Fall back to the blocking endpoint if streaming is unavailable.
    if (String(error.message).includes('409')) {
      setScanning(false);
      return;
    }
    try {
      const report = await api('/api/scan', { method: 'POST' });
      window.clearInterval(elapsedTimer);
      const elapsed = performance.now() - startedAt;
      await resolveScan(report, elapsed);
      await loadHistory();
    } catch (fallbackError) {
      window.clearInterval(elapsedTimer);
      scannerFail(fallbackError.message);
    }
  } finally {
    streaming = false;
    window.clearInterval(elapsedTimer);
  }
}

async function loadStages() {
  try {
    const meta = await api('/api/meta');
    return meta.stages || [];
  } catch (error) {
    return [];
  }
}

// -------------------------------------------------------------------- boot
async function boot() {
  $('version').textContent = `v${VERSION}`;
  $('report-link').href = '/api/latest';
  buildGaugeTicks();
  initScene();
  gauge.reset();

  const clock = () => setText('clock', new Date().toLocaleTimeString('zh-CN', { hour12: false }));
  clock();
  window.setInterval(clock, 1000);

  $('scan').addEventListener('click', runScan);
  window.addEventListener('keydown', (event) => {
    if (event.key === 'r' && !event.metaKey && !event.ctrlKey && !event.altKey && !streaming) runScan();
  });
  document.querySelectorAll('[data-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('[data-filter]').forEach((item) => item.classList.remove('active'));
      button.classList.add('active');
      applyFilter(button.dataset.filter);
    });
  });

  let meta = {};
  try {
    meta = await api('/api/meta');
  } catch (error) {
    meta = {};
  }

  if (!meta.has_report) {
    showEmpty('尚未检测；马上开始第一次环境扫描。');
  } else {
    try {
      const report = await api('/api/latest');
      render(report, { animate: false });
      await loadHistory();
    } catch (error) {
      showEmpty('尚未检测；马上开始第一次环境扫描。');
    }
  }

  document.body.classList.add('revealed');

  // Autostart: `sentinel live` passes --auto, and a first-ever run always scans.
  const wantsAuto = meta.autostart || !meta.has_report;
  if (wantsAuto) {
    await wait(420);
    runScan();
  }
}

boot();
