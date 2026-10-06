// ==UserScript==
// @name         Cheburcheck: проверка сайта в списках ТСПУ
// @namespace    https://github.com/TheReshkin/cheburcheck-tampermonkey
// @version      0.3.0
// @description  Проверяет, заблокирован ли домен текущего сайта и его сторонние домены (списки + динамическая проверка сканерами ТСПУ), через https://cheburcheck.ru/. Запуск вручную из меню Tampermonkey.
// @author       TheReshkin
// @license      MIT
// @homepageURL  https://github.com/TheReshkin/cheburcheck-tampermonkey
// @supportURL   https://github.com/TheReshkin/cheburcheck-tampermonkey/issues
// @updateURL    https://raw.githubusercontent.com/TheReshkin/cheburcheck-tampermonkey/main/cheburcheck.user.js
// @downloadURL  https://raw.githubusercontent.com/TheReshkin/cheburcheck-tampermonkey/main/cheburcheck.user.js
// @match        http://*/*
// @match        https://*/*
// @exclude      https://cheburcheck.ru/*
// @connect      cheburcheck.ru
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        GM_getValue
// @grant        GM_setValue
// @noframes
// @run-at       document-start
// ==/UserScript==

(function () {
  'use strict';

  const API = 'https://cheburcheck.ru/api/v1/check?target=';
  const PROBE_API = 'https://cheburcheck.ru/api/v1/probe/';
  const SITE = 'https://cheburcheck.ru/check?target=';
  const HOST_ID = 'cheburcheck-tm-badge';
  const PROBE_TIMEOUT_MS = 90000;
  const CONCURRENCY = 2;          // сколько доменов проверяем одновременно
  const MAX_DOMAINS = 40;         // потолок на один запуск
  const CACHE_TTL_MS = 3 * 60 * 60 * 1000;
  const RETRY_DELAYS_MS = [8000, 20000, 40000]; // при ответе 429

  // ---------------------------------------------------------------------------
  // Сбор доменов, к которым обращалась страница (ничего никуда не отправляется).
  // Запускаемся на document-start, чтобы PerformanceObserver увидел ранние запросы.
  // ---------------------------------------------------------------------------

  const seenHosts = new Set();

  function addHostFromUrl(url) {
    try {
      const u = new URL(url, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      seenHosts.add(u.hostname.toLowerCase());
    } catch (e) { /* игнорируем */ }
  }

  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) addHostFromUrl(e.name);
    }).observe({ type: 'resource', buffered: true });
  } catch (e) { /* PerformanceObserver недоступен — соберём из getEntriesByType при запуске */ }

  /** Домен текущей страницы без ведущего "www." */
  function currentDomain() {
    return location.hostname.replace(/^www\./i, '').toLowerCase();
  }

  const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'msk', 'spb']);

  /** Грубая оценка "основного" домена (без публичного списка суффиксов). */
  function baseDomain(host) {
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const take = SECOND_LEVEL.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2 ? 3 : 2;
    return parts.slice(-take).join('.');
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
  }

  /** Сторонние домены: не наш основной домен, не IP, не localhost. */
  function collectThirdParty() {
    try {
      for (const e of performance.getEntriesByType('resource')) addHostFromUrl(e.name);
    } catch (e) { /* нет API */ }
    const own = baseDomain(currentDomain());
    return [...seenHosts]
      .filter((h) => h.includes('.') && !isIp(h) && baseDomain(h) !== own)
      .sort();
  }

  // ---------------------------------------------------------------------------
  // Работа с API cheburcheck.ru
  // ---------------------------------------------------------------------------

  function httpError(message, status) {
    const err = new Error(message);
    err.status = status;
    return err;
  }

  /** Статическая проверка (GET /api/v1/check?target=...), как на сайте. */
  function fetchCheck(target) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: 'GET',
        url: API + encodeURIComponent(target),
        headers: { Accept: 'application/json' },
        timeout: 20000,
        onload(res) {
          if (res.status === 200) {
            try { resolve(JSON.parse(res.responseText)); }
            catch (e) { reject(new Error('Некорректный ответ сервера')); }
          } else if (res.status === 404) {
            reject(httpError('Домен не найден (не удалось определить)', 404));
          } else if (res.status === 429) {
            reject(httpError('Слишком много запросов, попробуйте позже', 429));
          } else {
            reject(httpError('HTTP ' + res.status, res.status));
          }
        },
        onerror() { reject(new Error('Ошибка сети')); },
        ontimeout() { reject(new Error('Таймаут запроса')); },
      });
    });
  }

  /** Приоритет вердиктов и подписи — как на сайте cheburcheck.ru. */
  const VERDICT_PRIORITY = ['tspu_block', 'sni_block', 'dns_spoofing', 'whitelist', 'cdn_block', 'ok', 'uncertain'];
  const VERDICTS = {
    tspu_block: { kind: 'bad', icon: '🚫', title: 'заблокирован', text: 'Сканеры обнаружили блокировку TCP на уровне ТСПУ' },
    sni_block: { kind: 'bad', icon: '🚫', title: 'заблокирован', text: 'Сканеры обнаружили блокировку по имени домена в SNI' },
    dns_spoofing: { kind: 'bad', icon: '🚫', title: 'заблокирован', text: 'Сканеры обнаружили подмену ответов DNS' },
    cdn_block: { kind: 'bad', icon: '🚫', title: 'недоступен', text: 'Сканеры обнаружили блокировку CDN (16-20 КБ)' },
    whitelist: { kind: 'warn', icon: '⚠', title: 'исключение для CDN', text: 'Домен снимает ограничение 16-20 КБ при подключении к заблокированным CDN' },
    ok: { kind: 'ok', icon: '✅', title: 'не ограничен', text: 'Ограничений не обнаружено' },
  };

  /** Вердикт одного сканера с учётом CDN (как displayProbeVerdicts на сайте). */
  function probeVerdict(probe, isStaticCdn) {
    const noHosts = probe.host_results && probe.host_results.length === 0;
    const list = (probe.verdicts || []).map((v) =>
      isStaticCdn && !probe.cdn_unblocked && !noHosts && v === 'ok' ? 'cdn_block' : v);
    return VERDICT_PRIORITY.find((c) => list.includes(c));
  }

  /** Итоговый вердикт голосованием сканеров (как selectProbeVerdict на сайте). */
  function selectVerdict(probes, isStaticCdn) {
    const votes = {};
    for (const p of probes) {
      const v = probeVerdict(p, isStaticCdn);
      if (v) votes[v] = (votes[v] || 0) + 1;
    }
    let winner = null;
    let best = 0;
    for (const v of VERDICT_PRIORITY) {
      if ((votes[v] || 0) > best) { winner = v; best = votes[v]; }
    }
    return winner === 'uncertain' ? null : winner;
  }

  /**
   * Читает SSE-поток динамической проверки (/api/v1/probe/<id>) и ждёт события "done".
   * onProgress(probes, online) вызывается при каждом новом результате.
   * Возвращает { probes, online, done }.
   */
  function runProbes(id, onProgress) {
    return new Promise((resolve, reject) => {
      const probes = new Map();
      let online = 0;
      let done = false;
      let parsed = 0;
      let finished = false;

      const finish = (err) => {
        if (finished) return;
        finished = true;
        if (err && !probes.size) reject(err);
        else resolve({ probes: [...probes.values()], online, done });
      };

      const handleEvent = (name, data) => {
        let obj;
        try { obj = JSON.parse(data); } catch (e) { return; }
        if (name === 'started') {
          online = obj.online_probes || 0;
        } else if (name === 'result') {
          probes.set(obj.probe_id, obj);
          onProgress([...probes.values()], online);
        } else if (name === 'done') {
          done = true;
          online = obj.online_probes || online;
          finish();
        }
      };

      // Разбираем только новые полностью пришедшие события (блоки разделены пустой строкой).
      const consume = (text) => {
        const normalized = text.replace(/\r\n/g, '\n');
        const end = normalized.lastIndexOf('\n\n');
        if (end < parsed) return;
        const chunk = normalized.slice(parsed, end + 2);
        parsed = end + 2;
        for (const block of chunk.split('\n\n')) {
          let name = 'message';
          const dataLines = [];
          for (const line of block.split('\n')) {
            if (line.startsWith('event:')) name = line.slice(6).trim();
            else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
          }
          if (dataLines.length) handleEvent(name, dataLines.join('\n'));
        }
      };

      GM_xmlhttpRequest({
        method: 'GET',
        url: PROBE_API + encodeURIComponent(id),
        headers: { Accept: 'text/event-stream' },
        timeout: PROBE_TIMEOUT_MS,
        onprogress(res) { consume(res.responseText || ''); },
        onload(res) {
          if (res.status !== 200) return finish(httpError('HTTP ' + res.status, res.status));
          consume(res.responseText || '');
          finish();
        },
        onerror() { finish(new Error('Ошибка сети при динамической проверке')); },
        ontimeout() { finish(new Error('Таймаут динамической проверки')); },
      });
    });
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /** Повторяет операцию при HTTP 429 с растущей паузой. */
  async function withRetry(fn) {
    for (let i = 0; ; i++) {
      try {
        return await fn();
      } catch (e) {
        if (e.status !== 429 || i >= RETRY_DELAYS_MS.length) throw e;
        await sleep(RETRY_DELAYS_MS[i]);
      }
    }
  }

  /**
   * Полная проверка домена: списки, затем (если не найден) динамическая проверка.
   * Возвращает { kind, label, text, info, probes, online, done, blocked }.
   * kind: 'ok' | 'bad' | 'warn' | 'err'.
   */
  async function checkDomain(domain, onProgress) {
    const r = await withRetry(() => fetchCheck(domain));
    const info = [];
    if (r.rkn_domain) info.push('Запись в реестре: ' + r.rkn_domain);
    if (r.blocked_subnets && r.blocked_subnets.length) {
      info.push('Заблокированные подсети: ' + r.blocked_subnets.length);
    }
    const cdns = Object.keys(r.cdn_providers || {});
    if (cdns.length) info.push('CDN: ' + cdns.join(', '));

    // Как на сайте: вердикт сканеров главнее списков, списки — запасной вариант.
    // (Статический blocked=true бывает и у доменов за заблокированным CDN, которые сканеры считают доступными.)
    const staticFallback = (note) => r.blocked
      ? { kind: 'bad', icon: '🚫', label: 'заблокирован', text: 'Найден в списках блокировок. ' + note, info, partial: true }
      : { kind: 'err', icon: '❔', label: 'вердикт не определён', text: note, info, partial: true };

    if (!r.id) return staticFallback('Сервер не вернул id динамической проверки');

    let res;
    try {
      res = await withRetry(() => runProbes(r.id, onProgress || (() => {})));
    } catch (e) {
      if (e.status === 429) throw e;
      return staticFallback('Динамическая проверка не удалась: ' + e.message);
    }
    const verdict = selectVerdict(res.probes, cdns.length > 0);
    const counts = res.probes.length + (res.online ? ' из ' + res.online : '') + ' сканеров';
    const partial = !res.done;

    if (!verdict) return staticFallback('Сканеры не дали вердикта (' + counts + ')');
    const v = VERDICTS[verdict];
    return { kind: v.kind, icon: v.icon, label: v.title, text: v.text + '. ' + counts, info, partial };
  }

  // ---------------------------------------------------------------------------
  // Кэш результатов (только завершённые, без ошибок)
  // ---------------------------------------------------------------------------

  function cacheGet(domain) {
    try {
      const e = GM_getValue('cc:' + domain, null);
      if (e && Date.now() - e.t < CACHE_TTL_MS) return e.res;
    } catch (err) { /* нет кэша */ }
    return null;
  }

  function cacheSet(domain, res) {
    if (res.kind === 'err' || res.partial) return;
    try { GM_setValue('cc:' + domain, { t: Date.now(), res }); } catch (err) { /* ignore */ }
  }

  // ---------------------------------------------------------------------------
  // Плашка
  // ---------------------------------------------------------------------------

  const STYLES = `
    :host { all: initial; }
    .box {
      position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
      width: max-content; max-width: 360px; padding: 10px 12px; border-radius: 8px;
      font: 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
      color: #fff; background: #374151; box-shadow: 0 4px 16px rgba(0,0,0,.35);
    }
    .box.ok { background: #15803d; }
    .box.bad { background: #b91c1c; }
    .box.warn { background: #b45309; }
    .box.err { background: #4b5563; }
    .title { font-weight: 600; padding-right: 18px; }
    .meta { margin-top: 4px; opacity: .9; font-size: 12px; }
    .list { margin-top: 8px; max-height: 40vh; overflow-y: auto; font-size: 12px; }
    .row { display: flex; gap: 6px; padding: 2px 0; align-items: baseline; }
    .row .d { flex: 1; word-break: break-all; }
    .row .s { opacity: .9; white-space: nowrap; }
    a { color: #fff; text-decoration: underline; }
    button {
      all: unset; cursor: pointer; position: absolute; top: 6px; right: 8px;
      font-size: 16px; line-height: 1; opacity: .8;
    }
    button:hover { opacity: 1; }
  `;

  function removeBadge() {
    const old = document.getElementById(HOST_ID);
    if (old) old.remove();
  }

  /**
   * Плашка со статусом. kind: '' | 'ok' | 'bad' | 'warn' | 'err'.
   * rows (необязательно): [{ domain, icon, status }] — список доменов.
   */
  function showBadge(kind, title, meta, domain, rows) {
    removeBadge();
    const host = document.createElement('div');
    host.id = HOST_ID;
    const root = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = STYLES;

    const box = document.createElement('div');
    box.className = 'box ' + kind;

    const close = document.createElement('button');
    close.textContent = '×';
    close.title = 'Закрыть';
    close.addEventListener('click', removeBadge);

    const t = document.createElement('div');
    t.className = 'title';
    t.textContent = title;
    box.append(close, t);

    if (meta) {
      const m = document.createElement('div');
      m.className = 'meta';
      m.textContent = meta;
      box.append(m);
    }

    if (rows && rows.length) {
      const list = document.createElement('div');
      list.className = 'list';
      for (const r of rows) {
        const row = document.createElement('div');
        row.className = 'row';
        const ic = document.createElement('span');
        ic.textContent = r.icon;
        const d = document.createElement('a');
        d.className = 'd';
        d.href = SITE + encodeURIComponent(r.domain);
        d.target = '_blank';
        d.rel = 'noopener noreferrer';
        d.textContent = r.domain;
        const s = document.createElement('span');
        s.className = 's';
        s.textContent = r.status;
        row.append(ic, d, s);
        list.append(row);
      }
      box.append(list);
    }

    if (domain) {
      const l = document.createElement('div');
      l.className = 'meta';
      const a = document.createElement('a');
      a.href = SITE + encodeURIComponent(domain);
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Подробнее на cheburcheck.ru';
      l.append(a);
      box.append(l);
    }

    root.append(style, box);
    (document.body || document.documentElement).append(host);
  }

  // ---------------------------------------------------------------------------
  // Команды меню
  // ---------------------------------------------------------------------------

  let running = false;

  /** Проверка домена текущего сайта. */
  async function runCheck() {
    if (running) return;
    const domain = currentDomain();
    if (!domain) return;
    running = true;
    showBadge('', 'Проверяю ' + domain + '…', 'Статическая проверка по спискам');
    try {
      const res = await checkDomain(domain, (probes, online) => {
        showBadge('', 'Проверяю ' + domain + '…',
          'Динамическая проверка: ответили ' + probes.length + (online ? ' из ' + online : '') + ' сканеров…');
      });
      cacheSet(domain, res);
      const tail = [res.text].concat(res.info);
      if (res.partial) tail.push('проверка завершена не полностью');
      showBadge(res.kind, res.icon + ' ' + domain + ': ' + res.label, tail.join(' · '), domain);
    } catch (e) {
      showBadge('err', '⚠ Не удалось проверить ' + domain, e.message, domain);
    } finally {
      running = false;
    }
  }

  const KIND_ORDER = { bad: 0, warn: 1, err: 2, ok: 3 };

  /** Проверка сторонних доменов, к которым обращалась страница. */
  async function runCheckThirdParty() {
    if (running) return;
    let domains = collectThirdParty();
    if (!domains.length) {
      showBadge('err', 'Сторонних доменов не найдено',
        'Страница пока не обращалась к другим доменам (или они не видны скрипту).');
      return;
    }
    const truncated = domains.length > MAX_DOMAINS;
    domains = domains.slice(0, MAX_DOMAINS);

    running = true;
    const results = new Map();   // domain -> результат или { kind: 'err', ... }
    const pending = new Set(domains);
    let doneCount = 0;

    const render = () => {
      const rows = domains.map((d) => {
        const r = results.get(d);
        if (r) return { domain: d, icon: r.icon || '⚠', status: r.label, kind: r.kind };
        return { domain: d, icon: '⏳', status: pending.has(d) ? 'ожидает' : 'проверяется…', kind: 'pending' };
      });
      const order = (x) => (x.kind === 'pending' ? 4 : KIND_ORDER[x.kind] ?? 2);
      rows.sort((a, b) => order(a) - order(b) || a.domain.localeCompare(b.domain));

      const all = [...results.values()];
      const bad = all.filter((r) => r.kind === 'bad').length;
      const warn = all.filter((r) => r.kind === 'warn').length;
      const err = all.filter((r) => r.kind === 'err').length;
      const finished = doneCount === domains.length;

      const parts = [];
      if (bad) parts.push('заблокировано: ' + bad);
      if (warn) parts.push('особые: ' + warn);
      if (err) parts.push('не проверено: ' + err);
      const summary = parts.length ? parts.join(', ') : (finished ? 'ограничений не найдено' : '');

      const kind = !finished ? '' : bad ? 'bad' : (warn || err) ? 'warn' : 'ok';
      const title = (finished ? 'Сторонние домены: ' : 'Проверено ' + doneCount + ' из ' + domains.length + ' · ') +
        (summary || 'идёт проверка…');
      const meta = (truncated ? 'Показаны первые ' + MAX_DOMAINS + ' доменов. ' : '') +
        (finished ? '' : 'Каждый домен проверяется до ~минуты, подождите.');
      showBadge(kind, title, meta, null, rows);
    };

    render();

    const queue = domains.slice();
    const worker = async () => {
      for (;;) {
        const d = queue.shift();
        if (!d) return;
        pending.delete(d);
        render();
        let res = cacheGet(d);
        if (!res) {
          try {
            res = await checkDomain(d);
            cacheSet(d, res);
          } catch (e) {
            res = { kind: 'err', icon: '⚠', label: e.message, text: e.message, info: [] };
          }
        }
        results.set(d, res);
        doneCount++;
        render();
      }
    };

    try {
      await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    } finally {
      running = false;
    }
  }

  GM_registerMenuCommand('Проверить этот сайт на cheburcheck.ru', runCheck);
  GM_registerMenuCommand('Проверить сторонние домены сайта', runCheckThirdParty);
})();
