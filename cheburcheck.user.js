// ==UserScript==
// @name         Cheburcheck: проверка сайта в списках ТСПУ
// @namespace    https://github.com/TheReshkin/cheburcheck-tampermonkey
// @version      0.4.0
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
// @grant        GM_setClipboard
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
  const RETRY_DELAYS_MS = [10000, 20000, 40000, 60000]; // при ответе 429 (если нет Retry-After)
  const MAX_RETRY_AFTER_MS = 120000;

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

  function httpError(message, status, retryAfterMs) {
    const err = new Error(message);
    err.status = status;
    err.retryAfterMs = retryAfterMs || 0;
    return err;
  }

  /** Значение заголовка Retry-After (секунды или дата) в миллисекундах, 0 если нет. */
  function retryAfterMs(res) {
    const m = /^retry-after:s*(.+)$/im.exec(res.responseHeaders || '');
    if (!m) return 0;
    const v = m[1].trim();
    const sec = Number(v);
    const ms = Number.isFinite(sec) ? sec * 1000 : Date.parse(v) - Date.now();
    return Number.isFinite(ms) && ms > 0 ? Math.min(ms, MAX_RETRY_AFTER_MS) : 0;
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
            reject(httpError('Лимит запросов API', 429, retryAfterMs(res)));
          } else {
            reject(httpError('HTTP ' + res.status, res.status, retryAfterMs(res)));
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
          if (res.status !== 200) {
            return finish(httpError(res.status === 429 ? 'Лимит запросов API' : 'HTTP ' + res.status,
              res.status, retryAfterMs(res)));
          }
          consume(res.responseText || '');
          finish();
        },
        onerror() { finish(new Error('Ошибка сети при динамической проверке')); },
        ontimeout() { finish(new Error('Таймаут динамической проверки')); },
      });
    });
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // Общая пауза при лимите: ни один из параллельных запросов не стартует, пока она не истечёт.
  let rateLimitedUntil = 0;

  function rateLimitLeftMs() {
    return Math.max(0, rateLimitedUntil - Date.now());
  }

  /** Повторяет операцию при HTTP 429; уважает Retry-After, пауза общая для всех проверок. */
  async function withRetry(fn) {
    for (let i = 0; ; i++) {
      while (rateLimitLeftMs() > 0) await sleep(Math.min(rateLimitLeftMs(), 1000));
      try {
        return await fn();
      } catch (e) {
        if (e.status !== 429) throw e;
        if (i >= RETRY_DELAYS_MS.length) throw httpError('Лимит запросов API (повторы исчерпаны)', 429);
        const wait = e.retryAfterMs || RETRY_DELAYS_MS[i];
        rateLimitedUntil = Math.max(rateLimitedUntil, Date.now() + wait);
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
    .actions { display: flex; gap: 8px; margin-top: 8px; }
    .btn { cursor: pointer; padding: 3px 10px; border-radius: 4px; background: rgba(255,255,255,.2); font-size: 12px; user-select: none; }
    .btn:hover { background: rgba(255,255,255,.32); }
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
   * actions (необязательно): [{ label, onClick(button) }] — кнопки под списком.
   */
  function showBadge(kind, title, meta, domain, rows, actions) {
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

    if (actions && actions.length) {
      const bar = document.createElement('div');
      bar.className = 'actions';
      for (const act of actions) {
        const btn = document.createElement('span');
        btn.className = 'btn';
        btn.setAttribute('role', 'button');
        btn.tabIndex = 0;
        btn.textContent = act.label;
        btn.addEventListener('click', () => act.onClick(btn));
        bar.append(btn);
      }
      box.append(bar);
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
  // Копирование результатов
  // ---------------------------------------------------------------------------

  function copyText(text) {
    try {
      if (typeof GM_setClipboard === 'function') { GM_setClipboard(text, 'text'); return Promise.resolve(); }
    } catch (e) { /* пробуем дальше */ }
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return Promise.reject(new Error('clipboard unavailable'));
  }

  /** Обработчик кнопки "Копировать": меняет подпись кнопки на результат. */
  function copyAction(getText) {
    return (btn) => {
      const old = btn.textContent;
      copyText(getText()).then(
        () => { btn.textContent = 'Скопировано ✓'; },
        () => { btn.textContent = 'Не удалось скопировать'; });
      setTimeout(() => { btn.textContent = old; }, 2000);
    };
  }

  const KIND_ICON = { bad: '🚫', warn: '⚠', err: '⚠', ok: '✅' };

  function resultLine(domain, r) {
    const parts = [domain, r.label];
    if (r.text && r.text !== r.label) parts.push(r.text);
    if (r.info && r.info.length) parts.push(r.info.join('; '));
    if (r.partial) parts.push('неполная проверка');
    return (KIND_ICON[r.kind] || '•') + ' ' + parts.join(' — ');
  }

  function reportHeader(title) {
    return title + '\nСтраница: ' + location.href + '\nДата: ' + new Date().toLocaleString('ru-RU') +
      '\nИсточник: https://cheburcheck.ru/';
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
    const ticker = setInterval(() => {
      const left = rateLimitLeftMs();
      if (left > 0) {
        showBadge('', 'Проверяю ' + domain + '…',
          'Достигнут лимит запросов API, пауза ' + Math.ceil(left / 1000) + ' с…');
      }
    }, 1000);
    try {
      const res = await checkDomain(domain, (probes, online) => {
        if (rateLimitLeftMs() > 0) return;
        showBadge('', 'Проверяю ' + domain + '…',
          'Динамическая проверка: ответили ' + probes.length + (online ? ' из ' + online : '') + ' сканеров…');
      });
      cacheSet(domain, res);
      const tail = [res.text].concat(res.info);
      if (res.partial) tail.push('проверка завершена не полностью');
      showBadge(res.kind, res.icon + ' ' + domain + ': ' + res.label, tail.join(' · '), domain, null, [
        { label: 'Копировать', onClick: copyAction(() => reportHeader('Cheburcheck: проверка сайта') + '\n' + resultLine(domain, res)) },
      ]);
    } catch (e) {
      clearInterval(ticker);
      running = false;
      showBadge('err', '⚠ Не удалось проверить ' + domain, e.message, domain, null, [
        { label: 'Повторить', onClick: () => runCheck() },
      ]);
    } finally {
      clearInterval(ticker);
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

    const results = new Map();   // domain -> результат (в том числе с kind 'err')
    const waiting = new Set(domains);
    let finished = false;

    const sortedRows = () => {
      const rows = domains.map((d) => {
        const r = results.get(d);
        if (r) return { domain: d, icon: r.icon || '⚠', status: r.label, kind: r.kind };
        return { domain: d, icon: '⏳', status: waiting.has(d) ? 'ожидает' : 'проверяется…', kind: 'pending' };
      });
      const order = (x) => (x.kind === 'pending' ? 4 : KIND_ORDER[x.kind] ?? 2);
      return rows.sort((a, b) => order(a) - order(b) || a.domain.localeCompare(b.domain));
    };

    const counts = () => {
      const all = [...results.values()];
      return {
        bad: all.filter((r) => r.kind === 'bad').length,
        warn: all.filter((r) => r.kind === 'warn').length,
        err: all.filter((r) => r.kind === 'err').length,
        ok: all.filter((r) => r.kind === 'ok').length,
      };
    };

    const summaryText = () => {
      const c = counts();
      const parts = [];
      if (c.bad) parts.push('заблокировано: ' + c.bad);
      if (c.warn) parts.push('особые: ' + c.warn);
      if (c.err) parts.push('не проверено: ' + c.err);
      return parts.length ? parts.join(', ') : (finished ? 'ограничений не найдено' : '');
    };

    const buildReport = () => {
      const lines = sortedRows().map((row) => resultLine(row.domain, results.get(row.domain)));
      const c = counts();
      return reportHeader('Cheburcheck: сторонние домены сайта') +
        '\nИтого: ' + domains.length + ' доменов, заблокировано ' + c.bad + ', особые ' + c.warn +
        ', не проверено ' + c.err + ', без ограничений ' + c.ok + '\n\n' + lines.join('\n');
    };

    const retryFailed = () => {
      if (running) return;
      for (const [d, r] of [...results]) if (r.kind === 'err') { results.delete(d); waiting.add(d); }
      start(domains.filter((d) => !results.has(d)));
    };

    const render = () => {
      const c = counts();
      const left = rateLimitLeftMs();
      const kind = !finished ? '' : c.bad ? 'bad' : (c.warn || c.err) ? 'warn' : 'ok';
      const title = (finished ? 'Сторонние домены: ' : 'Проверено ' + results.size + ' из ' + domains.length + ' · ') +
        (summaryText() || 'идёт проверка…');

      const meta = [];
      if (truncated) meta.push('Показаны первые ' + MAX_DOMAINS + ' доменов.');
      if (!finished) meta.push('Каждый домен проверяется до ~минуты, подождите.');
      if (left > 0) meta.push('Достигнут лимит запросов API, пауза ' + Math.ceil(left / 1000) + ' с…');

      let actions = null;
      if (finished) {
        actions = [{ label: 'Копировать результаты', onClick: copyAction(buildReport) }];
        if (c.err) actions.push({ label: 'Повторить неудачные (' + c.err + ')', onClick: retryFailed });
      }
      showBadge(kind, title, meta.join(' '), null, sortedRows(), actions);
    };

    const start = async (list) => {
      running = true;
      finished = false;
      const queue = list.slice();
      const ticker = setInterval(() => { if (rateLimitLeftMs() > 0) render(); }, 1000);
      render();
      const worker = async () => {
        for (;;) {
          const d = queue.shift();
          if (!d) return;
          waiting.delete(d);
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
          render();
        }
      };
      try {
        await Promise.all(Array.from({ length: CONCURRENCY }, worker));
      } finally {
        clearInterval(ticker);
        running = false;
        finished = true;
        render();
      }
    };

    await start(domains);
  }

  GM_registerMenuCommand('Проверить этот сайт на cheburcheck.ru', runCheck);
  GM_registerMenuCommand('Проверить сторонние домены сайта', runCheckThirdParty);
})();
