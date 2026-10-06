// ==UserScript==
// @name         Cheburcheck: проверка сайта в списках ТСПУ
// @namespace    https://github.com/TheReshkin/cheburcheck-tampermonkey
// @version      0.2.0
// @description  Проверяет, заблокирован ли домен текущего сайта (списки + динамическая проверка сканерами ТСПУ), через https://cheburcheck.ru/ (запуск вручную из меню Tampermonkey).
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
// @noframes
// @run-at       document-idle
// ==/UserScript==

(function () {
  'use strict';

  const API = 'https://cheburcheck.ru/api/v1/check?target=';
  const PROBE_API = 'https://cheburcheck.ru/api/v1/probe/';
  const SITE = 'https://cheburcheck.ru/check?target=';
  const HOST_ID = 'cheburcheck-tm-badge';
  const PROBE_TIMEOUT_MS = 90000;

  /** Домен текущей страницы без ведущего "www." */
  function currentDomain() {
    return location.hostname.replace(/^www\./i, '').toLowerCase();
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
            reject(new Error('Домен не найден (не удалось определить)'));
          } else if (res.status === 429) {
            reject(new Error('Слишком много запросов, попробуйте позже'));
          } else {
            reject(new Error('HTTP ' + res.status));
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
          if (res.status !== 200) return finish(new Error('HTTP ' + res.status));
          consume(res.responseText || '');
          finish();
        },
        onerror() { finish(new Error('Ошибка сети при динамической проверке')); },
        ontimeout() { finish(new Error('Таймаут динамической проверки')); },
      });
    });
  }

  const STYLES = `
    :host { all: initial; }
    .box {
      position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
      max-width: 340px; padding: 10px 12px; border-radius: 8px;
      font: 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
      color: #fff; background: #374151; box-shadow: 0 4px 16px rgba(0,0,0,.35);
    }
    .box.ok { background: #15803d; }
    .box.bad { background: #b91c1c; }
    .box.warn { background: #b45309; }
    .box.err { background: #4b5563; }
    .title { font-weight: 600; padding-right: 18px; }
    .meta { margin-top: 4px; opacity: .9; font-size: 12px; }
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

  /** Плашка со статусом. kind: '' | 'ok' | 'bad' | 'warn' | 'err' */
  function showBadge(kind, title, meta, domain) {
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

  let running = false;

  async function runCheck() {
    if (running) return;
    const domain = currentDomain();
    if (!domain) return;
    running = true;
    showBadge('', 'Проверяю ' + domain + '…', 'Статическая проверка по спискам');
    try {
      const r = await fetchCheck(domain);
      const info = [];
      if (r.rkn_domain) info.push('Запись в реестре: ' + r.rkn_domain);
      if (r.blocked_subnets && r.blocked_subnets.length) {
        info.push('Заблокированные подсети: ' + r.blocked_subnets.length);
      }
      const cdns = Object.keys(r.cdn_providers || {});
      if (cdns.length) info.push('CDN: ' + cdns.join(', '));

      // Найден в списках — динамическая проверка не нужна.
      if (r.blocked) {
        showBadge('bad', '🚫 ' + domain + ': заблокирован',
          ['Найден в списках блокировок'].concat(info).join(' · '), domain);
        return;
      }
      if (!r.id) {
        showBadge('err', '⚠ ' + domain + ': динамическая проверка недоступна',
          'В списках не найден, но сервер не вернул id проверки', domain);
        return;
      }

      // Динамическая проверка сканерами: ждём все ответы и итоговый вердикт.
      showBadge('', 'Проверяю ' + domain + '…', 'Динамическая проверка: ожидаю сканеры…');
      const res = await runProbes(r.id, (probes, online) => {
        showBadge('', 'Проверяю ' + domain + '…',
          'Динамическая проверка: ответили ' + probes.length + (online ? ' из ' + online : '') + ' сканеров…');
      });

      const verdict = selectVerdict(res.probes, cdns.length > 0);
      const tail = [res.probes.length + (res.online ? ' из ' + res.online : '') + ' сканеров'].concat(info);
      if (!res.done) tail.push('проверка завершена не полностью');

      if (!verdict) {
        showBadge('err', '❔ ' + domain + ': вердикт не определён', tail.join(' · '), domain);
      } else {
        const v = VERDICTS[verdict];
        showBadge(v.kind, v.icon + ' ' + domain + ': ' + v.title, v.text + '. ' + tail.join(' · '), domain);
      }
    } catch (e) {
      showBadge('err', '⚠ Не удалось проверить ' + domain, e.message, domain);
    } finally {
      running = false;
    }
  }

  GM_registerMenuCommand('Проверить этот сайт на cheburcheck.ru', runCheck);
})();
