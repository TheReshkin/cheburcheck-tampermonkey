// ==UserScript==
// @name         Cheburcheck: проверка сайта в списках ТСПУ
// @namespace    https://github.com/TheReshkin/cheburcheck-tampermonkey
// @version      0.1.0
// @description  Проверяет, есть ли домен текущего сайта в списках блокировок, через https://cheburcheck.ru/ (запуск вручную из меню Tampermonkey).
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
  const SITE = 'https://cheburcheck.ru/check?target=';
  const HOST_ID = 'cheburcheck-tm-badge';

  /** Домен текущей страницы без ведущего "www." */
  function currentDomain() {
    return location.hostname.replace(/^www\./i, '').toLowerCase();
  }

  /** Запрос к API cheburcheck.ru (тот же, что делает сайт: GET /api/v1/check?target=...). */
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

  const STYLES = `
    :host { all: initial; }
    .box {
      position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
      max-width: 320px; padding: 10px 12px; border-radius: 8px;
      font: 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
      color: #fff; background: #374151; box-shadow: 0 4px 16px rgba(0,0,0,.35);
    }
    .box.ok { background: #15803d; }
    .box.bad { background: #b91c1c; }
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

  /** Плашка со статусом. kind: '' | 'ok' | 'bad' | 'err' */
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

  async function runCheck() {
    const domain = currentDomain();
    if (!domain) return;
    showBadge('', 'Проверяю ' + domain + '…');
    try {
      const r = await fetchCheck(domain);
      const parts = [];
      if (r.rkn_domain) parts.push('Запись в реестре: ' + r.rkn_domain);
      if (r.blocked_subnets && r.blocked_subnets.length) {
        parts.push('Заблокированные подсети: ' + r.blocked_subnets.length);
      }
      const cdns = Object.keys(r.cdn_providers || {});
      if (cdns.length) parts.push('CDN: ' + cdns.join(', '));
      if (r.whitelist) parts.push('Есть в белом списке');

      if (r.blocked) {
        showBadge('bad', '🚫 ' + domain + ': заблокирован', parts.join(' · '), domain);
      } else {
        showBadge('ok', '✅ ' + domain + ': в списках блокировок не найден', parts.join(' · '), domain);
      }
    } catch (e) {
      showBadge('err', '⚠ Не удалось проверить ' + domain, e.message, domain);
    }
  }

  GM_registerMenuCommand('Проверить этот сайт на cheburcheck.ru', runCheck);
})();
