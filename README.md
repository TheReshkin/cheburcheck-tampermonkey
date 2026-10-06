# cheburcheck-tampermonkey

Tampermonkey userscript (>= 5.5.0) that checks whether the current site's
domain is in TSPU block lists using https://cheburcheck.ru/.

Status: work in progress (v0.1.0, manual check only).

## Установка

Нужен [Tampermonkey](https://www.tampermonkey.net/) 5.5.0 или новее.

**[Установить скрипт в один клик](https://raw.githubusercontent.com/TheReshkin/cheburcheck-tampermonkey/main/cheburcheck.user.js)**

Tampermonkey сам предложит установку при открытии raw-ссылки на `.user.js`.

## Использование

1. Откройте любой сайт.
2. Нажмите на иконку Tampermonkey и выберите **«Проверить этот сайт на cheburcheck.ru»**.
3. В правом нижнем углу появится плашка со статусом (заблокирован / не найден / ошибка).

При первом запуске Tampermonkey спросит разрешение на запросы к `cheburcheck.ru`
(`@connect`) — нужно разрешить.

## Приватность

Домен текущего сайта отправляется на cheburcheck.ru (`GET /api/v1/check?target=<домен>`),
сервис сохраняет историю проверок. Скрипт ничего не делает сам по себе, пока вы не
запустите проверку.

## Планы

- автоматическая проверка при открытии страницы;
- настройки (исключения, включение/выключение автозапуска).
