<div align="right">

**🇷🇺 Русский** · [🇬🇧 English](README.en.md)

</div>

# masterdns-zanoza-panel

Веб-панель и менеджер процессов для [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) с поддержкой приложения [Zanoza (iOS)](https://github.com/palmbeachpete9/masterdns-zanoza-ios).

Панель позволяет администратору создавать «инстансы» (комбинации **домен + ключ шифрования**) и раздавать их пользователям: каждый инстанс виден как `домен + ключ` и копируется как ссылка `zanoza://` для импорта в приложение Zanoza.

---

![Панель — список инстансов](docs/dashboard.png)

![Создание инстанса](docs/create-instance.png)

![Вход в панель](docs/login.png)

---

## Установка

Быстрая установка берёт текущую ветку `main` и после `git fetch` собирает
конкретный полученный коммит:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/masterdns-zanoza-panel/main/scripts/install.sh -o /tmp/zanoza-install.sh
sudo bash /tmp/zanoza-install.sh
```

Для воспроизводимой привилегированной установки закрепите проверенный полный
SHA коммита:

```sh
git clone https://github.com/palmbeachpete9/masterdns-zanoza-panel.git
cd masterdns-zanoza-panel
git checkout --detach <AUDITED_FULL_COMMIT_SHA>
sudo env ZANOZA_REF=<AUDITED_FULL_COMMIT_SHA> bash scripts/install.sh
```

Установщик (в стиле 3x-ui) спросит:

1. **Порт** — `Будет назначен случайный порт <порт>. Изменить? [y/N]:`
2. **Путь панели** — `Будет назначен путь панели /admin. Изменить? [y/N]:`
3. **Сертификат веб-панели**:
   - **1) IP-сертификат** — самоподписанный на IP сервера, срок 6 дней, автопродление (systemd-таймер).
   - **2) Доменный сертификат** Let's Encrypt — нужна A-запись `panel.example.com` → IP сервера.
   - **3) Без сертификата** — панель слушает **только** на `127.0.0.1` (внешний доступ через nginx/SSH-туннель).

Для TLS-терминирующего reverse proxy задайте при установке точный внешний
origin в `ZANOZA_EXTERNAL_ORIGIN` и IP/CIDR прокси в
`ZANOZA_TRUSTED_PROXIES`. Заголовок `X-Forwarded-For` принимается только от
доверенных прокси.

После установки генерируются **логин (10 символов)** и **пароль (20 символов)** и выводится полный адрес панели, в зависимости от выбора в п.1-3.

## Модель инстансов (домены + ключи)

Сервер MasterDnsVPN — это один процесс, слушающий **UDP :53**, с **одним** ключом и **одним** доменов. Чтобы раздавать пользователям **разные ключи**, панель использует форк сервера с **keyring** (`keyring.json`), который выбирает ключ(и) **по домену запроса** (домен виден до расшифровки):

- **Один ключ на домен** → прямая расшифровка, подходит **любой** метод, включая **XOR** (самый быстрый).
- **Несколько ключей на одном домене** → сервер перебирает ключи кольца; требуется **AEAD** (ChaCha20 / AES-GCM), потому что только AEAD позволяет отличить верный ключ по тегу аутентификации. Перебор идёт только на входящих пакетах этого домена; «горячий» ключ продвигается в начало кольца.

Метод шифрования инстанса должен **совпадать** с методом в приложении Zanoza (ссылка `zanoza://` задаёт его автоматически).

> **Важно!** Все домены инстансов (`v.example1.com`, `v.example2.com`, …) должны быть делегированы, и иметь:<br>
>**A-запись**, указывающую на IP адрес сервера с панелью<br>
>**NS-запись**, указывающую на A-запись.

## Управление: команда `zanoza`

```sh
zanoza              # интерактивное меню (как x-ui)
zanoza restart      # перезапустить панель
zanoza uninstall    # удалить панель
zanoza --help       # краткая справка
```

Меню умеет: показать адрес панели, сбросить логин/пароль, изменить порт/путь, перевыпустить сертификат, перезапуск, логи, обновление, удаление.

## Структура репозитория

```
masterdns-zanoza-panel/
├── src/main.tsx                  # React-интерфейс (Vite + Tailwind + lucide)
├── index.html, vite.config.ts, tailwind.config.ts, package.json
├── cmd/zanoza-panel/             # Go-бэкенд панели (stdlib)
│   ├── main.go                   #   HTTP/TLS, роутинг, API, embed web/dist
│   ├── config.go, auth.go        #   конфиг + авторизация (cookie/basic)
│   ├── process.go                #   супервизор сервера MasterDnsVPN + keyring.json
│   ├── zanozalink.go             #   генерация ссылок zanoza://
│   └── web/dist/                 #   собранный фронтенд (встроен в бинарник)
├── masterdns/                    # форк сервера MasterDnsVPN
│   └── internal/keyring/         #   выбор ключей по домену
├── scripts/install.sh, scripts/zanoza
└── packaging/systemd/zanoza-panel.service
```

## Переменные окружения

Все переменные опциональны; панель работает без них с дефолтными значениями.

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `ZANOZA_CONFIG` | Путь к JSON-конфигу панели | `/var/lib/zanoza-panel/config.json` |
| `ZANOZA_EXTERNAL_ORIGIN` | Точный внешний origin прокси | пусто |
| `ZANOZA_TRUSTED_PROXIES` | Список доверенных IP/CIDR прокси | пусто |
| `ZANOZA_RUNTIME_DIR` | Директория для keyring.json и server_config.toml | `<configDir>/masterdns` |
| `ZANOZA_PANEL_ADDR` | IP-адрес для HTTP-сервера | из `config.json` |
| `ZANOZA_PANEL_PORT` | Порт панели (1–65535) | из `config.json` |
| `ZANOZA_PANEL_PATH` | URL-путь админки (например `/secret`) | из `config.json` |
| `ZANOZA_TLS_CERT` / `ZANOZA_TLS_KEY` | Пути к TLS-сертификату и ключу | из `config.json` |
| `ZANOZA_NAME` | Имя сервера (отображается в UI) | из `config.json` |
| `ZANOZA_USER` / `ZANOZA_PASSWORD` | Авто-создание админа при первом запуске | — (только при первой настройке) |
| `ZANOZA_MASTERDNS_BIN` | Путь к бинарнику MasterDnsVPN | `/usr/local/bin/masterdns-server` |
| `ZANOZA_DNS_HOST` | UDP-адрес DNS-сервера | `0.0.0.0` |
| `ZANOZA_DNS_PORT` | UDP-порт DNS-сервера (1–65535) | `53` |
| `ZANOZA_DNS_UPSTREAM` | JSON-массив upstream-резолверов | `["1.1.1.1:53", "1.0.0.1:53"]` |

## Сборка из исходников

```sh
# инструменты (один раз)
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install mvdan.cc/gofumpt@latest

# фронтенд (нужен node)
npm install && npm run build

# всё через Makefile
make fmt      # форматирование gofumpt
make lint     # golangci-lint
make test     # тесты с -race
make build    # собрать бинарники
make check    # всё сразу (CI)
```

## Благодарности

- Протокол и сервер: [MasterDnsVPN от MasterkinG32](https://github.com/masterking32/MasterDnsVPN)
- UI и структура: [olcrtc-manager-panel](https://github.com/BigDaddy3334/olcrtc-manager-panel)
- Стиль установщика и CLI: [3x-ui](https://github.com/MHSanaei/3x-ui)
- Приложение-клиент: [Zanoza (iOS)](https://github.com/palmbeachpete9/masterdns-zanoza-ios)
