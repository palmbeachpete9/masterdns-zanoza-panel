<div align="right">

**🇷🇺 Русский** · [🇬🇧 English](README.en.md)

</div>

# masterdns-zanoza-panel

Веб-панель и менеджер процессов для [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) с поддержкой приложения [Zanoza (iOS)](https://github.com/palmbeachpete9/masterdns-zanoza-ios).

Панель позволяет администратору создавать «инстансы» (комбинации **домен + ключ шифрования**) и раздавать их пользователям: каждый инстанс виден как `домен + ключ` и копируется как ссылка `zanoza://` для импорта в приложение Zanoza.

## Установка

Ubuntu / Debian VPS, от root:

```sh
curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/masterdns-zanoza-panel/main/scripts/install.sh | sudo bash
```

Установщик (в стиле 3x-ui) спросит:

1. **Порт** — `A random port will be assigned. Customise? y/N:`
2. **Путь панели** — `Path /admin will be assigned. Customise? y/N:`
3. **Сертификат веб-панели**:
   - **1) IP-сертификат** — self-signed на IP сервера, срок 6 дней, автопродление (systemd-таймер).
   - **2) Доменный сертификат** Let's Encrypt — нужна A-запись `panel.example.com` → IP сервера.
   - **3) Без сертификата** — панель слушает **только** на `127.0.0.1` (внешний доступ через nginx/SSH-туннель).

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
│   └── web/dist/                 #   собранный фронтенд (встроен в бинарь)
├── masterdns/                    # форк сервера MasterDnsVPN
│   └── internal/keyring/         #   покеольцевой выбор ключей по домену
├── scripts/install.sh, scripts/zanoza
└── packaging/systemd/zanoza-panel.service
```

## Сборка из исходников

```sh
# фронтенд -> cmd/zanoza-panel/web/dist (нужен node)
npm install && npm run build

# панель (встраивает web/dist)
go build -o zanoza-panel ./cmd/zanoza-panel

# форк сервера MasterDnsVPN
cd masterdns && go build -o masterdns-server ./cmd/server
```

## Благодарности

- Протокол и сервер: [MasterDnsVPN от MasterkinG32](https://github.com/masterking32/MasterDnsVPN)
- UI и структура: [olcrtc-manager-panel](https://github.com/BigDaddy3334/olcrtc-manager-panel)
- Стиль установщика и CLI: [3x-ui](https://github.com/MHSanaei/3x-ui)
- Приложение-клиент: [Zanoza (iOS)](https://github.com/palmbeachpete9/masterdns-zanoza-ios)
