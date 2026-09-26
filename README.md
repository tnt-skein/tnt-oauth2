# tnt-oauth2

Клиент OAuth 2.0 для Tarantool: вход посетителя через чужую службу
потоком с кодом (RFC 6749, §4.1) с PKCE `S256` и `state` в сессии,
токены самого клиента, обновление и поставщик живого токена. Всё, что
пришло от службы негодным, — отказ парой с родом, а токены не попадают
ни в журнал, ни в текст отказа.

```lua
local oauth2 = require('tnt.oauth2')

local github = oauth2.new({
    name = 'github',
    client_id = os.getenv('GITHUB_CLIENT_ID'),
    client_secret = os.getenv('GITHUB_CLIENT_SECRET'),
    authorize_url = 'https://github.com/login/oauth/authorize',
    token_url = 'https://github.com/login/oauth/access_token',
    userinfo_url = 'https://api.github.com/user',
    redirect_uri = 'https://app.example.org/auth/github/callback',
    scopes = { 'read:user' },
    profile = function(user)
        return { subject = tostring(user.id), name = user.login }
    end,
})

local address = github:authorize(session)                  -- ответ 303 туда
local assertion, grant = github:finish(session, query)     -- удостоверение и токены либо nil, err
```

Зависимости: [`tnt-http`](https://github.com/tnt-skein/tnt-http) (запросы
к службе и кодирование адреса), [`tnt-hash`](https://github.com/tnt-skein/tnt-hash)
(вызов PKCE и сверка `state` за постоянное время),
[`tnt-must`](https://github.com/tnt-skein/tnt-must) (проверки аргументов),
[`tnt-clock`](https://github.com/tnt-skein/tnt-clock) (стенные часы сроков)
и [`tnt-external`](https://github.com/tnt-skein/tnt-external) (подмена часов
и случайных байтов в проверках).

## Зачем

Поток с кодом — пять шагов и два запроса, и каждый шаг, сделанный
«на глаз», открывает дверь. Пакет держит их в одном месте:

- **`state` в сессии и сверка за постоянное время** (RFC 9700, §2.1):
  ссылка возврата с чужим кодом не введёт посетителя в чужую учётную запись.
- **PKCE только `S256`** (RFC 7636): код, перехваченный по дороге,
  без проверочного кода на токены не меняется.
- **Начатый вход одноразовый и живёт пятнадцать минут**; адрес возврата —
  ровно из настроек, адреса службы — только `https://` (`http://` — только
  к `127.0.0.1` и `[::1]`).
- **Удостоверение собирает приложение.** OAuth 2.0 выдаёт доступ, а не
  личность: функция `profile` называет, кто вошёл, а пакет проверяет вид
  её ответа.
- **Токены — учётные данные.** Их нет в удостоверении, а из текста отказа
  они вычеркнуты, даже если служба повторила их в своей причине.
- **Поставщик живого токена** — функция, которая отдаёт токен и берёт
  новый за минуту до срока, одним обновлением на все файберы: так почта
  входит по XOAUTH2, а клиент чужого API ставит `Bearer`.

## Установка

```sh
tt rocks install tnt-oauth2 --server=https://tnt-skein.github.io/rocks
```

Или из исходников:

```sh
git clone https://github.com/tnt-skein/tnt-oauth2.git
cd tnt-oauth2 && tt rocks make
```

## Как пользоваться

| Действие | Что делает |
|---|---|
| `oauth2.new(настройки)` | клиент службы; в сеть не ходит, промах в настройках — бросок |
| `клиент:authorize(сессия[, { scopes, params }])` | начинает вход: `state` и проверочный код — в сессию, адрес службы — наружу |
| `клиент:finish(сессия, параметры)` | весь возврат: удостоверение и токены либо `nil, err` |
| `клиент:callback(сессия, параметры)` | только сверка `state` и токены за код |
| `клиент:userinfo(токены)` | профиль у точки профиля либо `nil, err` |
| `клиент:refresh(токен обновления[, { scopes }])` | новые токены |
| `клиент:credentials([{ scopes }])` | токены самого клиента (`client_credentials`) |
| `клиент:source({ grant \| refresh_token \| credentials = true })` | поставщик живого токена |

Сессия — любой объект посетителя с методами `put` и `pull`. Отказ —
таблица с родом `kind` (`state`, `denied`, `rejected`, `malformed`,
`unavailable`, `refused`), текстом `message` и кодом службы `code`:

```lua
local assertion, err = github:finish(session, { state = 'чужой', code = 'x' })
--> nil, ответ службы не к этому входу: state не совпал
err.kind
--> state

local token = github:source({ grant = grant })   -- функция: живой токен строкой либо nil, err
token()
```

## Проверки

```sh
make deps          # luatest, luacheck, luacov с cluacov и зависимости пакета в .rocks
make check         # форматирование, линт, проверки, покрытие с порогом 100 %
make mutants-all   # мутационное тестирование утилитой tnt-mutants из PATH, порог 100 % убитых
make oauth2-up     # mock-oauth2-server в докере для живых проверок; make oauth2-down гасит
```

Покрытие строк — 100 %, убитых мутантов — 100 % (78 проверок, из них
6 живых; 385 мутантов в десяти модулях; в фасаде мутировать нечего).
Служба в проверках — двойник клиента HTTP, который помнит, что ушло
к службе; вызов PKCE сверен с вектором RFC 7636, приложение B. Живые
проверки идут против mock-oauth2-server и без него пропускаются.

## Документ

Полное описание с обоснованием решений: [docs/oauth2.md](docs/oauth2.md).

## Лицензия

MIT.
