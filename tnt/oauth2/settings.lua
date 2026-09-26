--- Настройки клиента OAuth 2.0: проверка при сборке.
---
--- Негодная настройка — ошибка программиста, и обнаружиться она обязана
--- при сборке клиента, а не на первом входе посетителя: бросок на строке
--- вызывающего `oauth2.new`.
---
--- Решения, которые держит проверка:
---
--- * **Адреса — только `https://`**, а `http://` — только к петле
---   `127.0.0.1` и `[::1]`. Точка токенов получает ключ клиента и код,
---   точка авторизации — `state`, и RFC 6749 требует TLS у обеих (§3.1,
---   §3.2); петля нужна стенду и проверкам. Имя `localhost` не годится:
---   его разрешает чужая настройка узла (RFC 8252, §8.3).
--- * **В адресе нет ни имени с паролем, ни `#`.** Адрес уходит в журнал
---   клиента HTTP, а ключ клиента задают `client_secret`; часть после
---   решётки на сервер не уходит вовсе (RFC 6749, §3.1, §3.1.2).
--- * **Вход через службу — `authorize_url` и `redirect_uri` вместе.**
---   Клиент только для токенов службы (`credentials`, `refresh`) обходится
---   без обоих, а половина пары — всегда промах.
--- * **Имя службы — строчная латиница**, цифры, `_`, `.`, `-`, с буквы,
---   до 64 знаков. По нему ветвятся правила приложения, и `GitHub`
---   с `github` разошлись бы по разным веткам.

local fail = require('tnt.must.fail')
local must = require('tnt.must')
local url = require('tnt.http.url')

local Module = {}

--- Самое длинное имя службы.
Module.MAX_NAME = 64

--- Как клиент подтверждает себя по умолчанию (RFC 6749, §2.3.1): этот
--- способ обязана понимать всякая служба.
Module.CLIENT_AUTH = 'client_secret_basic'

--- Описание настроек.
local OPTIONS = {
    name = 'not_empty',
    client_id = 'not_empty',
    client_secret = '?not_empty',
    client_auth = { '?one_of', { 'client_secret_basic', 'client_secret_post' } },
    token_url = 'not_empty',
    authorize_url = '?not_empty',
    redirect_uri = '?not_empty',
    userinfo_url = '?not_empty',
    scopes = { '?array_of', 'not_empty' },
    profile = '?callable',
    http = '?table',
}

--- Настройки-адреса в порядке проверки.
local ADDRESSES = { 'token_url', 'authorize_url', 'redirect_uri', 'userinfo_url' }

--- Имя службы: строчная буква, дальше строчные, цифры, `_`, `.` и `-`.
local NAME = '^%l[%l%d_.%-]*$'

--- Узлы, до которых годится `http://`: петля адресом, а не именем.
local LOOPBACK = { ['127.0.0.1'] = true, ['[::1]'] = true }

---@class TntOAuth2Options Настройки клиента
---@field name string Имя службы: `provider` удостоверения
---@field client_id string Опознаватель клиента у службы
---@field client_secret string|nil Ключ клиента; у публичного клиента его нет
---@field client_auth string|nil client_secret_basic (по умолчанию) либо client_secret_post
---@field token_url string Точка токенов
---@field authorize_url string|nil Точка авторизации: куда уводят посетителя
---@field redirect_uri string|nil Адрес возврата: точно тот, что записан у службы
---@field userinfo_url string|nil Точка профиля: кто вошёл
---@field scopes string[]|nil Права, которые просит вход
---@field profile (fun(userinfo: table|nil, grant: TntOAuth2Grant): table|nil, string|nil)|nil Удостоверение из профиля
---@field http table|nil Клиент `tnt-http` либо таблица с `request(opts)`

---@class TntOAuth2Settings Проверенные настройки
---@field name string
---@field client_id string
---@field client_secret string|nil
---@field client_auth string
---@field token_url string
---@field authorize_url string|nil
---@field redirect_uri string|nil
---@field userinfo_url string|nil
---@field scopes string[]
---@field profile function|nil

--- Бросает, если значение не по образцу.
---@param value string
---@param label string Как назвать значение в броске
---@param pattern string Образец Lua
---@param expected string Чего ждали — словами
---@param level integer Уровень вины, как у `error`: 1 — эта функция
local function shaped(value, label, pattern, expected, level)
    if value:find(pattern) == nil then
        error(fail.text(label, expected, fail.show(value)), level)
    end
end

--- Чем адрес службы не годится; `nil` — годится.
---
--- Текст без броска: адреса приходят и из настроек, где промах — бросок,
--- и из описания службы OpenID Connect, которое приходит по сети: там
--- это данные снаружи и отказ парой.
---@param value string
---@param label string Как назвать адрес в тексте
---@return string|nil
function Module.address_complaint(value, label)
    local scheme, authority, rest = url.split(value)

    if authority:find('@') ~= nil then
        -- Сам адрес не показывается: пароль из него уехал бы в журнал.
        return ('%s: имя и пароль в адресе не пишут — ключ клиента задают client_secret'):format(
            label
        )
    end

    if rest:find('#') ~= nil then
        return fail.text(label, 'адрес без «#»', fail.show(value))
    end

    -- Узел без порта: снимается двоеточие с цифрами на конце. Адрес IPv6
    -- кончается скобкой и остаётся целым, двоеточия внутри него не задеты.
    local host = authority:gsub(':%d*$', '')
    local kind = (scheme or ''):lower()

    if host == '' or not (kind == 'https' or kind == 'http' and LOOPBACK[host]) then
        return fail.text(
            label,
            'адрес https://, а http:// — только к 127.0.0.1 и [::1]',
            fail.show(value)
        )
    end

    return nil
end

--- Проверяет адрес службы.
---@param value string
---@param label string
---@param level integer Уровень вины, как у `error`: 1 — эта функция
function Module.address(value, label, level)
    local complaint = Module.address_complaint(value, label)

    if complaint ~= nil then
        error(complaint, level)
    end
end

--- Проверяет настройки и дополняет умолчаниями.
---@param options TntOAuth2Options
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return TntOAuth2Settings
function Module.check(options, level)
    local caller = must.at(level)

    caller.options(options, 'настройки', OPTIONS)
    shaped(
        options.name,
        'настройки.name',
        NAME,
        'строчная латиница, цифры, «_», «.» и «-», с буквы',
        level + 1
    )
    caller.length(options.name, 'настройки.name', 1, Module.MAX_NAME)

    -- Пустой client_id отвергнут описанием настроек, и искать осталось
    -- только управляющий знак. Образец `^%C+$` сверял бы заодно и
    -- непустоту, а пустое сюда не доходит: эту половину образца
    -- не проверила бы ни одна проверка.
    if options.client_id:find('%c') ~= nil then
        local complaint = fail.text(
            'настройки.client_id',
            'строка без управляющих знаков',
            fail.show(options.client_id)
        )

        error(complaint, level)
    end

    for index, scope in ipairs(options.scopes or {}) do
        local label = ('настройки.scopes[%d]'):format(index)

        shaped(
            scope,
            label,
            '^[^%c%s"\\]+$',
            'право без пробелов, кавычек и управляющих знаков',
            level + 1
        )
    end

    for _, key in ipairs(ADDRESSES) do
        if options[key] ~= nil then
            Module.address(options[key], 'настройки.' .. key, level + 1)
        end
    end

    if (options.authorize_url == nil) ~= (options.redirect_uri == nil) then
        error(
            'настройки: authorize_url и redirect_uri задают вместе — без одного из них вход не собрать',
            level
        )
    end

    if options.client_auth ~= nil and options.client_secret == nil then
        error(
            'настройки.client_auth без client_secret не действует: публичный клиент называет себя client_id',
            level
        )
    end

    return {
        name = options.name,
        client_id = options.client_id,
        client_secret = options.client_secret,
        client_auth = options.client_auth or Module.CLIENT_AUTH,
        token_url = options.token_url,
        authorize_url = options.authorize_url,
        redirect_uri = options.redirect_uri,
        userinfo_url = options.userinfo_url,
        scopes = table.copy(options.scopes or {}),
        profile = options.profile,
    }
end

return Module
