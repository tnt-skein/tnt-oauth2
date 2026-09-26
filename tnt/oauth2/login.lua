--- Вход через службу: начало и возврат по потоку с кодом (RFC 6749, §4.1).
---
--- Начало (`authorize`) заводит два одноразовых значения — `state`
--- и проверочный код PKCE, — кладёт их в сессию посетителя и отдаёт адрес
--- службы, куда его уводят. Возврат (`callback`) забирает их из сессии,
--- сверяет `state` и меняет код на токены, предъявляя проверочный код.
---
--- Почему так:
---
--- * **`state` в сессии, сверка за постоянное время** (RFC 9700, §2.1):
---   иначе посетителя, открывшего чужую ссылку возврата, ввели бы
---   в учётную запись того, кто её подсунул.
--- * **PKCE только `S256`** (RFC 7636): код, перехваченный по дороге,
---   без проверочного кода не меняется на токены.
--- * **Значения одноразовые.** Возврат забирает их из сессии до всякой
---   сверки, удачной или нет: второй возврат с тем же адресом — отказ,
---   а не второй вход.
--- * **Срок входа — пятнадцать минут** от начала: пароль, второй фактор
---   и согласие у службы в них укладываются, а ответ старше — чужой
---   или забытый.
--- * **Адрес возврата — ровно из настроек**, а не из заголовков запроса:
---   служба сверяет его точным совпадением, а заголовок `Host` пишет
---   тот, кто прислал запрос.
---
--- Ключ сессии — `oauth2.<имя службы>`: у двух служб свои входы, и вход
--- через одну не затирает начатый через другую.

local hash = require('tnt.hash')
local must = require('tnt.must')
local url = require('tnt.http.url')

local outside = require('tnt.oauth2.outside')
local endpoint = require('tnt.oauth2.endpoint')
local failure = require('tnt.oauth2.failure')
local secret = require('tnt.oauth2.secret')
local token = require('tnt.oauth2.token')

local Module = {}

--- Сколько секунд живёт начатый вход: пятнадцать минут.
Module.STATE_TTL = 15 * 60

--- Параметры адреса службы, которые ставит сам вход: их не перекрыть.
---@type table<string, boolean>
local RESERVED = {
    response_type = true,
    client_id = true,
    redirect_uri = true,
    scope = true,
    state = true,
    code_challenge = true,
    code_challenge_method = true,
}

--- Описание настроек начала входа.
local AUTHORIZE = {
    scopes = { '?array_of', 'not_empty' },
    params = '?table',
}

---@class TntOAuth2AuthorizeOptions Настройки одного начала входа
---@field scopes string[]|nil Права вместо тех, что в настройках клиента
---@field params table<string, string>|nil Свои параметры службы: prompt, login_hint, access_type…

---@class TntOAuth2Pending Начатый вход в сессии
---@field state string
---@field verifier string Проверочный код PKCE
---@field at number Миг начала, секунд эпохи

--- Ключ сессии, под которым лежит начатый вход.
---@param settings TntOAuth2Settings
---@return string
function Module.key(settings)
    return 'oauth2.' .. settings.name
end

--- Бросает, если вход через службу не настроен.
---@param settings TntOAuth2Settings
---@param action string Что просили
---@param level integer Уровень вины, как у `error`: 1 — эта функция
local function configured(settings, action, level)
    if settings.authorize_url == nil then
        error(('%s: у клиента %s нет authorize_url и redirect_uri'):format(action, settings.name), level)
    end
end

--- Параметры адреса службы для начала входа.
---@param settings TntOAuth2Settings
---@param options TntOAuth2AuthorizeOptions
---@param pending TntOAuth2Pending
---@param level integer
---@return table<string, any>
local function params_of(settings, options, pending, level)
    local params = {}

    for name, value in pairs(options.params or {}) do
        local label = ('настройки входа.params.%s'):format(tostring(name))

        if RESERVED[name] then
            error(('%s ставит сам вход'):format(label), level)
        end

        must.at(level).string(value, label)
        params[name] = value
    end

    local scopes = options.scopes or settings.scopes

    params.response_type = 'code'
    params.client_id = settings.client_id
    params.redirect_uri = settings.redirect_uri
    params.state = pending.state
    params.code_challenge = secret.challenge(pending.verifier)
    params.code_challenge_method = 'S256'

    if #scopes > 0 then
        params.scope = table.concat(scopes, ' ')
    end

    return params
end

--- Начинает вход: одноразовые значения в сессию, адрес службы — наружу.
---@param client table Клиент: `settings`
---@param session table Сессия посетителя: `put`
---@param options TntOAuth2AuthorizeOptions|nil
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return string address Куда увести посетителя
function Module.authorize(client, session, options, level)
    local settings = client.settings
    local caller = must.at(level)

    configured(settings, 'authorize', level + 1)
    caller.table(session, 'сессия')
    caller.optional.options(options, 'настройки входа', AUTHORIZE)

    local pending = { state = secret.fresh(), verifier = secret.fresh(), at = outside.now() }
    local params = params_of(settings, options or {}, pending, level + 1)

    session:put(Module.key(settings), pending)

    -- Параметры — строки, и собрать адрес из них можно всегда.
    local address = url.with_query(settings.authorize_url, params) --[[@as string]]

    return address
end

--- Начатый вход из сессии: забирается в любом исходе.
---@param settings TntOAuth2Settings
---@param session table
---@return TntOAuth2Pending|nil pending
---@return TntOAuth2Failure|nil
local function pending_of(settings, session)
    local pending = session:pull(Module.key(settings))

    -- Сессию пишет и драйвер в куке: вид начатого входа сверяется,
    -- а не принимается на веру.
    local whole = type(pending) == 'table'
        and type(pending.state) == 'string'
        and type(pending.verifier) == 'string'
        and type(pending.at) == 'number'

    if not whole then
        local message = ('вход через %s не начат: в сессии его нет'):format(settings.name)

        return nil, failure.new(failure.STATE, message)
    end

    local age = math.floor(outside.now() - pending.at)

    if age > Module.STATE_TTL then
        local message = ('вход через %s начат %d с назад — дольше %d с'):format(
            settings.name,
            age,
            Module.STATE_TTL
        )

        return nil, failure.new(failure.STATE, message)
    end

    return pending
end

--- Возврат от службы: сверка `state` и обмен кода на токены.
---@param client table Клиент: `settings` и `http`
---@param session table Сессия посетителя: `pull`
---@param query table<string, any> Параметры адреса возврата
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return TntOAuth2Grant|nil
---@return TntOAuth2Failure|nil
function Module.callback(client, session, query, level)
    local settings = client.settings
    local caller = must.at(level)

    configured(settings, 'callback', level + 1)
    caller.table(session, 'сессия')
    caller.table(query, 'параметры возврата')

    local pending, stale = pending_of(settings, session)

    if pending == nil then
        return nil, stale
    end

    if not hash.equals(pending.state, query.state) then
        return nil,
            failure.new(failure.STATE, 'ответ службы не к этому входу: state не совпал')
    end

    if query.error ~= nil then
        return nil, endpoint.refusal(failure.DENIED, 'служба отказала во входе', query, {})
    end

    if type(query.code) ~= 'string' or query.code == '' then
        return nil,
            failure.new(failure.MALFORMED, 'служба не прислала код в адресе возврата')
    end

    local form = {
        grant_type = 'authorization_code',
        code = query.code,
        redirect_uri = settings.redirect_uri,
        code_verifier = pending.verifier,
    }

    return token.ask(client, form, 'обмен кода', { query.code, pending.verifier })
end

return Module
