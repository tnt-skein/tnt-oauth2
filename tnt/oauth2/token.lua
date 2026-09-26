--- Точка токенов: обмен кода, обновление и токен самого клиента.
---
--- Три запроса одного вида (RFC 6749, §4.1.3, §6, §4.4.2): форма POST
--- с `grant_type`, подпись клиента и ответ с токеном. Ответ становится
--- записью `TntOAuth2Grant`.
---
--- * **Клиент подтверждает себя заголовком `Basic`** (`client_secret_basic`,
---   §2.3.1): этот способ обязана понимать всякая служба. Имя и ключ перед
---   склейкой кодируются как в форме — так велит тот же параграф, и ключ
---   с двоеточием иначе разрезался бы не там. `client_secret_post` кладёт
---   их в тело; публичный клиент без ключа называет себя `client_id`
---   в теле (§4.1.3).
--- * **Переходов нет, повторов у POST нет.** Код годится один раз,
---   а переход 307 унёс бы тело с ключом клиента на другой адрес; ответ
---   3xx — отказ. Клиент HTTP по умолчанию собран без переходов,
---   а POST он не повторяет никогда.
--- * **Токен — только Bearer** (RFC 6750). Токен другого типа клиент
---   предъявить не умеет, и RFC 6749 (§7.1) запрещает им пользоваться.
---   Тип, которого служба не назвала, считается Bearer: так отвечают
---   службы, забывшие обязательное поле, а токен у них — Bearer.
--- * **Срок — мигом стенных часов** (`expires_at`): `expires_in` отсчитан
---   от ответа, и сверять его удобно с часами, а не с длительностью.
---   Служба, приславшая срок строкой с числом, понята; срок не числом
---   больше нуля — отказ `malformed`: бесконечный срок сделал бы токен
---   вечным, а `json.decode` читает `1e400` именно бесконечностью.
--- * **Токен обновления остаётся прежним**, если служба не прислала
---   нового (§6): иначе первое же обновление теряло бы право на второе.

local digest = require('digest')

local fail = require('tnt.must.fail')

local outside = require('tnt.oauth2.outside')
local endpoint = require('tnt.oauth2.endpoint')
local failure = require('tnt.oauth2.failure')
local url = require('tnt.http.url')

local Module = {}

--- Тип токена, который клиент умеет предъявить (RFC 6750).
Module.BEARER = 'Bearer'

--- Поля ответа, которые разбирает сам пакет; остальные — в `extra`.
---@type table<string, boolean>
local KNOWN = {
    access_token = true,
    token_type = true,
    expires_in = true,
    refresh_token = true,
    scope = true,
}

---@class TntOAuth2Grant Токены от службы
---@field access_token string Токен доступа — учётные данные: не в журнал
---@field token_type string Всегда Bearer
---@field expires_at number|nil Миг, до которого токен годен, секунд эпохи; служба не назвала — nil
---@field refresh_token string|nil Токен обновления — учётные данные: не в журнал
---@field scopes string[]|nil Права, которые дала служба; не назвала — те, что просили
---@field extra table<string, any> Прочие поля ответа: `id_token` OpenID Connect и своё службы

--- Подписывает запрос именем клиента (RFC 6749, §2.3.1).
---@param settings TntOAuth2Settings
---@param form table<string, any>
---@param headers table<string, string>
local function signed(settings, form, headers)
    if settings.client_secret == nil or settings.client_auth == 'client_secret_post' then
        form.client_id = settings.client_id
        form.client_secret = settings.client_secret

        return
    end

    local pair = url.encode(settings.client_id) .. ':' .. url.encode(settings.client_secret)

    headers.authorization = 'Basic ' .. digest.base64_encode(pair, { nowrap = true })
end

--- Срок токена секундами либо пустота; отказ — текстом.
---@param value any
---@return number|nil seconds
---@return string|nil complaint
local function lifetime_of(value)
    if value == nil then
        return nil
    end

    -- Число и строку с числом читает одно `tonumber`; прочее даёт пустоту.
    local seconds = tonumber(value)

    -- NaN не больше нуля, а бесконечность не меньше самой себя.
    if seconds == nil or not (seconds > 0 and seconds < math.huge) then
        return nil,
            ('срок expires_in не число секунд больше нуля: %s'):format(fail.show(value))
    end

    return seconds
end

--- Токены из ответа службы.
---@param object table Ответ — объект JSON без поля `error`
---@param previous string|nil Токен обновления, с которым просили
---@return TntOAuth2Grant|nil
---@return string|nil complaint Чем ответ не годится
local function grant_of(object, previous)
    if type(object.access_token) ~= 'string' or object.access_token == '' then
        return nil, 'в ответе нет access_token строкой'
    end

    local kind = object.token_type

    if kind ~= nil and (type(kind) ~= 'string' or kind:lower() ~= 'bearer') then
        return nil,
            ('тип токена %s — клиент предъявляет только Bearer'):format(
                tostring(kind)
            )
    end

    local seconds, wrong = lifetime_of(object.expires_in)

    if wrong ~= nil then
        return nil, wrong
    end

    local refresh = object.refresh_token

    if refresh ~= nil and (type(refresh) ~= 'string' or refresh == '') then
        return nil, 'refresh_token в ответе не строка'
    end

    local scopes

    if type(object.scope) == 'string' then
        scopes = object.scope:split()
    end

    local extra = {}

    for name, value in pairs(object) do
        if not KNOWN[name] then
            extra[name] = value
        end
    end

    return {
        access_token = object.access_token,
        token_type = Module.BEARER,
        expires_at = seconds and outside.now() + seconds,
        refresh_token = refresh or previous,
        scopes = scopes,
        extra = extra,
    }
end

--- Просит токены у службы.
---@param client table Клиент: `settings` и `http`
---@param form table<string, any> Тело: `grant_type` и его поля
---@param step string Что делали — начало текста отказа
---@param secrets string[] Тайны этого запроса, кроме ключа клиента
---@return TntOAuth2Grant|nil
---@return TntOAuth2Failure|nil
function Module.ask(client, form, step, secrets)
    local settings = client.settings
    local headers = { accept = 'application/json' }

    signed(settings, form, headers)
    table.insert(secrets, settings.client_secret)

    local call = { method = 'POST', url = settings.token_url, form = form, headers = headers }
    local object, err = endpoint.call(client.http, call, step, secrets)

    if object == nil then
        return nil, err
    end

    local grant, complaint = grant_of(object, form.refresh_token)

    if grant == nil then
        return nil, failure.new(failure.MALFORMED, ('%s: %s'):format(step, complaint))
    end

    return grant
end

return Module
