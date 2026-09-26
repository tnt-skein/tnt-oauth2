--- Клиент одной службы OAuth 2.0: вход, токены, поставщик токена.
---
--- Объект держит настройки и клиент HTTP и отвечает за всё, что делают
--- с одной службой: вход посетителя потоком с кодом (`authorize`,
--- `callback`, `userinfo`, `finish`), токены самого клиента
--- (`credentials`) и обновление (`refresh`), поставщика живого токена
--- (`source`).
---
--- Клиент HTTP — аргумент `http`. Без него собирается свой: без переходов
--- (переход 307 унёс бы тело с кодом и ключом клиента на другой адрес)
--- и с именем `tnt-oauth2` в `User-Agent`. Повторов POST у клиента HTTP
--- нет, и код не уйдёт к службе дважды.
---
--- Негодный аргумент — бросок на строке вызывающего; всё, что приходит
--- снаружи, — отказ парой `nil, err` (`tnt.oauth2.failure`).

local http = require('tnt.http')
local must = require('tnt.must')

local login = require('tnt.oauth2.login')
local profile = require('tnt.oauth2.profile')
local settings_of = require('tnt.oauth2.settings')
local source = require('tnt.oauth2.source')
local token = require('tnt.oauth2.token')

local Module = {}

--- Как клиент представляется службе.
Module.USER_AGENT = 'tnt-oauth2'

--- Описание настроек обновления и токенов клиента.
local SCOPED = { scopes = { '?array_of', 'not_empty' } }

--- Описание настроек поставщика.
local SOURCE = {
    grant = '?table',
    refresh_token = '?not_empty',
    credentials = '?boolean',
    scopes = { '?array_of', 'not_empty' },
}

---@class TntOAuth2ScopedOptions
---@field scopes string[]|nil Права вместо тех, что в настройках клиента

---@class TntOAuth2SourceOptions Откуда поставщик берёт токены: ровно одно из трёх
---@field grant TntOAuth2Grant|nil Токены после входа: обновлять их refresh_token
---@field refresh_token string|nil Токен обновления, сохранённый раньше
---@field credentials boolean|nil Токены самого клиента: client_credentials
---@field scopes string[]|nil Права токенов клиента

---@class TntOAuth2Client Клиент одной службы
---@field name string Имя службы
---@field settings TntOAuth2Settings
---@field http table Клиент HTTP
local Client = {}
Client.__index = Client

--- Права запроса: свои либо из настроек клиента, строкой через пробел.
---@param client TntOAuth2Client
---@param scopes string[]|nil
---@return string|nil
local function scope_of(client, scopes)
    local chosen = scopes or client.settings.scopes

    if #chosen == 0 then
        return nil
    end

    return table.concat(chosen, ' ')
end

--- Заводит клиент службы. В сеть не ходит.
---@param options TntOAuth2Options
---@return TntOAuth2Client
function Module.new(options)
    local settings = settings_of.check(options, 3)
    local transport = options.http or assert(http.new({ max_redirects = 0, user_agent = Module.USER_AGENT }))

    return setmetatable({ name = settings.name, settings = settings, http = transport }, Client)
end

--- Начинает вход посетителя: одноразовые значения — в сессию.
---@param session table Сессия посетителя: `put` и `pull`
---@param options TntOAuth2AuthorizeOptions|nil
---@return string address Куда увести посетителя: ответ 303 с `Location`
function Client:authorize(session, options)
    local address = login.authorize(self, session, options, 3)

    return address
end

--- Возврат от службы: сверка `state` и токены за код.
---@param session table Сессия посетителя
---@param query table<string, any> Параметры адреса возврата: `request.query`
---@return TntOAuth2Grant|nil
---@return TntOAuth2Failure|nil
function Client:callback(session, query)
    local grant, err = login.callback(self, session, query, 3)

    return grant, err
end

--- Профиль посетителя у точки профиля.
---@param grant TntOAuth2Grant
---@return table|nil userinfo
---@return TntOAuth2Failure|nil
function Client:userinfo(grant)
    local userinfo, err = profile.userinfo(self, grant, 3)

    return userinfo, err
end

--- Весь возврат: токены, профиль и удостоверение.
---@param session table Сессия посетителя
---@param query table<string, any> Параметры адреса возврата
---@return TntOAuth2Assertion|nil assertion
---@return TntOAuth2Failure|TntOAuth2Grant|nil err Отказ; при удаче — токены
function Client:finish(session, query)
    local grant, err = login.callback(self, session, query, 3)

    if grant == nil then
        return nil, err
    end

    local userinfo

    if self.settings.userinfo_url ~= nil then
        userinfo, err = profile.fetch(self, grant)

        if userinfo == nil then
            return nil, err
        end
    end

    local assertion, refused = profile.assertion(self, userinfo, grant, 3)

    if assertion == nil then
        return nil, refused
    end

    return assertion, grant
end

--- Новые токены по токену обновления (RFC 6749, §6).
---@param refresh_token string
---@param options TntOAuth2ScopedOptions|nil
---@return TntOAuth2Grant|nil
---@return TntOAuth2Failure|nil
function Client:refresh(refresh_token, options)
    local caller = must.at(2)

    caller.not_empty(refresh_token, 'токен обновления')
    caller.optional.options(options, 'настройки обновления', SCOPED)

    local form = {
        grant_type = 'refresh_token',
        refresh_token = refresh_token,
        scope = scope_of(self, (options or {}).scopes),
    }

    local grant, err = token.ask(self, form, 'обновление токена', { refresh_token })

    return grant, err
end

--- Токены самого клиента (RFC 6749, §4.4): вход службы, а не человека.
---@param options TntOAuth2ScopedOptions|nil
---@return TntOAuth2Grant|nil
---@return TntOAuth2Failure|nil
function Client:credentials(options)
    local caller = must.at(2)

    caller.optional.options(options, 'настройки токенов клиента', SCOPED)

    -- Вход по client_credentials — только у клиента с ключом (§4.4):
    -- публичному клиенту подтвердить себя нечем.
    if self.settings.client_secret == nil then
        error(('credentials: у клиента %s нет client_secret'):format(self.name), 2)
    end

    local form = { grant_type = 'client_credentials', scope = scope_of(self, (options or {}).scopes) }
    local grant, err = token.ask(self, form, 'токены клиента', {})

    return grant, err
end

--- Поставщик живого токена: функция без аргументов, токен либо отказ.
---@param options TntOAuth2SourceOptions
---@return fun(): string|nil, TntOAuth2Failure|nil
function Client:source(options)
    local caller = must.at(2)

    caller.options(options, 'настройки поставщика', SOURCE)

    local named = (options.grant and 1 or 0) + (options.refresh_token and 1 or 0) + (options.credentials and 1 or 0)

    if named ~= 1 then
        -- Текст — строкой выше, чтобы уровень вины стоял в одной строке
        -- с `error`: на отдельной строке генератор мутантов его не видит,
        -- и промах в уровне не поймала бы ни одна проверка.
        local complaint =
            'настройки поставщика: ровно одно из grant, refresh_token и credentials = true'

        error(complaint, 2)
    end

    if options.credentials then
        -- Промах виден при сборке поставщика, а не на первом токене посреди
        -- чужого вызова — там его бросок достался бы тому, кто шлёт письмо.
        if self.settings.client_secret == nil then
            error(('credentials: у клиента %s нет client_secret'):format(self.name), 2)
        end

        return source.new(function()
            return self:credentials({ scopes = options.scopes })
        end)
    end

    local first = options.grant
    local refresh_token = options.refresh_token

    if first ~= nil then
        caller.not_empty(first.access_token, 'настройки поставщика.grant.access_token')
        caller.not_empty(first.refresh_token, 'настройки поставщика.grant.refresh_token')
        caller.optional.number(first.expires_at, 'настройки поставщика.grant.expires_at')
        refresh_token = first.refresh_token
    end

    return source.new(function(held)
        -- Прежние токены несут свой токен обновления: служба могла его сменить.
        local chosen = held and held.refresh_token or refresh_token

        ---@cast chosen string
        local fresh, err = self:refresh(chosen)

        return fresh, err
    end, first)
end

return Module
