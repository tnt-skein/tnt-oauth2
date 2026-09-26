--- Кто вошёл: профиль службы и удостоверение из него.
---
--- OAuth 2.0 выдаёт доступ, а не личность: токен говорит, что можно,
--- но не кто это. Стандартного ответа «кто это» у OAuth 2.0 нет, и какое
--- поле у службы постоянно (`id`, а не почта), знает только тот, кто её
--- подключает. Поэтому удостоверение собирает функция приложения
--- `profile(userinfo, grant)` из ответа точки профиля, а пакет только
--- спрашивает и проверяет.
---
--- `profile` отдаёт `{ subject, name, methods, claims }` либо `nil, причина`:
--- пустота — служба ответила, а пользователя в ответе не узнать, это отказ
--- `refused`. Поля закрыты, а их вид сверяется: негодное — бросок,
--- потому что `profile` пишет программист, и данные службы он обязан
--- проверить сам. `subject` числом лёг бы в журнал аудита исключением box,
--- а поле `id` вместо `subject` ехало бы молча до первой проверки прав.
---
--- Удостоверение: `provider` — имя службы из настроек, `issuer` — пусто
--- (у OAuth 2.0 выдавшего нет; ключ учётной записи у приложения — пара
--- `provider` и `subject`), `methods` — что назвала `profile`, иначе пусто
--- («неизвестно», RFC 8176), `authenticated_at` — миг ответа службы,
--- `claims` — что назвала `profile`, иначе весь профиль. Токенов в нём нет:
--- удостоверение идёт в поиск учётной записи и в журнал, а токены —
--- учётные данные.

local fail = require('tnt.must.fail')
local must = require('tnt.must')

local outside = require('tnt.oauth2.outside')
local endpoint = require('tnt.oauth2.endpoint')
local failure = require('tnt.oauth2.failure')

local Module = {}

--- Самый длинный `subject`, байтов: предел `sub` OpenID Connect.
Module.MAX_SUBJECT = 255

--- Описание того, что отдаёт `profile`.
local FOUND = {
    subject = 'not_empty',
    name = '?string',
    methods = { '?array_of', 'not_empty' },
    claims = '?table',
}

---@class TntOAuth2Assertion Удостоверение: кто вошёл, через какую службу и когда
---@field provider string Источник: имя службы из настроек
---@field issuer string|nil Кто выдал: у OAuth 2.0 — пусто
---@field subject string Кто это у службы: 1…255 байт без управляющих знаков
---@field name string|nil Как служба его называет
---@field methods string[] Чем доказано; пусто — неизвестно
---@field authenticated_at number Когда доказано, секунд эпохи
---@field expires_at number|nil До какого мига годно
---@field claims table Что ещё сказала служба

--- Профиль у точки профиля: объект JSON либо отказ.
---@param client table Клиент: `settings` и `http`
---@param grant TntOAuth2Grant
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return table|nil userinfo
---@return TntOAuth2Failure|nil
function Module.userinfo(client, grant, level)
    local settings = client.settings
    local caller = must.at(level)

    if settings.userinfo_url == nil then
        error(('userinfo: у клиента %s нет userinfo_url'):format(settings.name), level)
    end

    caller.table(grant, 'токены')
    caller.not_empty(grant.access_token, 'токены.access_token')

    return Module.fetch(client, grant)
end

--- Профиль по токенам, которые уже проверены: их отдал обмен кода.
---@param client table Клиент: `settings` и `http`
---@param grant TntOAuth2Grant
---@return table|nil userinfo
---@return TntOAuth2Failure|nil
function Module.fetch(client, grant)
    local call = {
        method = 'GET',
        url = client.settings.userinfo_url,
        headers = { accept = 'application/json', authorization = 'Bearer ' .. grant.access_token },
    }

    return endpoint.call(client.http, call, 'профиль', { grant.access_token })
end

--- Удостоверение по профилю: функция приложения и проверка её ответа.
---@param client table Клиент: `settings`
---@param userinfo table|nil Профиль; у службы без точки профиля — пусто
---@param grant TntOAuth2Grant
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return TntOAuth2Assertion|nil
---@return TntOAuth2Failure|nil
function Module.assertion(client, userinfo, grant, level)
    local settings = client.settings

    if settings.profile == nil then
        error(
            ('finish: у клиента %s нет profile — удостоверение собрать нечем'):format(
                settings.name
            ),
            level
        )
    end

    local found, reason = settings.profile(userinfo, grant)

    if found == nil then
        local message = ('профиль %s: %s'):format(
            settings.name,
            tostring(reason or 'пользователь не назван')
        )

        return nil, failure.new(failure.REFUSED, message)
    end

    must.at(level).options(found, 'profile', FOUND)

    -- Предел — в байтах, а не в знаках: так его считают хранилища,
    -- куда `subject` ляжет ключом.
    if #found.subject > Module.MAX_SUBJECT or found.subject:find('%c') ~= nil then
        local expected = ('строка до %d байт без управляющих знаков'):format(
            Module.MAX_SUBJECT
        )

        error(fail.text('profile.subject', expected, fail.show(found.subject)), level)
    end

    return {
        provider = settings.name,
        subject = found.subject,
        name = found.name,
        methods = found.methods or {},
        authenticated_at = outside.now(),
        claims = found.claims or userinfo or {},
    }
end

return Module
