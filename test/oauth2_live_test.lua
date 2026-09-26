--- Клиент против настоящей службы OAuth 2.0.
---
--- Двойник показывает, что мы правильно разговариваем сами с собой.
--- Настоящая служба показывает, что нас понимает кто-то ещё: форма
--- и заголовок `Basic` в том виде, в каком их отправил libcurl, проверка
--- проверочного кода PKCE на той стороне, настоящие ответы точки
--- токенов и точки профиля.
---
--- Служба поднимается отдельно — `test/stand/oauth2.sh` (mock-oauth2-server
--- на 127.0.0.1:18480, вход без окна), — и если её нет, проверки честно
--- пропускаются: гейты не должны зависеть от докера.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.live')

--- Где стоит служба: тот же адрес, что поднимает скрипт стенда.
local HOST, PORT = '127.0.0.1', 18480

--- Адрес выдавшего на службе.
local SERVICE = ('http://%s:%d/default'):format(HOST, PORT)

--- Клиент службы стенда; проверка пропускается, если стенда нет.
---
--- Отдаётся без типа: проверки читают поля ответов, которые по типу
--- бывают и отказом.
---@return any
local function client_of()
    t.skip_if(not helper.listening(HOST, PORT), 'служба OAuth 2.0 не отвечает: test/stand/oauth2.sh')

    return helper.oauth2.new({
        name = 'mock',
        client_id = 'app',
        client_secret = 'secret',
        authorize_url = SERVICE .. '/authorize',
        token_url = SERVICE .. '/token',
        userinfo_url = SERVICE .. '/userinfo',
        redirect_uri = 'http://127.0.0.1:9/callback',
        scopes = { 'openid', 'profile' },
        profile = function(user)
            if type(user.sub) ~= 'string' then
                return nil, 'служба не назвала sub'
            end

            return { subject = user.sub, claims = { iss = user.iss } }
        end,
    })
end

--- Посетитель у службы: переход по её адресу без браузера.
---
--- Служба стенда входит без окна и сразу уводит на адрес возврата;
--- параметры этого адреса и есть то, с чем посетитель вернулся бы.
---@param client any
---@param address string
---@return table<string, string>
local function visit(client, address)
    local answer = assert(client.http:request({ method = 'GET', url = address }))

    t.assert_equals(answer.status, 302)

    return helper.query_of(answer.headers.location)
end

g.after_each(helper.restore)

g.test_a_visitor_logs_in_with_pkce_and_state = function()
    local client = client_of()
    local session = helper.session()
    local query = visit(client, client:authorize(session))
    local assertion, grant = client:finish(session, query)

    t.assert_equals(type(assertion), 'table', tostring(grant))
    t.assert_equals(assertion.provider, 'mock')
    t.assert_equals(type(assertion.subject), 'string')
    t.assert_equals(assertion.claims, { iss = SERVICE })
    t.assert_equals(grant.token_type, 'Bearer')
    t.assert_equals(type(grant.refresh_token), 'string')
    t.assert_equals(type(grant.extra.id_token), 'string')
    t.assert_gt(grant.expires_at, os.time())
end

g.test_a_code_under_another_verifier_is_rejected_by_the_service = function()
    local client = client_of()
    local session = helper.session()
    local query = visit(client, client:authorize(session))
    local pending = session.data['oauth2.mock']

    pending.verifier = pending.verifier:reverse()

    local grant, err = client:callback(session, query)

    t.assert_equals(grant, nil)
    t.assert_equals({ err.kind, err.code }, { 'rejected', 'invalid_grant' })
    t.assert_str_contains(err.message, 'обмен кода: служба ответила 400 — invalid_grant')
end

g.test_a_foreign_state_never_reaches_the_service = function()
    local client = client_of()
    local session = helper.session()
    local query = visit(client, client:authorize(session))

    query.state = query.state:reverse()

    local grant, err = client:callback(session, query)

    t.assert_equals(grant, nil)
    t.assert_equals(err.kind, 'state')
end

g.test_tokens_are_refreshed_and_kept_alive = function()
    local client = client_of()
    local session = helper.session()
    local _, grant = client:finish(session, visit(client, client:authorize(session)))
    local fresh = assert(client:refresh(grant.refresh_token))

    t.assert_not_equals(fresh.access_token, grant.access_token)

    local token = client:source({ grant = grant })

    t.assert_equals(token(), grant.access_token)
end

g.test_the_client_gets_its_own_tokens = function()
    local client = client_of()
    local grant = assert(client:credentials({ scopes = { 'mail' } }))
    local token = client:source({ credentials = true })

    t.assert_equals(grant.token_type, 'Bearer')
    t.assert_equals(type(token()), 'string')
end

g.test_a_foreign_token_is_refused_by_the_profile = function()
    local client = client_of()
    local userinfo, err = client:userinfo({ access_token = 'forged' })

    t.assert_equals(userinfo, nil)
    t.assert_equals({ err.kind, err.code }, { 'rejected', 'invalid_token' })
end
