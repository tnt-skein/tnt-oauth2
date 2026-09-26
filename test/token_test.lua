--- Проверки точки токенов: обновление, токены клиента, разбор ответа.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.token')

g.before_each(function()
    helper.clock(helper.NOW)
end)

g.after_each(helper.restore)

g.test_refresh_keeps_the_old_refresh_token_when_the_service_sends_none = function()
    local client, asked = helper.client({ helper.tokens(), helper.tokens('"refresh_token":"rt-2"') })
    local kept = client:refresh('rt-1')
    local rotated = client:refresh('rt-1', { scopes = { 'email' } })

    t.assert_equals(kept.refresh_token, 'rt-1')
    t.assert_equals(rotated.refresh_token, 'rt-2')
    t.assert_equals(asked[1].form, { grant_type = 'refresh_token', refresh_token = 'rt-1', scope = 'read:user email' })
    t.assert_equals(asked[2].form.scope, 'email')
end

g.test_client_credentials_need_a_secret = function()
    local client, asked = helper.client({ helper.tokens() }, { scopes = false })
    local grant = client:credentials()

    t.assert_equals(grant.access_token, 'at-1')
    t.assert_equals(asked[1].form, { grant_type = 'client_credentials' })

    local public = helper.client({}, { client_secret = false })

    helper.assert_blamed({
        {
            function()
                public:credentials()
            end,
            'credentials: у клиента example нет client_secret',
        },
        {
            function()
                client:credentials({ scope = 'x' })
            end,
            'настройки токенов клиента: ключа «scope» нет, есть scopes',
        },
        {
            function()
                client:refresh('')
            end,
            'токен обновления — непустая строка, а не пустая',
        },
        {
            function()
                client:refresh('rt-1', { scopes = 'email' })
            end,
            'настройки обновления.scopes — массив, а не строка',
        },
    })
end

g.test_the_grant_keeps_other_fields_and_the_granted_scopes = function()
    local client = helper.client({
        helper.tokens('"scope":"email  profile","id_token":"eyJ","ext_expires_in":7200'),
    })
    local grant = client:refresh('rt-1')

    t.assert_equals(grant.scopes, { 'email', 'profile' })
    t.assert_equals(grant.extra, { id_token = 'eyJ', ext_expires_in = 7200 })
end

g.test_the_lifetime_is_a_moment_of_the_wall_clock = function()
    local client = helper.client({
        helper.answer(200, '{"access_token":"a","expires_in":"60"}'),
        helper.answer(200, '{"access_token":"a","token_type":"bearer","expires_in":0.5}'),
        helper.answer(200, '{"access_token":"a","token_type":"BEARER","expires_in":null}'),
    })

    t.assert_equals(client:refresh('rt').expires_at, helper.NOW + 60)
    t.assert_equals(client:refresh('rt').expires_at, helper.NOW + 0.5)
    t.assert_equals(client:refresh('rt').expires_at, nil)
end

g.test_a_response_out_of_protocol_is_malformed = function()
    local cases = {
        { '{"token_type":"Bearer"}', 'в ответе нет access_token строкой' },
        { '{"access_token":""}', 'в ответе нет access_token строкой' },
        { '{"access_token":7}', 'в ответе нет access_token строкой' },
        {
            '{"access_token":"a","token_type":"mac"}',
            'тип токена mac — клиент предъявляет только Bearer',
        },
        {
            '{"access_token":"a","token_type":1}',
            'тип токена 1 — клиент предъявляет только Bearer',
        },
        {
            '{"access_token":"a","expires_in":0}',
            'срок expires_in не число секунд больше нуля: 0',
        },
        {
            '{"access_token":"a","expires_in":-5}',
            'срок expires_in не число секунд больше нуля: -5',
        },
        {
            '{"access_token":"a","expires_in":1e400}',
            'срок expires_in не число секунд больше нуля: inf',
        },
        {
            '{"access_token":"a","expires_in":nan}',
            'срок expires_in не число секунд больше нуля: NaN',
        },
        {
            '{"access_token":"a","expires_in":"soon"}',
            'срок expires_in не число секунд больше нуля: «soon»',
        },
        {
            '{"access_token":"a","expires_in":[1]}',
            'срок expires_in не число секунд больше нуля: таблица',
        },
        { '{"access_token":"a","refresh_token":""}', 'refresh_token в ответе не строка' },
        { '{"access_token":"a","refresh_token":5}', 'refresh_token в ответе не строка' },
    }

    for _, case in ipairs(cases) do
        local client = helper.client({ helper.answer(200, case[1]) })
        local grant, err = client:refresh('rt')

        t.assert_equals(grant, nil, case[1])
        t.assert_equals(
            { err.kind, err.message },
            { 'malformed', 'обновление токена: ' .. case[2] },
            case[1]
        )
    end
end

g.test_a_body_that_is_not_a_json_object_is_malformed_and_not_shown = function()
    for _, body in ipairs({ 'access_token=at-9&token_type=bearer', '[1]', '{broken', '' }) do
        local client = helper.client({ helper.answer(200, body) })
        local _, err = client:refresh('rt')

        t.assert_equals(err.kind, 'malformed', body)
        t.assert_equals(
            err.message,
            ('обновление токена: ответ не объект JSON — %d байт'):format(#body),
            body
        )
    end

    local client = helper.client({ { status = 200, headers = {} } })
    local _, err = client:refresh('rt')

    t.assert_equals(err.message, 'обновление токена: ответ не объект JSON — 3 байт')
end

g.test_an_error_in_a_200_is_still_a_refusal = function()
    local client = helper.client({ helper.answer(200, '{"error":"bad_verification_code"}') })
    local grant, err = client:refresh('rt')

    helper.assert_refused(
        grant,
        err,
        'rejected',
        'обновление токена: служба ответила 200 — bad_verification_code',
        'bad_verification_code'
    )
end

g.test_a_busy_service_is_unavailable_and_other_codes_rejected = function()
    local cases = {
        { 408, 'unavailable' },
        { 429, 'unavailable' },
        { 499, 'rejected' },
        { 500, 'unavailable' },
        { 503, 'unavailable' },
        { 302, 'rejected' },
        { 404, 'rejected' },
        { 201, 'rejected' },
    }

    for _, case in ipairs(cases) do
        local client = helper.client({ helper.answer(case[1], '<html>занято</html>') })
        local _, err = client:refresh('rt')

        t.assert_equals(
            { err.kind, err.message },
            { case[2], ('обновление токена: служба ответила %d'):format(case[1]) },
            tostring(case[1])
        )
    end

    local client = helper.client({ helper.answer(503, '{"error":"temporarily_unavailable","error_description":"x"}') })
    local grant, err = client:refresh('rt')

    helper.assert_refused(
        grant,
        err,
        'unavailable',
        'обновление токена: служба ответила 503 — temporarily_unavailable: x',
        'temporarily_unavailable'
    )
end

g.test_an_error_without_a_code_names_only_the_status = function()
    local client = helper.client({
        helper.answer(401, '{"error":{"code":"InvalidAuthenticationToken"},"error_description":7}'),
        helper.answer(400, '{"error":null,"message":"x"}'),
    })
    local grant, err = client:refresh('rt')

    helper.assert_refused(
        grant,
        err,
        'rejected',
        'обновление токена: служба ответила 401'
    )

    grant, err = client:refresh('rt')
    helper.assert_refused(
        grant,
        err,
        'rejected',
        'обновление токена: служба ответила 400'
    )
end

g.test_no_answer_is_unavailable_with_the_reason_without_the_address = function()
    local client = helper.client({
        function()
            return nil,
                {
                    kind = 'unreachable',
                    reason = 'сервер не ответил: Timeout',
                    message = 'POST https://…',
                }
        end,
        function()
            return nil, 'обрыв rt-1'
        end,
    })
    local grant, err = client:refresh('rt-1')

    helper.assert_refused(
        grant,
        err,
        'unavailable',
        'обновление токена: служба не ответила: сервер не ответил: Timeout'
    )

    grant, err = client:refresh('rt-1')
    helper.assert_refused(
        grant,
        err,
        'unavailable',
        'обновление токена: служба не ответила: обрыв [скрыто]'
    )
end

g.test_the_reason_is_limited_and_has_no_control_characters = function()
    local long = string.rep('я', 150)
    local client = helper.client({
        helper.answer(400, ('{"error":"invalid_request","error_description":"%s"}'):format(long)),
    })
    local _, err = client:refresh('rt')

    t.assert_equals(
        err.message,
        'обновление токена: служба ответила 400 — invalid_request: '
            .. string.rep('я', 100)
    )
    t.assert_equals(helper.endpoint.scrubbed('a\tb\0c', {}), 'a.b.c')
    t.assert_equals(helper.endpoint.scrubbed('x%y.z', { '%y.' }), 'x[скрыто]z')
    t.assert_equals(
        helper.endpoint.scrubbed(string.rep('k', 199) .. 'secret', { 'secret' }),
        string.rep('k', 199) .. '['
    )
end
