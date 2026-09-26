--- Проверки всего возврата: токены, профиль и удостоверение.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.finish')

g.before_each(function()
    helper.clock(helper.NOW)
end)

g.after_each(helper.restore)

--- Параметры удачного возврата.
local RETURNED = { state = helper.STATE, code = 'code-1' }

--- Профиль службы.
local USER = helper.answer(200, '{"id":42,"login":"anna","email":"anna@example.org"}')

g.test_the_assertion_comes_from_the_profile = function()
    local client, asked = helper.client({ helper.tokens('"refresh_token":"rt-1"'), USER })
    local assertion, grant = client:finish(helper.started(), RETURNED)

    t.assert_equals(assertion, {
        provider = 'example',
        subject = '42',
        name = 'anna',
        methods = {},
        authenticated_at = helper.NOW,
        claims = { id = 42, login = 'anna', email = 'anna@example.org' },
    })
    t.assert_equals({ grant.access_token, grant.refresh_token }, { 'at-1', 'rt-1' })
    t.assert_equals(asked[2], {
        method = 'GET',
        url = helper.USERINFO,
        headers = { accept = 'application/json', authorization = 'Bearer at-1' },
    })
end

g.test_the_profile_sees_the_grant_and_names_its_claims_and_methods = function()
    local seen
    local client = helper.client({ helper.tokens('"user_id":"u-7"'), USER }, {
        profile = function(user, grant)
            seen = { user = user.login, grant = grant.extra.user_id }

            return { subject = grant.extra.user_id, methods = { 'pwd', 'otp' }, claims = { team = 'ops' } }
        end,
    })
    local assertion = client:finish(helper.started(), RETURNED)

    t.assert_equals(seen, { user = 'anna', grant = 'u-7' })
    t.assert_equals(
        { assertion.subject, assertion.name, assertion.methods, assertion.claims },
        { 'u-7', nil, { 'pwd', 'otp' }, { team = 'ops' } }
    )
end

g.test_without_a_profile_address_the_profile_gets_nothing = function()
    local client, asked = helper.client({ helper.tokens('"user":"u-9"') }, {
        userinfo_url = false,
        profile = function(user, grant)
            t.assert_equals(user, nil)

            return { subject = grant.extra.user }
        end,
    })
    local assertion = client:finish(helper.started(), RETURNED)

    t.assert_equals({ assertion.subject, assertion.claims }, { 'u-9', {} })
    t.assert_equals(#asked, 1)
end

g.test_an_empty_profile_is_refused = function()
    local client = helper.client({ helper.tokens(), USER, helper.tokens(), USER }, {
        profile = function(user)
            if user.login == 'anna' and user.email ~= nil then
                return nil, 'почта не подтверждена'
            end
        end,
    })
    local assertion, err = client:finish(helper.started(), RETURNED)

    helper.assert_refused(assertion, err, 'refused', 'профиль example: почта не подтверждена')

    client = helper.client({ helper.tokens(), USER }, {
        profile = function() end,
    })
    assertion, err = client:finish(helper.started(), RETURNED)
    helper.assert_refused(
        assertion,
        err,
        'refused',
        'профиль example: пользователь не назван'
    )
end

g.test_a_failed_step_ends_the_return = function()
    local client, asked = helper.client({ helper.answer(400, '{"error":"invalid_grant"}') })
    local assertion, err = client:finish(helper.started(), RETURNED)

    helper.assert_refused(
        assertion,
        err,
        'rejected',
        'обмен кода: служба ответила 400 — invalid_grant',
        'invalid_grant'
    )
    t.assert_equals(#asked, 1)

    client = helper.client({ helper.tokens(), helper.answer(401, '{"error":"invalid_token"}') })
    assertion, err = client:finish(helper.started(), RETURNED)
    helper.assert_refused(
        assertion,
        err,
        'rejected',
        'профиль: служба ответила 401 — invalid_token',
        'invalid_token'
    )

    client = helper.client({ helper.tokens(), helper.answer(200, '[{"id":1}]') })
    assertion, err = client:finish(helper.started(), RETURNED)
    helper.assert_refused(
        assertion,
        err,
        'malformed',
        'профиль: ответ не объект JSON — 10 байт'
    )
end

g.test_the_access_token_repeated_by_the_profile_is_hidden = function()
    local client = helper.client({
        helper.tokens(),
        helper.answer(403, '{"error":"insufficient_scope","error_description":"token at-1 lacks read:user"}'),
    })
    local _, err = client:finish(helper.started(), RETURNED)

    t.assert_equals(
        err.message,
        'профиль: служба ответила 403 — insufficient_scope: token [скрыто] lacks read:user'
    )
end

g.test_userinfo_alone_asks_the_profile_address = function()
    local client = helper.client({ USER })
    local userinfo = client:userinfo({ access_token = 'at-5' })

    t.assert_equals(userinfo.login, 'anna')

    local bare = helper.client({}, { userinfo_url = false })

    helper.assert_blamed({
        {
            function()
                bare:userinfo({ access_token = 'at-5' })
            end,
            'userinfo: у клиента example нет userinfo_url',
        },
        {
            function()
                client:userinfo('at-5')
            end,
            'токены — таблица, а не строка',
        },
        {
            function()
                client:userinfo({ access_token = '' })
            end,
            'токены.access_token — непустая строка, а не пустая',
        },
    })
end

g.test_a_wrong_profile_result_is_a_programmer_error = function()
    local cases = {
        { { id = '7' }, 'profile: ключа «id» нет, есть claims, methods, name, subject' },
        { { subject = 7 }, 'profile.subject — непустая строка, а не число' },
        { { subject = '' }, 'profile.subject — непустая строка, а не пустая' },
        { { subject = '7', name = 7 }, 'profile.name — строка, а не число' },
        { { subject = '7', methods = 'pwd' }, 'profile.methods — массив, а не строка' },
        { { subject = '7', claims = 'x' }, 'profile.claims — таблица, а не строка' },
        {
            { subject = 'a\nb' },
            'profile.subject — строка до 255 байт без управляющих знаков, а не «a\nb»',
        },
        { 'anna', 'profile — таблица, а не строка' },
    }

    for _, case in ipairs(cases) do
        local client = helper.client({ helper.tokens(), USER }, {
            profile = function()
                return case[1]
            end,
        })
        local ok, err = pcall(client.finish, client, helper.started(), RETURNED)

        t.assert_equals(ok, false)
        t.assert_str_contains(tostring(err), case[2])
    end
end

g.test_the_subject_is_up_to_255_bytes = function()
    local wide = string.rep('я', 128)

    local function finish_with(subject)
        local client = helper.client({ helper.tokens(), USER }, {
            profile = function()
                return { subject = subject }
            end,
        })

        return client:finish(helper.started(), RETURNED)
    end

    t.assert_equals(finish_with(string.rep('s', 255)).subject, string.rep('s', 255))

    helper.assert_blamed({
        {
            function()
                finish_with(string.rep('s', 256))
            end,
            ('profile.subject — строка до 255 байт без управляющих знаков, а не «%s…»'):format(
                string.rep('s', 40)
            ),
        },
    })

    local ok, err = pcall(finish_with, wide)

    t.assert_equals(ok, false)
    t.assert_str_contains(tostring(err), 'profile.subject — строка до 255 байт')
end

g.test_wrong_arguments_of_finish_blame_the_caller = function()
    local client = helper.client({})

    helper.assert_blamed({
        {
            function()
                client:finish(nil, RETURNED)
            end,
            'сессия — таблица, а не nil',
        },
        {
            function()
                client:finish(helper.started(), 'code=1')
            end,
            'параметры возврата — таблица, а не строка',
        },
    })
end

g.test_finish_needs_a_profile_function = function()
    local client = helper.client({ helper.tokens(), USER }, { profile = false })

    helper.assert_blamed({
        {
            function()
                client:finish(helper.started(), RETURNED)
            end,
            'finish: у клиента example нет profile — удостоверение собрать нечем',
        },
    })
end
