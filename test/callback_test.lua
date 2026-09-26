--- Проверки возврата от службы: state, отказ службы, обмен кода.

local digest = require('digest')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.callback')

g.before_each(function()
    helper.clock(helper.NOW)
end)

g.after_each(helper.restore)

--- Параметры удачного возврата.
local RETURNED = { state = helper.STATE, code = 'code-1' }

g.test_the_code_is_exchanged_with_the_verifier_and_basic_auth = function()
    local client, asked = helper.client({ helper.tokens('"refresh_token":"rt-1","scope":"read:user email"') })
    local session = helper.started()
    local grant, err = client:callback(session, RETURNED)

    t.assert_equals(err, nil)
    t.assert_equals(grant, {
        access_token = 'at-1',
        token_type = 'Bearer',
        expires_at = helper.NOW + 3600,
        refresh_token = 'rt-1',
        scopes = { 'read:user', 'email' },
        extra = {},
    })

    local call = asked[1]
    local pair = digest.base64_decode(call.headers.authorization:match('^Basic (.+)$'))

    t.assert_equals({ call.method, call.url }, { 'POST', helper.TOKEN })
    t.assert_equals(call.form, {
        grant_type = 'authorization_code',
        code = 'code-1',
        redirect_uri = helper.REDIRECT,
        code_verifier = helper.VERIFIER,
    })
    t.assert_equals(call.headers.accept, 'application/json')
    t.assert_equals(pair, 'app-7:s3cr3t%3Awith%2Fslash')
    t.assert_equals(session.data, {}, 'начатый вход забран')
end

g.test_a_long_basic_pair_stays_one_line = function()
    local secret = string.rep('k', 90)
    local client, asked = helper.client({ helper.tokens() }, { client_secret = secret })

    client:callback(helper.started(), RETURNED)

    local header = asked[1].headers.authorization

    t.assert_equals(
        header:find('[\r\n]'),
        nil,
        'перенос посреди заголовка — конец заголовка'
    )
    t.assert_equals(digest.base64_decode(header:match('^Basic (.+)$')), 'app-7:' .. secret)
end

g.test_the_secret_goes_in_the_form_on_request = function()
    local client, asked = helper.client({ helper.tokens() }, { client_auth = 'client_secret_post' })

    client:callback(helper.started(), RETURNED)

    t.assert_equals(asked[1].headers.authorization, nil)
    t.assert_equals(asked[1].form.client_id, helper.CLIENT_ID)
    t.assert_equals(asked[1].form.client_secret, helper.CLIENT_SECRET)
end

g.test_a_public_client_names_itself_in_the_form = function()
    local client, asked = helper.client({ helper.tokens() }, { client_secret = false })

    client:callback(helper.started(), RETURNED)

    t.assert_equals(asked[1].headers, { accept = 'application/json' })
    t.assert_equals(asked[1].form.client_id, helper.CLIENT_ID)
    t.assert_equals(asked[1].form.client_secret, nil)
end

g.test_a_start_that_is_not_in_the_session_is_refused = function()
    local client, asked = helper.client({})

    for _, stored in ipairs({
        {},
        { ['oauth2.example'] = 'broken' },
        { ['oauth2.example'] = { verifier = helper.VERIFIER, at = helper.NOW } },
        { ['oauth2.example'] = { state = helper.STATE, at = helper.NOW } },
        { ['oauth2.example'] = { state = helper.STATE, verifier = helper.VERIFIER } },
        { ['oauth2.other'] = { state = helper.STATE, verifier = helper.VERIFIER, at = helper.NOW } },
    }) do
        local grant, err = client:callback(helper.session(stored), RETURNED)

        helper.assert_refused(
            grant,
            err,
            'state',
            'вход через example не начат: в сессии его нет'
        )
    end

    t.assert_equals(#asked, 0)
end

g.test_a_start_lives_fifteen_minutes = function()
    local client = helper.client({ helper.tokens() })

    helper.clock(helper.NOW + 900)
    t.assert_not_equals(client:callback(helper.started(), RETURNED), nil)

    helper.clock(helper.NOW + 901.5)

    local grant, err = client:callback(helper.started(), RETURNED)

    helper.assert_refused(
        grant,
        err,
        'state',
        'вход через example начат 901 с назад — дольше 900 с'
    )
end

g.test_a_foreign_or_missing_state_is_refused_and_the_start_is_gone = function()
    local client, asked = helper.client({})

    for _, query in ipairs({
        { state = helper.STATE:sub(1, -2) .. 'A', code = 'code-1' },
        { code = 'code-1' },
        { state = { helper.STATE, helper.STATE }, code = 'code-1' },
    }) do
        local session = helper.started()
        local grant, err = client:callback(session, query)

        helper.assert_refused(
            grant,
            err,
            'state',
            'ответ службы не к этому входу: state не совпал'
        )
        t.assert_equals(session.data, {}, 'второй возврат с тем же адресом — не вход')
    end

    t.assert_equals(#asked, 0)
end

g.test_the_second_return_with_the_same_address_is_refused = function()
    local client = helper.client({ helper.tokens() })
    local session = helper.started()

    t.assert_not_equals(client:callback(session, RETURNED), nil)

    local grant, err = client:callback(session, RETURNED)

    helper.assert_refused(
        grant,
        err,
        'state',
        'вход через example не начат: в сессии его нет'
    )
end

g.test_a_refusal_of_the_service_is_denied_with_its_code = function()
    local client, asked = helper.client({})
    local grant, err = client:callback(helper.started(), {
        state = helper.STATE,
        error = 'access_denied',
        error_description = 'The user said\nno',
    })

    helper.assert_refused(
        grant,
        err,
        'denied',
        'служба отказала во входе — access_denied: The user said.no',
        'access_denied'
    )

    grant, err = client:callback(helper.started(), { state = helper.STATE, error = { 'a', 'b' } })

    helper.assert_refused(grant, err, 'denied', 'служба отказала во входе')
    t.assert_equals(#asked, 0)
end

g.test_a_return_without_a_code_is_malformed = function()
    local client = helper.client({})

    for _, code in ipairs({ box.NULL, '', 42 }) do
        local grant, err = client:callback(helper.started(), { state = helper.STATE, code = code })

        helper.assert_refused(
            grant,
            err,
            'malformed',
            'служба не прислала код в адресе возврата'
        )
    end
end

g.test_a_code_under_another_verifier_is_rejected = function()
    local client = helper.client({
        helper.answer(
            400,
            '{"error":"invalid_grant","error_description":"code_verifier does not compute to code_challenge"}'
        ),
    })
    local grant, err = client:callback(helper.started(), RETURNED)

    helper.assert_refused(
        grant,
        err,
        'rejected',
        'обмен кода: служба ответила 400 — invalid_grant: code_verifier does not compute to code_challenge',
        'invalid_grant'
    )
end

g.test_the_secrets_repeated_by_the_service_are_hidden = function()
    local description = ('code %s with verifier %s for s3cr3t:with/slash'):format('code-1', helper.VERIFIER)
    local client = helper.client({
        helper.answer(401, ('{"error":"invalid_client","error_description":"%s"}'):format(description)),
    })
    local _, err = client:callback(helper.started(), RETURNED)

    t.assert_equals(
        err.message,
        'обмен кода: служба ответила 401 — invalid_client: code [скрыто] with verifier [скрыто] for [скрыто]'
    )
end

g.test_wrong_arguments_blame_the_caller = function()
    local client = helper.client({})
    local bare = helper.client({}, { authorize_url = false, redirect_uri = false })

    helper.assert_blamed({
        {
            function()
                bare:callback(helper.started(), RETURNED)
            end,
            'callback: у клиента example нет authorize_url и redirect_uri',
        },
        {
            function()
                client:callback(nil, RETURNED)
            end,
            'сессия — таблица, а не nil',
        },
        {
            function()
                client:callback(helper.started(), 'code=1')
            end,
            'параметры возврата — таблица, а не строка',
        },
    })
end
