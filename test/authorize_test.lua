--- Проверки начала входа: адрес службы, одноразовые значения в сессии.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.authorize')

g.before_each(function()
    helper.clock(helper.NOW)
    helper.random()
end)

g.after_each(helper.restore)

g.test_the_address_carries_the_code_flow_with_pkce = function()
    local client, asked = helper.client({})
    local session = helper.session()
    local address = client:authorize(session)

    t.assert_equals(address:sub(1, #helper.AUTHORIZE + 1), helper.AUTHORIZE .. '?')
    t.assert_equals(helper.query_of(address), {
        response_type = 'code',
        client_id = helper.CLIENT_ID,
        redirect_uri = helper.REDIRECT,
        scope = 'read:user email',
        state = helper.STATE,
        code_challenge = helper.secret.challenge(helper.VERIFIER),
        code_challenge_method = 'S256',
    })
    t.assert_equals(session.data, {
        ['oauth2.example'] = { state = helper.STATE, verifier = helper.VERIFIER, at = helper.NOW },
    })
    t.assert_equals(#asked, 0, 'начало входа в сеть не ходит')
end

g.test_the_parameters_go_in_a_fixed_order_with_spaces_encoded = function()
    local client = helper.client({})
    local address = client:authorize(helper.session())

    t.assert_str_contains(address, '&redirect_uri=https%3A%2F%2Fapp.example.org%2Fauth%2Fexample%2Fcallback&')
    t.assert_str_contains(address, '&scope=read%3Auser%20email&')
    t.assert_equals(address:match('%?(.-)='), 'client_id')
end

g.test_the_challenge_is_s256_of_the_verifier = function()
    -- RFC 7636, приложение B.
    t.assert_equals(
        helper.secret.challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
        'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    )
end

g.test_fresh_values_are_43_characters_of_base64url = function()
    local asked = {}

    helper.substitute('random', function(length)
        table.insert(asked, length)

        return string.rep('\255', length)
    end)

    t.assert_equals(helper.secret.fresh(), string.rep('_', 42) .. '8')
    t.assert_equals(asked, { 32 })

    helper.restore()

    local value = helper.secret.fresh()

    t.assert_equals(#value, 43)
    t.assert_equals(value:find('[^%w_-]'), nil)
    t.assert_not_equals(helper.secret.fresh(), value)
end

g.test_each_start_brings_fresh_values_and_replaces_the_pending_one = function()
    local client = helper.client({})
    local session = helper.session()

    client:authorize(session)
    helper.clock(helper.NOW + 5)

    local address = client:authorize(session)
    local pending = session.data['oauth2.example']

    t.assert_equals(pending.at, helper.NOW + 5)
    t.assert_equals(helper.query_of(address).state, pending.state)
end

g.test_the_scopes_and_own_parameters_of_one_start = function()
    local client = helper.client({})
    local address = client:authorize(helper.session(), {
        scopes = { 'openid' },
        params = { prompt = 'consent', access_type = 'offline' },
    })
    local params = helper.query_of(address)

    t.assert_equals({ params.scope, params.prompt, params.access_type }, { 'openid', 'consent', 'offline' })
end

g.test_no_scopes_means_no_scope_parameter = function()
    local client = helper.client({}, { scopes = false })

    t.assert_equals(helper.query_of(client:authorize(helper.session())).scope, nil)
end

g.test_the_service_address_keeps_its_own_parameters = function()
    local client = helper.client({}, { authorize_url = 'https://id.example.org/authorize?tenant=7' })
    local address = client:authorize(helper.session())

    local head = 'https://id.example.org/authorize?tenant=7&client_id='

    t.assert_equals(address:sub(1, #head), head)
end

g.test_wrong_arguments_blame_the_caller = function()
    local client = helper.client({})
    local bare = helper.client({}, { authorize_url = false, redirect_uri = false })

    helper.assert_blamed({
        {
            function()
                bare:authorize(helper.session())
            end,
            'authorize: у клиента example нет authorize_url и redirect_uri',
        },
        {
            function()
                client:authorize(nil)
            end,
            'сессия — таблица, а не nil',
        },
        {
            function()
                client:authorize(helper.session(), { scope = { 'x' } })
            end,
            'настройки входа: ключа «scope» нет, есть params, scopes',
        },
        {
            function()
                client:authorize(helper.session(), { params = { state = 'mine' } })
            end,
            'настройки входа.params.state ставит сам вход',
        },
        {
            function()
                client:authorize(helper.session(), { params = { code_challenge_method = 'plain' } })
            end,
            'настройки входа.params.code_challenge_method ставит сам вход',
        },
        {
            function()
                client:authorize(helper.session(), { params = { max_age = 60 } })
            end,
            'настройки входа.params.max_age — строка, а не число',
        },
    })
end

g.test_no_parameter_of_the_start_itself_is_overridden = function()
    local client = helper.client({})
    local reserved = {
        'response_type',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'code_challenge',
        'code_challenge_method',
    }

    for _, name in ipairs(reserved) do
        local ok, err = pcall(client.authorize, client, helper.session(), { params = { [name] = 'x' } })

        t.assert_equals(ok, false, name)
        t.assert_str_contains(
            err,
            ('настройки входа.params.%s ставит сам вход'):format(name)
        )
    end
end

g.test_a_refused_start_leaves_the_session_alone = function()
    local client = helper.client({})
    local session = helper.session()

    pcall(client.authorize, client, session, { params = { redirect_uri = 'https://evil.example/' } })

    t.assert_equals(session.data, {})
end
