--- Проверки настроек клиента: имя, адреса, пара входа, способ подписи.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local oauth2 = helper.oauth2

local g = t.group('tnt.oauth2.settings')

g.after_each(helper.restore)

g.test_the_client_keeps_checked_settings_with_defaults = function()
    local client = helper.oauth2.new(helper.options({ userinfo_url = false, scopes = false, profile = false }))

    t.assert_equals(client.name, 'example')
    t.assert_equals(client.settings, {
        name = 'example',
        client_id = helper.CLIENT_ID,
        client_secret = helper.CLIENT_SECRET,
        client_auth = 'client_secret_basic',
        token_url = helper.TOKEN,
        authorize_url = helper.AUTHORIZE,
        redirect_uri = helper.REDIRECT,
        scopes = {},
    })
end

g.test_the_scopes_are_copied_and_not_shared_with_the_caller = function()
    local scopes = { 'email' }
    local client = oauth2.new(helper.options({ scopes = scopes }))

    table.insert(scopes, 'admin')

    t.assert_equals(client.settings.scopes, { 'email' })
end

g.test_without_a_client_the_package_builds_one_without_redirects = function()
    local client = oauth2.new(helper.options())
    local status = client.http:status()

    t.assert_equals({ status.max_redirects, status.user_agent }, { 0, 'tnt-oauth2' })
end

g.test_a_given_http_client_is_taken_as_is = function()
    local http = helper.http({})
    local client = oauth2.new(helper.options({ http = http }))

    t.assert_is(client.http, http)
end

g.test_names_follow_the_identity_contract = function()
    for _, name in ipairs({ 'a', 'github', 'my-idp', 'corp.sso', 'idp_2' }) do
        t.assert_equals(oauth2.new(helper.options({ name = name })).name, name)
    end

    t.assert_equals(oauth2.new(helper.options({ name = string.rep('a', 64) })).name, string.rep('a', 64))

    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ name = 'GitHub' }))
            end,
            'настройки.name — строчная латиница, цифры, «_», «.» и «-», с буквы, а не «GitHub»',
        },
        {
            function()
                oauth2.new(helper.options({ name = '2fa' }))
            end,
            'настройки.name — строчная латиница, цифры, «_», «.» и «-», с буквы, а не «2fa»',
        },
        {
            function()
                oauth2.new(helper.options({ name = 'my idp' }))
            end,
            'настройки.name — строчная латиница, цифры, «_», «.» и «-», с буквы, а не «my idp»',
        },
        {
            function()
                oauth2.new(helper.options({ name = string.rep('a', 65) }))
            end,
            'настройки.name — строка длиной от 1 до 64 знаков, а не 65',
        },
    })
end

g.test_the_client_id_and_scopes_have_no_control_characters = function()
    t.assert_equals(oauth2.new(helper.options({ client_id = 'my app ~' })).settings.client_id, 'my app ~')
    t.assert_equals(oauth2.new(helper.options({ scopes = { 'a!#[]~' } })).settings.scopes, { 'a!#[]~' })

    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ client_id = 'app\n7' }))
            end,
            'настройки.client_id — строка без управляющих знаков, а не «app\n7»',
        },
        {
            function()
                oauth2.new(helper.options({ scopes = { 'email', 'read user' } }))
            end,
            'настройки.scopes[2] — право без пробелов, кавычек и управляющих знаков, а не «read user»',
        },
        {
            function()
                oauth2.new(helper.options({ scopes = { 'a"b' } }))
            end,
            'настройки.scopes[1] — право без пробелов, кавычек и управляющих знаков, а не «a"b»',
        },
        {
            function()
                oauth2.new(helper.options({ scopes = { 'a\\b' } }))
            end,
            'настройки.scopes[1] — право без пробелов, кавычек и управляющих знаков, а не «a\\b»',
        },
        {
            function()
                oauth2.new(helper.options({ scopes = { 'a\1' } }))
            end,
            'настройки.scopes[1] — право без пробелов, кавычек и управляющих знаков, а не «a\1»',
        },
    })
end

g.test_addresses_are_https_and_http_only_to_the_loopback = function()
    local accepted = {
        'https://id.example.org/token',
        'HTTPS://id.example.org:8443/token?tenant=7',
        'http://127.0.0.1:18480/default/token',
        'http://[::1]:8080/token',
        'http://[::1]/token',
        'http://127.0.0.1:/token',
        'Http://127.0.0.1/token',
        'https://[2001:db8::1]/token',
    }

    for _, address in ipairs(accepted) do
        t.assert_equals(oauth2.new(helper.options({ token_url = address })).settings.token_url, address)
    end

    local expected = 'адрес https://, а http:// — только к 127.0.0.1 и [::1]'

    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ token_url = 'http://id.example.org/token' }))
            end,
            ('настройки.token_url — %s, а не «http://id.example.org/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'http://localhost/token' }))
            end,
            ('настройки.token_url — %s, а не «http://localhost/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'http://127.0.0.2/token' }))
            end,
            ('настройки.token_url — %s, а не «http://127.0.0.2/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'http://[::2]:80/token' }))
            end,
            ('настройки.token_url — %s, а не «http://[::2]:80/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'ftp://id.example.org/token' }))
            end,
            ('настройки.token_url — %s, а не «ftp://id.example.org/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = '/token' }))
            end,
            ('настройки.token_url — %s, а не «/token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'https:///token' }))
            end,
            ('настройки.token_url — %s, а не «https:///token»'):format(expected),
        },
        {
            function()
                oauth2.new(helper.options({ token_url = 'https://:443/token' }))
            end,
            ('настройки.token_url — %s, а не «https://:443/token»'):format(expected),
        },
    })
end

g.test_every_address_setting_is_checked = function()
    for _, key in ipairs({ 'authorize_url', 'redirect_uri', 'userinfo_url' }) do
        local _, err = pcall(oauth2.new, helper.options({ [key] = 'http://example.org/x' }))

        t.assert_str_contains(tostring(err), ('настройки.%s — адрес https://'):format(key))
    end
end

g.test_an_address_has_neither_credentials_nor_a_fragment = function()
    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ token_url = 'https://app:secret@id.example.org/token' }))
            end,
            'настройки.token_url: имя и пароль в адресе не пишут — ключ клиента задают client_secret',
        },
        {
            function()
                oauth2.new(helper.options({ redirect_uri = 'https://app.example.org/callback#done' }))
            end,
            'настройки.redirect_uri — адрес без «#», а не «https://app.example.org/callback#done»',
        },
    })
end

g.test_the_login_pair_comes_together = function()
    local tokens_only = oauth2.new(helper.options({ authorize_url = false, redirect_uri = false }))

    t.assert_equals(tokens_only.settings.authorize_url, nil)

    local message =
        'настройки: authorize_url и redirect_uri задают вместе — без одного из них вход не собрать'

    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ redirect_uri = false }))
            end,
            message,
        },
        {
            function()
                oauth2.new(helper.options({ authorize_url = false }))
            end,
            message,
        },
    })
end

g.test_the_client_auth_needs_a_secret = function()
    local posting = oauth2.new(helper.options({ client_auth = 'client_secret_post' }))

    t.assert_equals(posting.settings.client_auth, 'client_secret_post')

    helper.assert_blamed({
        {
            function()
                oauth2.new(helper.options({ client_auth = 'client_secret_post', client_secret = false }))
            end,
            'настройки.client_auth без client_secret не действует: публичный клиент называет себя client_id',
        },
        {
            function()
                oauth2.new(helper.options({ client_auth = 'private_key_jwt' }))
            end,
            'настройки.client_auth — одно из «client_secret_basic», «client_secret_post», а не «private_key_jwt»',
        },
        {
            function()
                oauth2.new(helper.options({ client_id = '' }))
            end,
            'настройки.client_id — непустая строка, а не пустая',
        },
        {
            function()
                oauth2.new(helper.options({ tokens_url = helper.TOKEN }))
            end,
            'настройки: ключа «tokens_url» нет, есть authorize_url, client_auth, client_id, client_secret, '
                .. 'http, name, profile, redirect_uri, scopes, token_url, userinfo_url',
        },
    })
end

g.test_the_facade_names_the_constants = function()
    t.assert_equals({
        oauth2.STATE_TTL,
        oauth2.MARGIN,
        oauth2.UNKNOWN_TTL,
        oauth2.STATE,
        oauth2.DENIED,
        oauth2.REJECTED,
        oauth2.MALFORMED,
        oauth2.UNAVAILABLE,
        oauth2.REFUSED,
    }, { 900, 60, 300, 'state', 'denied', 'rejected', 'malformed', 'unavailable', 'refused' })
end
