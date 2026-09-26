--- Проверки поставщика токена: срок, обновление, одно обновление на всех.

local fiber = require('fiber')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.source')

g.before_each(function()
    helper.clock(helper.NOW)
end)

g.after_each(helper.restore)

--- Ответ с токеном `name` и сроком `seconds`; без срока — поле не шлётся.
---@param name string
---@param seconds number|nil
---@param refresh string|nil
---@return table
local function issued(name, seconds, refresh)
    local fields = { ('"access_token":"%s"'):format(name) }

    if seconds ~= nil then
        table.insert(fields, ('"expires_in":%s'):format(seconds))
    end

    if refresh ~= nil then
        table.insert(fields, ('"refresh_token":"%s"'):format(refresh))
    end

    return helper.answer(200, '{' .. table.concat(fields, ',') .. '}')
end

g.test_a_token_is_renewed_a_minute_before_its_end = function()
    local client, asked = helper.client({ issued('a', 3600), issued('b', 3600) })
    local token = client:source({ credentials = true, scopes = { 'mail' } })

    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 3539)
    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 3540)
    t.assert_equals(token(), 'b')
    t.assert_equals(#asked, 2)
    t.assert_equals(asked[1].form, { grant_type = 'client_credentials', scope = 'mail' })
end

g.test_a_short_token_is_renewed_halfway = function()
    local client, asked = helper.client({ issued('a', 60), issued('b', 60) })
    local token = client:source({ credentials = true })

    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 29)
    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 30)
    t.assert_equals(token(), 'b')
    t.assert_equals(#asked, 2)
end

g.test_a_token_without_a_lifetime_lives_five_minutes = function()
    local busy = helper.answer(503, 'занято')
    local client, asked = helper.client({ issued('a'), issued('b'), busy, busy })
    local token = client:source({ credentials = true })

    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 239)
    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 240)
    t.assert_equals(token(), 'b')
    t.assert_equals(#asked, 2)

    -- Токен «b» получен на 240-й секунде и годен до 540-й: обновление,
    -- не удавшееся на 539-й, отдаёт его, а на 540-й — уже отказ.
    helper.clock(helper.NOW + 539)
    t.assert_equals(token(), 'b')
    helper.clock(helper.NOW + 540)
    t.assert_equals(select(2, token()).kind, 'unavailable')
end

g.test_a_failed_first_fetch_is_a_refusal = function()
    local client = helper.client({ helper.answer(401, '{"error":"invalid_client"}') })
    local token = client:source({ credentials = true })
    local value, err = token()

    helper.assert_refused(
        value,
        err,
        'rejected',
        'токены клиента: служба ответила 401 — invalid_client',
        'invalid_client'
    )
end

g.test_a_living_token_is_better_than_a_failed_renewal = function()
    local client, asked = helper.client({
        issued('a', 3600),
        helper.answer(503, 'занято'),
        helper.answer(503, 'занято'),
        issued('b', 3600),
    })
    local token = client:source({ credentials = true })

    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 3590)
    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 3600)

    local value, err = token()

    helper.assert_refused(value, err, 'unavailable', 'токены клиента: служба ответила 503')
    t.assert_equals(token(), 'b')
    t.assert_equals(#asked, 4)
end

g.test_fibers_share_one_renewal = function()
    local client, asked = helper.client({
        function()
            fiber.sleep(0.01)

            return issued('a', 3600)
        end,
    })
    local token = client:source({ credentials = true })
    local got = {}
    local done = fiber.channel(2)

    for index = 1, 2 do
        fiber.create(function()
            got[index] = token()
            done:put(true)
        end)
    end

    done:get(1)
    done:get(1)

    t.assert_equals(got, { 'a', 'a' })
    t.assert_equals(#asked, 1)
end

g.test_the_waiters_get_the_same_refusal = function()
    local client, asked = helper.client({
        function()
            fiber.sleep(0.01)

            return helper.answer(503, 'занято')
        end,
    })
    local token = client:source({ credentials = true })
    local got = {}
    local done = fiber.channel(2)

    for index = 1, 2 do
        fiber.create(function()
            local _, err = token()

            got[index] = err
            done:put(true)
        end)
    end

    done:get(1)
    done:get(1)

    t.assert_is(got[1], got[2])
    t.assert_equals(got[1].message, 'токены клиента: служба ответила 503')
    t.assert_equals(#asked, 1)
end

g.test_a_throwing_client_wakes_the_waiters_and_rethrows = function()
    local client, asked = helper.client({
        function()
            fiber.sleep(0.01)
            error('двойник сломан', 0)
        end,
        issued('a', 3600),
    })
    local token = client:source({ credentials = true })
    local waited = {}
    local done = fiber.channel(1)

    fiber.create(function()
        fiber.yield()
        waited.value, waited.err = token()
        done:put(true)
    end)

    local ok, thrown = pcall(token)

    done:get(1)

    t.assert_equals({ ok, thrown }, { false, 'двойник сломан' })
    t.assert_equals(waited.value, nil)
    t.assert_equals(
        { waited.err.kind, waited.err.message },
        { 'unavailable', 'токен не получен: двойник сломан' }
    )
    t.assert_equals(token(), 'a')
    t.assert_equals(#asked, 2)
end

g.test_a_grant_is_used_first_and_renewed_by_its_refresh_token = function()
    local client, asked = helper.client({ issued('b', 3600, 'rt-2'), issued('c', 3600) })
    local token = client:source({
        grant = { access_token = 'a', refresh_token = 'rt-1', expires_at = helper.NOW + 120 },
    })

    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 60)
    t.assert_equals(token(), 'b')
    helper.clock(helper.NOW + 60 + 3540)
    t.assert_equals(token(), 'c')
    t.assert_equals(
        { asked[1].form.refresh_token, asked[2].form.refresh_token },
        { 'rt-1', 'rt-2' },
        'токен обновления, сменённый службой, идёт в следующее обновление'
    )
    t.assert_equals(#asked, 2)
end

g.test_a_saved_refresh_token_fetches_at_the_first_call = function()
    local client, asked = helper.client({ issued('a', 3600), issued('b', 3600) })
    local token = client:source({ refresh_token = 'rt-1' })

    t.assert_equals(#asked, 0, 'поставщик в сеть до первого вызова не ходит')
    t.assert_equals(token(), 'a')
    helper.clock(helper.NOW + 3540)
    t.assert_equals(token(), 'b')
    t.assert_equals({ asked[1].form.refresh_token, asked[2].form.refresh_token }, { 'rt-1', 'rt-1' })
end

g.test_the_source_takes_exactly_one_origin = function()
    local client = helper.client({})
    local message =
        'настройки поставщика: ровно одно из grant, refresh_token и credentials = true'

    helper.assert_blamed({
        {
            function()
                client:source({})
            end,
            message,
        },
        {
            function()
                client:source({ refresh_token = 'rt', credentials = true })
            end,
            message,
        },
        {
            function()
                client:source({ refresh_token = 'rt', grant = { access_token = 'a', refresh_token = 'rt' } })
            end,
            message,
        },
        {
            function()
                client:source({ credentials = false })
            end,
            message,
        },
        {
            function()
                client:source({ grant = { access_token = 'a' } })
            end,
            'настройки поставщика.grant.refresh_token — непустая строка, а не nil',
        },
        {
            function()
                client:source({ grant = { refresh_token = 'rt' } })
            end,
            'настройки поставщика.grant.access_token — непустая строка, а не nil',
        },
        {
            function()
                client:source({ grant = { access_token = 'a', refresh_token = 'rt', expires_at = 'soon' } })
            end,
            'настройки поставщика.grant.expires_at — число, а не строка',
        },
        {
            function()
                client:source(nil)
            end,
            'настройки поставщика — таблица, а не nil',
        },
        {
            function()
                helper.client({}, { client_secret = false }):source({ credentials = true })
            end,
            'credentials: у клиента example нет client_secret',
        },
    })
end
