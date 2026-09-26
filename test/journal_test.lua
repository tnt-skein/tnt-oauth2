--- Проверки того, что тайны входа не попадают ни в журнал, ни в отказ.
---
--- Здесь клиент HTTP настоящий — тот, что пакет собирает сам, — а libcurl
--- под ним подменён: журнал пишет клиент HTTP, и что туда попало, видно
--- только по его записям.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.oauth2.journal')

--- Тайны одного входа: всё, чего в журнале быть не должно.
local SECRETS = { 'code-1', helper.VERIFIER, helper.STATE, 'at-1', 'rt-1', 's3cr3t', 'czNjcjN0' }

--- Что ушло к libcurl, и журнал на время проверки.
---@type any
local sent
---@type any
local journal

--- Ставит двойник libcurl с ответами по порядку.
---@param answers table[]
local function serve(answers)
    local script = helper.script(answers)

    sent = {}
    helper.transport._set_source({
        client = function()
            return {
                request = function(_, method, url, body, options)
                    table.insert(sent, { method = method, url = url, body = body, options = options })

                    return script.next()
                end,
            }
        end,
    })
end

--- Ответ libcurl.
---@param status integer
---@param body string
---@param reason string|nil
---@return table
local function reply(status, body, reason)
    return {
        status = status,
        reason = reason or 'OK',
        headers = { ['content-type'] = 'application/json' },
        body = body,
    }
end

g.before_each(function()
    helper.clock(helper.NOW)
    journal = helper.capture_log()
end)

g.after_each(function()
    journal.release()
    helper.transport._set_source(nil)
    helper.restore()
end)

--- Сверяет, что ни в журнале, ни в тексте отказа нет ни одной тайны.
---@param err any
local function assert_no_secrets(err)
    local records = journal.records()

    t.assert_not_equals(#records, 0, 'клиент HTTP записал неудачу')

    for _, record in ipairs(records) do
        for _, secret in ipairs(SECRETS) do
            t.assert_equals(record.line:find(secret, 1, true), nil, record.line)
        end
    end

    for _, secret in ipairs(SECRETS) do
        t.assert_equals(tostring(err):find(secret, 1, true), nil, tostring(err))
    end
end

g.test_a_failed_exchange_leaves_no_secret_in_the_journal = function()
    serve({ reply(595, '', "Couldn't connect to server") })

    ---@type any
    local client = helper.oauth2.new(helper.options())
    local assertion, err = client:finish(helper.started(), { state = helper.STATE, code = 'code-1' })

    t.assert_equals(assertion, nil)
    t.assert_equals(err.kind, 'unavailable')
    t.assert_equals(
        err.message,
        "обмен кода: служба не ответила: сервер не ответил: Couldn't connect to server (код 595)"
    )
    t.assert_equals(sent[1].method, 'POST')
    t.assert_equals(#sent, 1, 'POST за кодом не повторяется')
    assert_no_secrets(err)
end

g.test_a_failed_profile_leaves_no_token_in_the_journal = function()
    serve({
        reply(200, '{"access_token":"at-1","token_type":"Bearer","refresh_token":"rt-1"}'),
        reply(595, '', "Couldn't connect to server"),
        reply(595, '', "Couldn't connect to server"),
        reply(595, '', "Couldn't connect to server"),
    })
    helper.retry_runner._set_source({
        sleep = function() end,
    })

    ---@type any
    local client = helper.oauth2.new(helper.options())
    local _, err = client:finish(helper.started(), { state = helper.STATE, code = 'code-1' })

    helper.retry_runner._set_source(nil)

    t.assert_equals(err.kind, 'unavailable')
    t.assert_equals(sent[2].method, 'GET')
    t.assert_equals(sent[2].options.headers.authorization, 'Bearer at-1')
    assert_no_secrets(err)
end
