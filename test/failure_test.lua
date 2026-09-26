--- Проверки отказа: строкой он — свой текст.

local json = require('json')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local failure = helper.failure

local g = t.group('tnt.oauth2.failure')

g.test_a_refusal_reads_as_its_message = function()
    local err =
        failure.new(failure.DENIED, 'служба отказала во входе — access_denied', 'access_denied')

    t.assert_equals({ err.kind, err.message, err.code }, {
        'denied',
        'служба отказала во входе — access_denied',
        'access_denied',
    })
    t.assert_equals(tostring(err), 'служба отказала во входе — access_denied')
    t.assert_equals(
        'вход не удался: ' .. err,
        'вход не удался: служба отказала во входе — access_denied'
    )
    t.assert_equals(err .. '.', 'служба отказала во входе — access_denied.')
    t.assert_equals(
        json.encode({ err = err }),
        '{"err":"служба отказала во входе — access_denied"}'
    )
end
