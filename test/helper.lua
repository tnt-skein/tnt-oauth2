--- Общие средства проверок клиента OAuth 2.0.
---
--- Служба подменяется двойником клиента HTTP: таблицей с `request`, как
--- её описывает договор `tnt-http` («Что можно подставить вместо
--- клиента»). Двойник отдаёт ответы по порядку и помнит запросы — так
--- видно, что именно ушло к службе: форма, заголовки, адрес. Настоящие
--- `tnt-hash` и `digest` считают вызов PKCE и `state`, подменяются только
--- часы и случайные байты. Сессия — таблица с `put` и `pull`: больше
--- пакет от сессии ничего не берёт.
---
--- Исходники пакета читаются с диска, а не через `require`: у Tarantool
--- свой загрузчик `.rocks`, он идёт раньше `package.path` и подсунул бы
--- установленную копию пакета, если она есть. Проверки тогда шли бы
--- против вчерашнего кода, а покрытие считалось бы по нему. Зависимости
--- пакета — `tnt-http` с его соседями, `tnt-hash`, `tnt-must`, `tnt-clock`
--- и `tnt-external` — берутся из `.rocks` обычным `require`: проверяется
--- этот пакет, а не они.
---
--- Оснастка в `test/testing/` — загрузчик исходников, ловушка журнала
--- и сценарий ответов двойника — грузится так же, файлами, и один раз
--- на процесс: второй экземпляр загрузчика не знал бы, что вытеснил
--- первый, и не вернул бы вытесненное на место.

local digest = require('digest')
local fio = require('fio')
local socket = require('socket')
local t = require('luatest')

--- Модули оснастки в порядке зависимостей: ловушка журнала берёт
--- загрузчик.
local TESTING = {
    { name = 'tnt.testing.sources', path = 'test/testing/sources.lua' },
    { name = 'tnt.testing.journal', path = 'test/testing/journal.lua' },
    { name = 'tnt.testing.protocol', path = 'test/testing/protocol.lua' },
}

for _, module in ipairs(TESTING) do
    if package.loaded[module.name] == nil then
        local chunk, failure = loadfile(fio.abspath(module.path))

        if chunk == nil then
            error(('оснастка %s не читается: %s'):format(module.name, tostring(failure)))
        end

        package.loaded[module.name] = chunk()
    end
end

local sources = package.loaded['tnt.testing.sources']

--- Имена модулей пакета в порядке зависимостей.
local OWN = {
    'tnt.oauth2.failure',
    'tnt.oauth2.outside',
    'tnt.oauth2.secret',
    'tnt.oauth2.settings',
    'tnt.oauth2.endpoint',
    'tnt.oauth2.token',
    'tnt.oauth2.login',
    'tnt.oauth2.profile',
    'tnt.oauth2.source',
    'tnt.oauth2.client',
    'tnt.oauth2',
}

local helper = {
    --- Модули пакета в порядке зависимостей: имя и путь исходника.
    MODULES = {},
}

for _, name in ipairs(OWN) do
    table.insert(helper.MODULES, { name = name, path = (name:gsub('%.', '/')) .. '.lua' })
end

--- Слушает ли порт стенда: живые проверки без него пропускаются.
---@param host string
---@param port integer
---@return boolean
function helper.listening(host, port)
    local connection = socket.tcp_connect(host, port, 0.3)

    if connection == nil then
        return false
    end

    connection:close()

    return true
end

--- Фасад пакета из исходников.
---
--- Грузится при каждом подключении помощника, то есть раз на файл
--- проверок: состояния у пакета нет, кроме часов и случайных байтов,
--- а их проверки возвращают сами (`restore`).
helper.oauth2 = sources.load(helper.MODULES, 'tnt.oauth2')

--- Части пакета из той же загрузки, что и фасад.
helper.endpoint = sources.module('tnt.oauth2.endpoint')
helper.failure = sources.module('tnt.oauth2.failure')
helper.secret = sources.module('tnt.oauth2.secret')

--- Подмена libcurl и пауз повторов у клиента HTTP: пакет берёт
--- установленный `tnt-http`, и подменять надо те же его модули.
helper.transport = require('tnt.http.transport')
helper.retry_runner = require('tnt.retry.runner')

--- Значение мимо проверки типов: негодный аргумент нарочно.
---@param value any
---@return any
function helper.wrong(value)
    return value
end

--- Сверяет, что каждый вызов бросает названный отказ и винит строку
--- вызова в файле проверок, а не внутри пакета.
---
--- Вызов стоит в замыкании первой строкой тела, то есть строкой ниже
--- слова `function`: место броска сверяется с ней целиком — файлом,
--- строкой и текстом.
---@param cases table[] Пары: замыкание с вызовом и текст броска
function helper.assert_blamed(cases)
    for _, case in ipairs(cases) do
        local _, err = pcall(case[1])
        local info = debug.getinfo(case[1], 'S') --[[@as { short_src: string, linedefined: integer }]]

        t.assert_equals(err, ('%s:%d: %s'):format(info.short_src, info.linedefined + 1, case[2]))
    end
end

--- Ловушка журнала: что ушло в журнал, видно проверке.
helper.capture_log = package.loaded['tnt.testing.journal'].capture

--- Ответы двойника по порядку: кончившийся сценарий — ошибка проверки.
helper.script = package.loaded['tnt.testing.protocol'].script

--- Миг, на котором стоят часы проверок: 2026-09-21, целая секунда.
helper.NOW = 1790000000

--- Настройки обычной службы.
helper.CLIENT_ID = 'app-7'
helper.CLIENT_SECRET = 's3cr3t:with/slash'
helper.AUTHORIZE = 'https://id.example.org/authorize'
helper.TOKEN = 'https://id.example.org/token'
helper.USERINFO = 'https://api.example.org/user'
helper.REDIRECT = 'https://app.example.org/auth/example/callback'

--- Одноразовые значения, которые отдают подменённые случайные байты:
--- `state` — из байтов «s», проверочный код — из байтов «v».
helper.STATE = digest.base64_encode(string.rep('s', 32), { urlsafe = true })
helper.VERIFIER = digest.base64_encode(string.rep('v', 32), { urlsafe = true })

--- Подменённые внешние зависимости пакета: часы и случайные байты
--- ставятся порознь, а объявление у них одно.
local substituted = {}

--- Подменяет одну внешнюю зависимость, не трогая другую.
---@param name string now либо random
---@param value function|nil
function helper.substitute(name, value)
    substituted[name] = value
    helper.oauth2._set_source(next(substituted) ~= nil and table.copy(substituted) or nil)
end

--- Ставит часы пакета на миг `now`.
---@param now number
function helper.clock(now)
    helper.substitute('now', function()
        return now
    end)
end

--- Подменяет случайные байты: сначала «s», затем «v», затем снова.
function helper.random()
    local next_byte = 's'

    helper.substitute('random', function(length)
        local bytes = string.rep(next_byte, length)

        next_byte = next_byte == 's' and 'v' or 's'

        return bytes
    end)
end

--- Возвращает пакету настоящие часы и случайные байты.
function helper.restore()
    substituted = {}
    helper.oauth2._set_source(nil)
end

--- Двойник клиента HTTP: ответы по порядку, запросы — в список.
---
--- Ответ — таблица `{ status, body }` либо функция: так двойник отдаёт
--- отказ парой и уступает управление посреди запроса.
---@param answers table[]
---@return table client
---@return table[] asked Запросы в порядке прихода
function helper.http(answers)
    local script = helper.script(answers)
    local asked = {}

    return {
        request = function(_, call)
            table.insert(asked, call)

            return script.next()
        end,
    },
        asked
end

--- Ответ службы: код и тело — объект JSON строкой.
---@param status integer
---@param body string
---@return table
function helper.answer(status, body)
    return { status = status, headers = {}, body = body }
end

--- Ответ точки токенов с токеном.
---@param fields string|nil Поля JSON поверх обычных, без скобок
---@return table
function helper.tokens(fields)
    local extra = fields and (', ' .. fields) or ''

    return helper.answer(200, ('{"access_token":"at-1","token_type":"Bearer","expires_in":3600%s}'):format(extra))
end

--- Обычные настройки; `overrides` заменяет поля целиком, `false` убирает.
---@param overrides table|nil
---@return TntOAuth2Options
function helper.options(overrides)
    local options = {
        name = 'example',
        client_id = helper.CLIENT_ID,
        client_secret = helper.CLIENT_SECRET,
        authorize_url = helper.AUTHORIZE,
        token_url = helper.TOKEN,
        userinfo_url = helper.USERINFO,
        redirect_uri = helper.REDIRECT,
        scopes = { 'read:user', 'email' },
        profile = function(user)
            return { subject = tostring(user.id), name = user.login }
        end,
    }

    for name, value in pairs(overrides or {}) do
        if value == false then
            options[name] = nil
        else
            options[name] = value
        end
    end

    return options
end

--- Клиент с обычными настройками и двойником службы.
---@param answers table[] Ответы службы по порядку
---@param overrides table|nil
---@return TntOAuth2Client client
---@return table[] asked
function helper.client(answers, overrides)
    local http, asked = helper.http(answers)
    local options = helper.options(overrides)

    options.http = http

    return helper.oauth2.new(options), asked
end

--- Сессия посетителя: `put`, `get` и `pull`.
---@param data table|nil Что уже лежит в сессии
---@return table
function helper.session(data)
    local stored = data or {}

    return {
        data = stored,

        put = function(_, key, value)
            stored[key] = value
        end,

        get = function(_, key)
            return stored[key]
        end,

        pull = function(_, key)
            local value = stored[key]

            stored[key] = nil

            return value
        end,
    }
end

--- Начатый вход в сессии: на миг `at`, с обычными значениями.
---@param at number|nil По умолчанию — `NOW`
---@return table
function helper.started(at)
    return helper.session({
        ['oauth2.example'] = { state = helper.STATE, verifier = helper.VERIFIER, at = at or helper.NOW },
    })
end

--- Разбирает строку формы и параметры адреса в таблицу.
---@param text string
---@return table<string, string>
function helper.decoded(text)
    local fields = {}

    for pair in text:gmatch('[^&]+') do
        ---@type any, any
        local name, value = pair:match('^([^=]*)=(.*)$')

        fields[name] = value:gsub('%%(%x%x)', function(hex)
            return string.char(tonumber(hex, 16) --[[@as integer]])
        end)
    end

    return fields
end

--- Параметры адреса после знака вопроса.
---@param address string
---@return table<string, string>
function helper.query_of(address)
    return helper.decoded(address:match('%?(.*)$') --[[@as string]])
end

--- Сверяет отказ: род, текст и код службы.
---@param outcome any Первое значение вызова: при отказе пусто
---@param err any Отказ
---@param kind string
---@param message string
---@param code string|nil
function helper.assert_refused(outcome, err, kind, message, code)
    t.assert_equals(outcome, nil)
    t.assert_equals({ kind = err.kind, message = err.message, code = err.code }, {
        kind = kind,
        message = message,
        code = code,
    })
end

return helper
