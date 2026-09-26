--- Обращение к точке службы: запрос, ответ, отказ по роду.
---
--- У точки токенов и точки профиля один и тот же разговор: запрос
--- клиентом HTTP, ответ — объект JSON, отказ — объект с полем `error`
--- (RFC 6749, §5.2; RFC 6750, §3.1). Здесь он разбирается один раз.
---
--- * **Ошибка OAuth узнаётся по полю `error`, а не по коду ответа.** Часть
---   служб отвечает ею с кодом 200, и такой ответ — отказ, а не токен.
--- * **Занятость — не отказ во входе.** Нет ответа, 408, 429 и 5xx —
---   род `unavailable`: лечит время, а не посетитель. Прочий код не 200 —
---   `rejected`, ответ без объекта JSON — `malformed`.
--- * **Тайн в тексте отказа нет.** Причина службы (`error_description`)
---   бывает с повтором присланного — кода, токена обновления, — поэтому
---   из неё вычёркиваются все наши тайны этого обращения, управляющие знаки
---   становятся точкой, а длина — не больше предела. Тело ответа в отказ
---   не попадает никогда: служба, не понявшая `Accept`, отдаёт токен
---   формой, и начало такого тела — сам токен.

local json = require('json')

local failure = require('tnt.oauth2.failure')

local Module = {}

--- Самая длинная причина службы в тексте отказа, байтов.
Module.REASON_LIMIT = 200

--- Чем заменяется вычеркнутая тайна.
local HIDDEN = '[скрыто]'

--- Код ответа, при котором служба ответила по делу.
local OK = 200

--- Коды, при которых служба занята, а не отказала: срок запроса
--- и слишком частые запросы.
local BUSY = { [408] = true, [429] = true }

--- Первый код ответа «служба сломалась».
local BROKEN = 500

---@class TntOAuth2Call Обращение к точке
---@field method string GET либо POST
---@field url string
---@field form table<string, string>|nil Тело формой
---@field headers table<string, string>

--- Причина службы, пригодная для отказа и журнала.
---
--- Тайны вычёркиваются до обрезки: тайна, разрезанная пределом, оставила
--- бы в тексте своё начало.
---@param text any
---@param secrets string[] Что вычеркнуть
---@return string
function Module.scrubbed(text, secrets)
    local shown = tostring(text)

    for _, secret in ipairs(secrets) do
        -- Тайна ищется как есть: каждый знак пунктуации экранирован.
        shown = shown:gsub(secret:gsub('%p', '%%%0'), HIDDEN)
    end

    -- Срез от начала — отрицательным отсчётом: у `sub(1, n)` мутант
    -- `sub(0, n)` неотличим.
    return (shown:sub(-#shown, Module.REASON_LIMIT):gsub('%c', '.'))
end

--- Объект JSON из тела ответа либо пустота.
---
--- Объект узнаётся по первому знаку записи: `json.decode` читает и массив
--- той же таблицей Lua.
---@param body any
---@return table|nil
local function object_of(body)
    if type(body) ~= 'string' or body:find('^%s*{') == nil then
        return nil
    end

    local decoded, object = pcall(json.decode, body)

    if not decoded then
        return nil
    end

    ---@cast object table
    return object
end

--- Занята ли служба по коду ответа.
---@param status integer
---@return boolean
local function busy(status)
    return BUSY[status] or status >= BROKEN
end

--- Отказ по ошибке OAuth: код `error` и причина `error_description`.
---
--- Одна запись на ответ точки и на адрес возврата (RFC 6749, §4.1.2.1,
--- §5.2): у обоих те же два поля, и текст отказа у них один и тот же.
---@param kind string Род отказа
---@param head string Начало текста: что делали и что ответила служба
---@param object table Поля ответа: `error`, `error_description`
---@param secrets string[] Что вычеркнуть
---@return TntOAuth2Failure
function Module.refusal(kind, head, object, secrets)
    local message = head
    local code

    if type(object.error) == 'string' then
        code = Module.scrubbed(object.error, secrets)
        message = ('%s — %s'):format(message, code)
    end

    if type(object.error_description) == 'string' then
        message = ('%s: %s'):format(message, Module.scrubbed(object.error_description, secrets))
    end

    return failure.new(kind, message, code)
end

--- Обращается к точке службы.
---@param http table Клиент: `request(opts)`
---@param call TntOAuth2Call
---@param step string Что делали — начало текста отказа: «обмен кода», «профиль»
---@param secrets string[] Тайны этого обращения: их в тексте отказа не будет
---@return table|nil object Ответ — объект JSON
---@return TntOAuth2Failure|nil
function Module.call(http, call, step, secrets)
    local answer, err = http:request(call)

    if answer == nil then
        -- Причина без адреса, если клиент её дал: в адресе ездят ключи.
        local reason = type(err) == 'table' and err.reason or err
        local message = ('%s: служба не ответила: %s'):format(step, Module.scrubbed(reason, secrets))

        return nil, failure.new(failure.UNAVAILABLE, message)
    end

    local status = answer.status
    local object = object_of(answer.body)

    if object ~= nil and object.error ~= nil then
        local kind = busy(status) and failure.UNAVAILABLE or failure.REJECTED

        return nil, Module.refusal(kind, ('%s: служба ответила %d'):format(step, status), object, secrets)
    end

    if busy(status) then
        return nil, failure.new(failure.UNAVAILABLE, ('%s: служба ответила %d'):format(step, status))
    end

    if status ~= OK then
        return nil, failure.new(failure.REJECTED, ('%s: служба ответила %d'):format(step, status))
    end

    if object == nil then
        local message = ('%s: ответ не объект JSON — %d байт'):format(step, #tostring(answer.body))

        return nil, failure.new(failure.MALFORMED, message)
    end

    return object
end

return Module
