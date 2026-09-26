--- Отказ клиента OAuth 2.0: род, текст и код ошибки службы.
---
--- Вход через чужую службу срывается по причинам, которые приходят
--- снаружи: посетитель нажал «отмена», ответ пришёл не к этому входу,
--- служба лежит. Это «так бывает», а не ошибка программиста, — отказ
--- парой `nil, err`. Вызывающему нужен род — слово, по которому решают,
--- что делать дальше:
---
--- * `state` — ответ не к этому входу: в сессии нет начатого входа, вход
---   начат слишком давно либо `state` не совпал;
--- * `denied` — служба сама отказала во входе (`error` в адресе
---   возврата, RFC 6749, §4.1.2.1): посетитель отказался, прав нет;
--- * `rejected` — служба отвергла запрос клиента: код выдан под другой
---   проверочный код PKCE, токен обновления отозван, клиент не тот;
--- * `malformed` — служба ответила не по протоколу: не JSON, нет токена,
---   токен не Bearer, в адресе возврата нет кода;
--- * `unavailable` — служба не ответила либо занята (сеть, срок, 5xx,
---   429): лечит время, а не посетитель;
--- * `refused` — служба ответила, а приложение не узнало пользователя:
---   функция `profile` отдала пустоту.
---
--- Роды разведены ради одного различия: `unavailable` — не «неверный
--- вход», и повторять его посетителю незачем, а считать попыткой подбора —
--- нельзя: на отказ службы отвечают 503, а не 401.
---
--- Строкой отказ читается целиком: `tostring(err)`, склейка и `json.encode`
--- дают его текст. Тайн в тексте нет: коды, токены и ключ клиента
--- вычёркиваются, даже если служба повторила их в своей причине.

local Module = {}

--- Ответ не к этому входу.
Module.STATE = 'state'

--- Служба отказала во входе.
Module.DENIED = 'denied'

--- Служба отвергла запрос клиента.
Module.REJECTED = 'rejected'

--- Служба ответила не по протоколу.
Module.MALFORMED = 'malformed'

--- Служба не ответила либо занята.
Module.UNAVAILABLE = 'unavailable'

--- Приложение не узнало пользователя.
Module.REFUSED = 'refused'

---@class TntOAuth2Failure Отказ клиента OAuth 2.0
---@field kind string Род: state, denied, rejected, malformed, unavailable либо refused
---@field message string Что не так — его и отдаёт `tostring`
---@field code string|nil Код ошибки OAuth 2.0 от службы: access_denied, invalid_grant…

--- Текст отказа: им отказ читается строкой, в склейке и в JSON.
---@param refusal TntOAuth2Failure
---@return string
local function message_of(refusal)
    return refusal.message
end

--- Поведение всех отказов пакета.
local BEHAVIOUR = {
    __tostring = message_of,
    __serialize = message_of,
    __concat = function(left, right)
        return tostring(left) .. tostring(right)
    end,
}

--- Отказ с родом, текстом и кодом службы.
---@param kind string Род — одна из констант модуля
---@param message string
---@param code string|nil Код ошибки OAuth 2.0, если служба его назвала
---@return TntOAuth2Failure
function Module.new(kind, message, code)
    local refusal = { kind = kind, message = message, code = code }

    return setmetatable(refusal, BEHAVIOUR)
end

return Module
