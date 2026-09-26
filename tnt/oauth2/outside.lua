--- Внешние зависимости пакета: стенные часы и случайные байты.
---
--- **Часы — стенные.** Срок токена служба называет длительностью
--- (`expires_in`, RFC 6749, §5.1), а пакет переводит его в миг стенных
--- часов (`expires_at`): так срок можно положить в сессию и сверить
--- на другом узле и после перезапуска, где монотонные часы свои. Тем же
--- мигом отмечается начало входа в сессии и миг входа в удостоверении
--- (`authenticated_at`): удостоверение уходит в журнал и в сессию, и миг
--- в нём читают другие узлы.
---
--- **Случайные байты — `digest.urandom`**: из них `state` и проверочный
--- код PKCE (`tnt.oauth2.secret`).
---
--- Обе — внешние зависимости одного объявления: проверки ставят часы
--- на заданный миг, сверяют сроки на самой границе, а вызов PKCE —
--- с вектором RFC 7636 по известным байтам.

local digest = require('digest')

local clock = require('tnt.clock')
local external = require('tnt.external')

---@class TntOAuth2Outside
---@field _set_source fun(replacement: table|nil) Подмена — для проверок; ставит её `external.install`
local Module = {}

--- Внешние зависимости: часы и случайные байты.
local source = external.install(Module, { now = clock.realtime, random = digest.urandom })

--- Сейчас по стенным часам, секунд эпохи.
---@return number
function Module.now()
    return source().now()
end

--- Случайные байты заданной длины.
---@param length integer
---@return string
function Module.random(length)
    return source().random(length)
end

return Module
