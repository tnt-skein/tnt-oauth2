--- Одноразовые значения входа: `state` и проверочный код PKCE.
---
--- Оба — 32 случайных байта в base64url без набивки, 43 знака. Столько
--- RFC 7636 (§4.1) советует для проверочного кода, а `state` из тех же
--- байтов не угадать и не подобрать за время входа (RFC 9700, §2.1).
---
--- Вызов PKCE — только `S256`: `BASE64URL(SHA256(verifier))` (RFC 7636,
--- §4.2). `plain` не шлётся никогда: при нём вызов и есть проверочный
--- код, и его знает всякий, кто видел адрес перехода, — журнал прокси,
--- история браузера, заголовок `Referer`.
---
--- Случайные байты — внешняя зависимость пакета (`tnt.oauth2.outside`):
--- проверки подставляют известные и сверяют значения дословно.

local digest = require('digest')

local hash = require('tnt.hash')

local outside = require('tnt.oauth2.outside')

local Module = {}

--- Сколько случайных байтов в одноразовом значении.
Module.BYTES = 32

--- Свежее одноразовое значение: base64url без набивки.
---@return string
function Module.fresh()
    return digest.base64_encode(outside.random(Module.BYTES), { urlsafe = true })
end

--- Вызов PKCE по проверочному коду: `S256`.
---@param verifier string
---@return string
function Module.challenge(verifier)
    return hash.digest('sha256', verifier, 'base64url')
end

return Module
