--- Клиент OAuth 2.0: вход через чужую службу, токены и поставщик живого токена.
---
---     local oauth2 = require('tnt.oauth2')
---
---     local github = oauth2.new({
---         name = 'github',
---         client_id = id,
---         client_secret = secret,
---         authorize_url = 'https://github.com/login/oauth/authorize',
---         token_url = 'https://github.com/login/oauth/access_token',
---         userinfo_url = 'https://api.github.com/user',
---         redirect_uri = 'https://app.example.org/auth/github/callback',
---         scopes = { 'read:user' },
---         profile = function(user)
---             return { subject = tostring(user.id), name = user.login }
---         end,
---     })
---
---     local address = github:authorize(request.session)             -- ответ 303 туда
---     local assertion, err = github:finish(request.session, request.query)
---     local token = github:source({ refresh_token = stored })       -- живой токен по сроку
---
--- Поток с кодом (RFC 6749, §4.1) с PKCE `S256` и `state` в сессии,
--- сверенным за постоянное время; адрес возврата — ровно из настроек.
--- OAuth 2.0 выдаёт доступ, а не личность: удостоверение из профиля
--- службы собирает функция приложения `profile`, а учётную запись по нему
--- находит само приложение. Токены — учётные данные: их нет
--- в удостоверении и в журнале, а из текста отказа они вычеркнуты, даже
--- если служба повторила их в своей причине.
---
--- Сверх входа — токены самого клиента (`credentials`), обновление
--- (`refresh`) и поставщик живого токена (`source`): его берёт почта для
--- входа XOAUTH2 и клиент чужого API. Отказ — пара с родом
--- (`tnt.oauth2.failure`), негодный аргумент — бросок на строке
--- вызывающего. Подробно — `docs/oauth2.md`.

local client = require('tnt.oauth2.client')
local failure = require('tnt.oauth2.failure')
local login = require('tnt.oauth2.login')
local outside = require('tnt.oauth2.outside')
local source = require('tnt.oauth2.source')

local Module = {}

Module.new = client.new

--- Сколько живёт начатый вход и когда поставщик берёт новый токен.
Module.STATE_TTL = login.STATE_TTL
Module.MARGIN = source.MARGIN
Module.UNKNOWN_TTL = source.UNKNOWN_TTL

--- Роды отказа.
Module.STATE = failure.STATE
Module.DENIED = failure.DENIED
Module.REJECTED = failure.REJECTED
Module.MALFORMED = failure.MALFORMED
Module.UNAVAILABLE = failure.UNAVAILABLE
Module.REFUSED = failure.REFUSED

--- Подменяет стенные часы и случайные байты пакета. Только для проверок.
Module._set_source = outside._set_source

return Module
