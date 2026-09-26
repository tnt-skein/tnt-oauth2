--- Поставщик токена доступа: отдаёт живой токен и берёт новый по сроку.
---
--- Токен доступа живёт час, а пользуются им дольше: почта входит
--- по XOAUTH2 на каждое письмо, клиент чужого API — на каждый запрос.
--- Поставщик — функция без аргументов: она отдаёт токен строкой либо
--- `nil, err`, и тот, кто её зовёт, о сроках не знает ничего.
---
--- * **Новый токен — до срока, а не после отказа.** Токен, отданный
---   за секунду до срока, умер бы посреди входа, а отказ сервера почты
---   поставщик не видит. Поэтому новый берётся за минуту до срока, а у
---   короткого токена — на половине его жизни.
--- * **Служба, не назвавшая срок**, получает пять минут: токен без срока
---   мог быть отозван, и спросить новый дешевле, чем проверять старый.
--- * **Одно обновление на всех.** Файберы, которым токен понадобился
---   в миг обновления, ждут его, а не шлют своё: у службы, меняющей токен
---   обновления на каждом шаге (RFC 9700, §4.14.2), второе обновление
---   тем же токеном отозвало бы всю цепочку. Отказ обновления достаётся
---   всем ждавшим — тем же отказом.
--- * **Живой токен лучше отказа.** Не удалось обновиться за минуту
---   до срока — отдаётся прежний, пока он годен: служба, лежащая минуту,
---   не должна ронять почту узла.
---
--- Токен в поставщике — учётные данные, и наружу он не показывается ничем,
--- кроме самого вызова.

local fiber = require('fiber')

local raise = require('tnt.must.fail').raise

local outside = require('tnt.oauth2.outside')
local failure = require('tnt.oauth2.failure')

local Module = {}

--- За сколько секунд до срока брать новый токен.
Module.MARGIN = 60

--- Сколько секунд годен токен, срока которого служба не назвала.
Module.UNKNOWN_TTL = 5 * 60

---@class TntOAuth2Held Токен в поставщике и его сроки
---@field grant TntOAuth2Grant
---@field renew number Миг, с которого брать новый
---@field expires number Миг, после которого токен не отдаётся

--- Токен со сроками: когда обновлять и когда он мёртв.
---@param grant TntOAuth2Grant
---@param now number
---@return TntOAuth2Held
local function held(grant, now)
    local expires = grant.expires_at or now + Module.UNKNOWN_TTL
    local early = math.min(Module.MARGIN, (expires - now) / 2)

    return { grant = grant, renew = expires - early, expires = expires }
end

--- Поставщик поверх того, кто берёт новые токены.
---
--- `obtain(grant)` отдаёт новые токены либо отказ; прежние токены — его
--- аргумент: из них он берёт токен обновления.
---@param obtain fun(grant: TntOAuth2Grant|nil): TntOAuth2Grant|nil, TntOAuth2Failure|nil
---@param grant TntOAuth2Grant|nil Токены, с которых начать; нет — первый вызов возьмёт
---@return fun(): string|nil, TntOAuth2Failure|nil
function Module.new(obtain, grant)
    local current = grant and held(grant, outside.now())
    --- Обновление в полёте: условие, на котором ждут остальные.
    ---@type any
    local flight
    local failed

    --- Берёт новые токены; ждавшие будятся в любом исходе.
    ---
    --- Бросок `obtain` — ошибка программиста, и он уходит вызывающему,
    --- но ждавшие не остаются ждать вечно: их будят с отказом.
    local function renew()
        local done = fiber.cond()

        flight = done

        local ok, fresh, err = pcall(obtain, current and current.grant)

        flight = nil

        if ok and fresh ~= nil then
            current = held(fresh, outside.now())
        end

        failed = err

        if not ok then
            failed = failure.new(failure.UNAVAILABLE, ('токен не получен: %s'):format(tostring(fresh)))
        end

        done:broadcast()

        if not ok then
            raise(fresh)
        end
    end

    return function()
        if current == nil or outside.now() >= current.renew then
            if flight ~= nil then
                flight:wait()
            else
                renew()
            end
        end

        if current ~= nil and outside.now() < current.expires then
            return current.grant.access_token
        end

        return nil, failed
    end
end

return Module
