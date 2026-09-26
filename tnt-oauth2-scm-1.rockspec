rockspec_format = '3.0'

package = 'tnt-oauth2'
version = 'scm-1'

source = {
    url = 'git+https://github.com/tnt-skein/tnt-oauth2.git',
    branch = 'main',
}

description = {
    summary = 'Клиент OAuth 2.0: вход через чужую службу с PKCE и state, токены клиента и поставщик живого токена',
    detailed = [[
        Вход посетителя через чужую службу потоком с кодом по RFC 6749:
        authorize кладёт state и проверочный код PKCE в сессию и отдаёт
        адрес службы, finish сверяет state за постоянное время, меняет код
        на токены с проверочным кодом (только S256, RFC 7636) и спрашивает
        профиль. Начатый вход одноразовый и живёт пятнадцать минут, адрес
        возврата берётся ровно из настроек, а адреса службы — только https
        (http — только к 127.0.0.1 и [::1]).

        OAuth 2.0 выдаёт доступ, а не личность: удостоверение из профиля
        собирает функция приложения profile, и его вид проверяется —
        subject строкой до 255 байт, закрытые поля. Токены — учётные данные:
        их нет в удостоверении, и из текста отказа они вычеркнуты, даже если
        служба повторила их в своей причине.

        Сверх входа — токены самого клиента (client_credentials),
        обновление по refresh_token и поставщик живого токена: функция,
        которая отдаёт токен и берёт новый за минуту до срока, одним
        обновлением на все файберы. Так почта входит по XOAUTH2, а клиент
        чужого API ставит Bearer.

        Отказ — пара с родом: state, denied, rejected, malformed,
        unavailable, refused. Зависит от tnt-http (запросы к службе
        и кодирование адреса), tnt-hash (вызов PKCE и сверка state),
        tnt-must (проверки аргументов), tnt-clock (стенные часы сроков)
        и tnt-external (подмена часов и случайных байтов в проверках).
    ]],
    homepage = 'https://github.com/tnt-skein/tnt-oauth2',
    issues_url = 'https://github.com/tnt-skein/tnt-oauth2/issues',
    maintainer = 'tnt-skein',
    license = 'MIT',
    labels = { 'tarantool', 'oauth2', 'oauth', 'pkce', 'authentication', 'xoauth2' },
}

dependencies = {
    'lua >= 5.1',
    -- Проверки настроек и аргументов на строке вызывающего.
    'tnt-must',
    -- Запросы к точкам службы и кодирование адреса авторизации.
    'tnt-http',
    -- Вызов PKCE (SHA-256 в base64url) и сверка state за постоянное время.
    'tnt-hash',
    -- Стенные часы: срок токена, срок входа, миг удостоверения.
    'tnt-clock',
    -- Подмена часов и случайных байтов в проверках.
    'tnt-external',
}

build = {
    type = 'builtin',
    modules = {
        ['tnt.oauth2'] = 'tnt/oauth2.lua',
        ['tnt.oauth2.client'] = 'tnt/oauth2/client.lua',
        ['tnt.oauth2.endpoint'] = 'tnt/oauth2/endpoint.lua',
        ['tnt.oauth2.failure'] = 'tnt/oauth2/failure.lua',
        ['tnt.oauth2.login'] = 'tnt/oauth2/login.lua',
        ['tnt.oauth2.outside'] = 'tnt/oauth2/outside.lua',
        ['tnt.oauth2.profile'] = 'tnt/oauth2/profile.lua',
        ['tnt.oauth2.secret'] = 'tnt/oauth2/secret.lua',
        ['tnt.oauth2.settings'] = 'tnt/oauth2/settings.lua',
        ['tnt.oauth2.source'] = 'tnt/oauth2/source.lua',
        ['tnt.oauth2.token'] = 'tnt/oauth2/token.lua',
    },
}
