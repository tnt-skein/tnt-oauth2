#!/usr/bin/env bash
# Поднимает службу OAuth 2.0 для живых проверок клиента tnt-oauth2.
#
# mock-oauth2-server — настоящая служба протокола, а не двойник: точка
# авторизации отвечает переходом с кодом и state, точка токенов меняет
# код на токены только с верным проверочным кодом PKCE (чужой —
# invalid_grant), обновляет токены и выдаёт токены самому клиенту,
# точка профиля отвечает на Bearer и отвергает чужой. Вход без окна
# (interactiveLogin: false): точка авторизации сразу уводит на адрес
# возврата, и проверке не нужен браузер.
#
# Двойник показывает, что мы правильно разговариваем сами с собой,
# а настоящая служба — что нас понимает кто-то ещё: кодирование формы,
# заголовок Basic, разбор ответа.
#
#   test/stand/oauth2.sh          # поднять
#   test/stand/oauth2.sh stop     # погасить
#
# Описание службы: http://127.0.0.1:18480/default/.well-known/openid-configuration
set -euo pipefail

cd "$(dirname "$0")"

OAUTH2_IMAGE='ghcr.io/navikt/mock-oauth2-server:2.1.10'
OAUTH2_CONTAINER='tnt-stand-oauth2'
OAUTH2_PORT='18480'

if ! command -v docker > /dev/null 2>&1; then
    echo 'docker не найден: службу OAuth 2.0 поднять нечем' >&2
    exit 1
fi

if [ "${1:-up}" = 'stop' ]; then
    docker rm -f "${OAUTH2_CONTAINER}" > /dev/null 2>&1 || true
    echo 'служба OAuth 2.0 остановлена'
    exit 0
fi

mkdir -p run

# Повторный запуск безвреден: контейнер с тем же именем сносится
# и поднимается заново. Токены в нём проверочные, жалеть их незачем.
docker rm -f "${OAUTH2_CONTAINER}" > /dev/null 2>&1 || true

docker run -d \
    --name "${OAUTH2_CONTAINER}" \
    -p "127.0.0.1:${OAUTH2_PORT}:8080" \
    -e JSON_CONFIG='{"interactiveLogin":false}' \
    "${OAUTH2_IMAGE}" > /dev/null

echo "${OAUTH2_CONTAINER}" > run/oauth2.containers

# Готовности ждём: проверки, запущенные сразу после подъёма, иначе
# пропустятся — и это выглядит как «всё хорошо», хотя ничего
# не проверено.
for _ in $(seq 1 60); do
    if curl -s -f -o /dev/null "http://127.0.0.1:${OAUTH2_PORT}/default/.well-known/openid-configuration"; then
        echo "служба OAuth 2.0 поднята: http://127.0.0.1:${OAUTH2_PORT}/default"
        exit 0
    fi

    sleep 0.5
done

echo 'служба OAuth 2.0 не ответила за 30 секунд: смотрите docker logs' >&2
exit 1
