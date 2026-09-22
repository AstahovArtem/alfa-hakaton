# pdn-shield

Сервис маскирует персональные данные перед отправкой в LLM и демаскирует ответ. Он встраивается в цепочку «система-потребитель - LLM» и не даёт исходным данным уйти наружу.

```
Система -> pdn-shield [детект -> маска] -> LLM -> [демаска] -> Система
```

Сервис находит ПД в тексте, заменяет их на безопасные значения и сохраняет соответствие. Ответ модели сервис восстанавливает обратно. Исходные данные не покидают сервис и не попадают в логи.

## Быстрый старт

Скопируйте конфиг и задайте ключи в окружении.

```bash
cp configs/config.yaml configs/local.yaml
export PDN_ENC_KEY=$(openssl rand -hex 32)
make run
```

Сервис поднимется на `:8080`. Проверьте здоровье.

```bash
curl -s localhost:8080/healthz
```

Маскирование через контракт чекера.

```bash
curl -s -X POST localhost:8080/process \
  -H 'Content-Type: application/json' \
  -d '{"payload":"Клиент Иванов Иван Иванович, паспорт 4509 123456, тел +7 (916) 123-45-67","payload_id":"doc1"}'
```

Ответ содержит замаскированный текст. Тот же `payload_id` с замаскированным текстом вернёт исходник.

```bash
curl -s -X POST localhost:8080/process \
  -H 'Content-Type: application/json' \
  -d '{"payload":"<замаскированный текст>","payload_id":"doc1"}'
```

Маскирование с генерацией id.

```bash
curl -s -X POST localhost:8080/mask \
  -H 'Content-Type: application/json' \
  -d '{"text":"Клиент Иванов Иван Иванович, тел +7 (916) 123-45-67"}'
```

Демаскирование по id.

```bash
curl -s -X POST localhost:8080/unmask \
  -H 'Content-Type: application/json' \
  -d '{"id":"<id из /mask>","text":"<замаскированный текст>"}'
```

Прокси в LLM.

```bash
curl -s -X POST localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Клиент Иванов Иван Иванович, тел +7 (916) 123-45-67"}]}'
```

Демо-страница лежит на `GET /`. Она ходит в те же эндпоинты и показывает найденные типы ПД и замаскированный текст.

## Настройка систем-потребителей

Каждая система описана в `configs/config.yaml` в блоке `systems`. Чтобы добавить систему, добавьте блок с уникальным `id` и включите её через `enabled: true`. Ключ задаётся переменной окружения через `api_key_env`, пустое значение означает, что ключ не требуется. Список `categories` ограничивает, какие типы ПД маскируются, пустой список означает все типы. Стратегия `strategy` выбирает вид замены: `partial`, `token` или `synthetic`. Флаг `unmask` разрешает системе демаскировать ответ, по умолчанию он выключен.

## Добавление нового типа ПД

Простые типы добавляются правилом в `internal/pii/detectors/rules.yaml`. Укажите имя, категорию, регулярное выражение и валидатор. Сложные типы, вроде имён или адресов, получают отдельный Go-детектор в `internal/pii/detectors`. Детектор реализует интерфейс `pii.Detector` и регистрируется в `Default()`. Правки в pipeline и resolve не нужны.

## Логи и метрики

Логи пишутся в JSON через `log/slog`. На каждый запрос одна запись с полями `system`, `route`, `status`, `duration_ms`, `found` и другими. Текст, значения спанов и ключи в логи не попадают. Метрики отдаёт `GET /metrics` в формате Prometheus.

RPS по маршруту.

```promql
sum(rate(pdn_requests_total[5m])) by (route)
```

Латентность по маршруту.

```promql
histogram_quantile(0.95, sum(rate(pdn_request_duration_seconds_bucket[5m])) by (le, route))
```

TPS (токены в секунду).

```promql
sum(rate(pdn_tokens_total[5m])) by (direction)
```

## Переменные окружения

| Переменная | Назначение |
| --- | --- |
| `PDN_CONFIG` | путь к конфигу, альтернатива флагу `-config` |
| `PDN_ENC_KEY` | ключ шифрования хранилища, 32 байта hex или base64 |
| `MODEL_KEY` | ключ доступа к шлюзу LLM |
| `PDN_DEMO_KEY` | ключ системы `demo` |
| `PDN_CHATBOT_KEY` | ключ системы `chatbot` |
| `PDN_LEGACY_KEY` | ключ системы `legacy_crm` |
| `PDN_REDIS_PASSWORD` | пароль Redis, если он задан |
| `REDIS_ADDR` | адрес Redis для интеграционного теста |

## Развёртывание и нагрузка

### Локальная разработка

Сервис и Redis поднимаются через compose. Ключи берутся из `.env`.

```bash
make compose-up
make compose-down
```

### Сборка образа и деплой в k3s

Образ собирается локально и грузится в k3s через `docker save`. Реестра образов нет, поэтому `imagePullPolicy` стоит `IfNotPresent`.

```bash
export SERVER=root@62.109.26.223
make deploy
```

Скрипт `deploy/scripts/build-and-load.sh` собирает образ с тегом из короткого sha коммита, грузит его в k3s и перекатывает deployment. Тег можно задать вручную через `TAG`, а путь к kubeconfig через `KUBECONFIG`.

### Манифесты

Манифесты лежат в `deploy/k8s` и собираются через kustomize в namespace `pdn`. Применить их можно так.

```bash
make k8s-apply
```

### Секрет

Реальный секрет не хранится в репозитории. Шаблон лежит в `deploy/k8s/secret.example.yaml`. Создайте секрет командой, подставив свои ключи.

```bash
kubectl -n pdn create secret generic pdn-shield-secrets \
  --from-literal=PDN_ENC_KEY=$(openssl rand -hex 32) \
  --from-literal=MODEL_KEY=<ключ шлюза> \
  --from-literal=PDN_DEMO_KEY=<ключ demo> \
  --from-literal=PDN_CHATBOT_KEY=<ключ chatbot>
```

### Логи и метрики

Логи смотрятся через `kubectl logs`.

```bash
kubectl -n pdn logs -l app=pdn-shield -f
```

Метрики отдаёт `GET /metrics` внутри кластера, наружу он не публикуется. Дашборд «pdn-shield» доступен в Grafana по адресу https://grafana.alfa-hakaton-prod.ru.

### Нагрузочный тест

Утилита в `loadtest` воспроизводит контракт чекера: для каждого элемента датасета генерируется уникальный `payload_id`, первый запрос `POST /process` маскирует исходный текст, второй с тем же `payload_id` и замаскированным текстом должен вернуть исходник. Если второй запрос не возвращает исходный текст, это считается round-trip failure. Заголовки аутентификации по умолчанию не отправляются (система `checker`). Запуск против локального сервиса.

```bash
make load-test URL=http://localhost:8080/process RPS=200 DURATION=10s
```

Параметры можно задать и напрямую.

```bash
go run ./loadtest -url http://localhost:8080/process -rps 200 -duration 10s
```

Опциональные флаги `-system` и `-api-key` задают заголовки `X-System-Id` и `X-API-Key` для прогонов от имени других систем; по умолчанию они пустые.

```bash
go run ./loadtest -url http://localhost:8080/process -rps 200 -duration 10s -system demo -api-key "$PDN_DEMO_KEY"
```

Отчёт печатается в stdout и сохраняется в `loadtest/report-<ts>.md` (файл в `.gitignore`). В нём достигнутый RPS, ошибки по кодам, доля 429, перцентили латентности отдельно для шага mask и шага unmask и доля неверных round-trip.

## Ограничения

Прокси всегда отдаёт не-стримовый ответ, даже если клиент прислал `stream: true`. Шлюз AlfaGen принимает только `stream: true`, поэтому сервис собирает SSE-чанки и возвращает обычный JSON. Текст длиннее 64 KiB режется на чанки по границам предложений, спаны смещаются на offset чанка. При недоступности LLM сервис отвечает 502 и остаётся живым. Redis-хранилище реализовано на чистом net без внешней библиотеки, оно покрыто интеграционным тестом, который пропускается без `REDIS_ADDR`.