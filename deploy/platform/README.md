# Стенд с нуля: deploy/platform

Скрипт `bootstrap.sh` поднимает весь стенд на чистом Ubuntu 24.04: k3s с Traefik,
Helm, cert-manager, namespace `pdn` с Redis, HTTPS-редирект, сертификат, стек
мониторинга (Prometheus, Grafana и дашборд), Headlamp и сам сервис `pdn-shield`.
Каждый шаг идемпотентен: повторный запуск ничего не ломает и только закрывает
пропуски.

## Требования

- Сервер Ubuntu 24.04, 4 vCPU / 8 GiB RAM, доступ по SSH от `root`.
- DNS-записи, указывающие на IP сервера:
  - `@` (alfa-hakaton-prod.ru) и `www.` ведут на сервис `pdn-shield`;
  - `grafana.` ведёт на Grafana;
  - `k8s.` ведёт на Headlamp.
- Открытые порты в файрволе: `22`, `80`, `443`, `6443` (скрипт сам добавит их в ufw).

## Переменные

| Переменная | Обязательная | Назначение |
| --- | --- | --- |
| `DOMAIN` | да | публичный домен, по умолчанию `alfa-hakaton-prod.ru` |
| `ACME_EMAIL` | да | email аккаунта Let's Encrypt |
| `GRAFANA_ADMIN_PASSWORD` | да | пароль админа Grafana (в файлы не пишется) |
| `SERVER_IP` | нет | публичный IP сервера; по умолчанию берётся из A-записи `DOMAIN` |
| `REMOTE` | нет | ssh-цель, например `root@1.2.3.4`; запустить на сервере через ssh |
| `PDN_ENC_KEY` | нет | ключ шифрования хранилища; генерируется, если пуст |
| `MODEL_KEY` | нет | ключ шлюза LLM; генерируется, если пуст |
| `PDN_DEMO_KEY` | нет | ключ системы `demo`; генерируется, если пуст |
| `PDN_CHATBOT_KEY` | нет | ключ системы `chatbot`; генерируется, если пуст |

Значения сгенерированных ключей не печатаются, только имена. Пароль Grafana и
ключи нигде не сохраняются в открытом виде.

## Одна команда запуска

Локально от root:

```bash
sudo DOMAIN=alfa-hakaton-prod.ru \
     ACME_EMAIL=you@example.com \
     GRAFANA_ADMIN_PASSWORD='сложный-пароль' \
     ./deploy/platform/bootstrap.sh
```

С ноутбука через ssh (скрипт копируется на сервер и выполняется там):

```bash
REMOTE=root@SERVER_IP \
DOMAIN=alfa-hakaton-prod.ru \
ACME_EMAIL=you@example.com \
GRAFANA_ADMIN_PASSWORD='сложный-пароль' \
./deploy/platform/bootstrap.sh
```

Через Makefile:

```bash
make platform-bootstrap REMOTE=root@SERVER_IP \
     DOMAIN=alfa-hakaton-prod.ru ACME_EMAIL=you@example.com \
     GRAFANA_ADMIN_PASSWORD='сложный-пароль'
```

Проверить, что будет сделано, без изменений на сервере:

```bash
make platform-render
```

## Что получится

- **k3s** (одноузловой, Traefik, metrics-server) с `--tls-san $SERVER_IP --tls-san $DOMAIN`.
- **cert-manager** с ClusterIssuer `letsencrypt-prod` и `letsencrypt-staging`.
- Namespace **pdn**: Redis, Middleware `https-redirect`, Certificate `pdn-shield-tls`.
- **kube-prometheus-stack** (Alertmanager выключен, retention 2 дня), ServiceMonitor
  `pdn-shield`, дашборд «pdn-shield», Ingress Grafana на `grafana.$DOMAIN`.
- **Headlamp** с Ingress на `k8s.$DOMAIN` и ServiceAccount `headlamp-admin`.
- Секрет `pdn-shield-secrets` и сам сервис через `kubectl apply -k deploy/k8s`.

## Как посмотреть

- **Grafana**: https://grafana.alfa-hakaton-prod.ru, логин `admin`, пароль из
  `GRAFANA_ADMIN_PASSWORD`. Дашборд «pdn-shield» появится автоматически.
- **Headlamp**: https://k8s.alfa-hakaton-prod.ru, на экране входа вставьте токен,
  который скрипт печатает в конце (команда `kubectl -n headlamp get secret
  headlamp-admin-token -o jsonpath='{.data.token}' | base64 -d`). Токен в файл не
  сохраняется.

## Как выпускается TLS

Сертификаты выпускает cert-manager через ACME `http-01` (Let's Encrypt). Для
каждого хоста создаётся отдельный `Certificate`:

- `pdn-shield-tls` (ns `pdn`) покрывает `$DOMAIN` и `www.$DOMAIN`;
- `grafana-tls` (ns `monitoring`) покрывает `grafana.$DOMAIN`;
- `headlamp-tls` (ns `headlamp`) покрывает `k8s.$DOMAIN`.

HTTP автоматически редиректится на HTTPS через Traefik Middleware. После выпуска
сертификата обновление происходит автоматически.

## Структура

```
deploy/platform/
  README.md
  bootstrap.sh
  namespace.yaml
  redis.yaml
  cert-manager/
    cluster-issuers.tpl.yaml
    certificate.tpl.yaml
  traefik/
    https-redirect.yaml
  monitoring/
    values.tpl.yaml
    servicemonitor.yaml
    dashboard-configmap.yaml
  headlamp/
    values.tpl.yaml
    admin.yaml
    middleware.yaml
```

Файлы с `${VAR}` называются `*.tpl.yaml`; скрипт рендерит их через `envsubst` в
`/tmp/pdn-platform-render` перед `kubectl apply`. Паролей, токенов и IP в открытом
виде в манифестах нет, только значения по умолчанию переменных в этом README.