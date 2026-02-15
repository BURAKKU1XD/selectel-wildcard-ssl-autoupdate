# Selectel wildcard SSL Auto Updater

Скрипт автоматически:

- Получает SSL-сертификаты из Selectel Certificate Manager
- Сохраняет их локально
- Атомарно обновляет сертификаты в nginx
- Создаёт бэкапы старых файлов
- Может автоматически создать systemd-службу и ежедневный таймер


---

## Требования

- Linux с systemd
- Python 3.8+
- Доступ к Selectel API
- Root-доступ для установки службы

---

## Установка (без git)

### 1. Загрузка

```bash
curl -L https://github.com/BURAKKU1XD/selectel-wildcard-ssl-autoupdate/archive/refs/heads/main.tar.gz | tar xz \
&& cd selectel-wildcard-ssl-autoupdate-main \
&& cp -n example.env .env
```

### 1?. Загрузка в `/usr/local/bin/`

```bash
cd /usr/local/bin/ \
&& curl -L https://github.com/BURAKKU1XD/selectel-wildcard-ssl-autoupdate/archive/refs/heads/main.tar.gz | tar xz \
&& cd selectel-wildcard-ssl-autoupdate-main \
&& cp -n example.env .env
```
### 2. Заполнить .env по шаблону
```env
# Selectel service user (IAM)
SELECTEL_USERNAME=имя сервисного акка, буквально
SELECTEL_ACCOUNT_ID=ид акка из панели(справа сверху)
SELECTEL_PASSWORD=пароль сервисного акка
SELECTEL_PROJECT_NAME=Имя проекта

# URLs (можно не трогать — дефолты адекватные)
SELECTEL_IDENTITY_URL=https://cloud.api.selcloud.ru/identity/v3
SELECTEL_LE_BASE_URL=https://api.selectel.ru/certs/le
SELECTEL_CERT_MANAGER_URL=https://cloud.api.selcloud.ru/certificate-manager/v1

# Где хранить версии сертификатов по доменам (там папочка со всеми сертификатами и датой их окончания)
CERT_STORE_DIR=/etc/nginx/ssl

# Разрешённые префиксы путей, которые скрипт имеет право менять (через запятую)
# (по умолчанию берётся CERT_STORE_DIR)
MANAGED_PREFIXES=/etc/nginx/ssl,/etc/letsencrypt/live

# Если remote отличается от local меньше чем на N минут — не обновлять
MIN_EXPIRE_DIFF_MINUTES=720

# Служебное
LOG_LEVEL=INFO
# LOG_FILE=/var/log/selectel-ssl-autorenew.log
HTTP_TIMEOUT=60
NGINX_BIN=nginx
SYSTEMCTL_BIN=systemctl
```
### 3. Создать сервис
```bash
chmod +x create_service.sh
```
Запуск раз в день и при запуске сервера.



