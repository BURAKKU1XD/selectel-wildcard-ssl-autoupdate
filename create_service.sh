#!/bin/sh
set -e

ENV_FILE=".env"

if [ ! -f "$ENV_FILE" ]; then
  echo ".env файл не найден"
  exit 1
fi

# читаем SELECTEL_PROJECT_NAME
SELECTEL_PROJECT_NAME=$(grep '^SELECTEL_PROJECT_NAME=' "$ENV_FILE" | cut -d= -f2)

if [ -z "$SELECTEL_PROJECT_NAME" ]; then
  echo "SELECTEL_PROJECT_NAME не найден в .env"
  exit 1
fi

SERVICE_NAME="selectel-cert-update-${SELECTEL_PROJECT_NAME}.service"
TIMER_NAME="selectel-cert-update-${SELECTEL_PROJECT_NAME}.timer"

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
TIMER_PATH="/etc/systemd/system/${TIMER_NAME}"

SCRIPT_PATH="$(readlink -f "$0")"
WORKDIR="$(dirname "$SCRIPT_PATH")"

# --- создаем service если нет ---
if [ ! -f "$SERVICE_PATH" ]; then
  echo "Создаю службу $SERVICE_NAME"

  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Selectel SSL updater (${SELECTEL_PROJECT_NAME})
After=network.target

[Service]
Type=oneshot
WorkingDirectory=${WORKDIR}
ExecStart=/usr/bin/python3 ${WORKDIR}/main.py
User=root
EOF
else
  echo "Служба уже существует"
fi

# --- создаем timer если нет ---
if [ ! -f "$TIMER_PATH" ]; then
  echo "Создаю таймер $TIMER_NAME"

  cat > "$TIMER_PATH" <<EOF
[Unit]
Description=Daily Selectel SSL updater (${SELECTEL_PROJECT_NAME})

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
else
  echo "Таймер уже существует"
fi

# --- применяем ---
systemctl daemon-reload
systemctl enable "$TIMER_NAME"
systemctl start "$TIMER_NAME"

echo "Готово."
echo "Проверка:"
echo "systemctl status $TIMER_NAME"