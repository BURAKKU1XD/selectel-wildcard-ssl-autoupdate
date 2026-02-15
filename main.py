#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
cert_update.py

Автообновление wildcard TLS сертификатов Selectel (Let's Encrypt) и бесшовная
переключалка nginx через симлинки/атомарную замену файлов.

Без внешних зависимостей (только стандартная библиотека).
"""

import argparse
import sys
from datetime import datetime, timedelta
from utils.env import load_dotenv
from utils.logger import setup_logging
from utils.nginx import *
from utils.openssl import *
from utils.other import *
from utils.parsers import  *
from utils.selectel_api import *



def main() -> int:
    parser = argparse.ArgumentParser(description="Selectel SSL auto-renew + nginx seamless switch")
    parser.add_argument("--dry-run", action="store_true", help="Ничего не пишем на диск и не перезагружаем nginx")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(script_dir, ".env")
    env = load_dotenv(env_path)

    setup_logging(env.get("LOG_LEVEL", "INFO"), env.get("LOG_FILE"))

    # обязательные
    username = env.get("SELECTEL_USERNAME") or env.get("SERVICE_USERNAME")
    account_id = env.get("SELECTEL_ACCOUNT_ID") or env.get("ACCOUNT_ID")
    password = env.get("SELECTEL_PASSWORD") or env.get("SERVICE_PASSWORD")
    project_name = env.get("SELECTEL_PROJECT_NAME") or env.get("PROJECT_NAME")

    if not all([username, account_id, password, project_name]):
        logging.error(
            "Не хватает переменных в .env. Нужно: SELECTEL_USERNAME, SELECTEL_ACCOUNT_ID, SELECTEL_PASSWORD, SELECTEL_PROJECT_NAME"
        )
        return 2

    identity_url = env.get("SELECTEL_IDENTITY_URL", "https://cloud.api.selcloud.ru/identity/v3")
    le_base_url = env.get("SELECTEL_LE_BASE_URL", "https://api.selectel.ru/certs/le")
    cert_manager_url = env.get("SELECTEL_CERT_MANAGER_URL", "https://cloud.api.selcloud.ru/certificate-manager/")

    nginx_bin = env.get("NGINX_BIN", "nginx")
    systemctl_bin = env.get("SYSTEMCTL_BIN", "systemctl")

    cert_store_dir = env.get("CERT_STORE_DIR", "/etc/nginx/ssl")
    http_timeout = int(env.get("HTTP_TIMEOUT", "30"))

    # дополнительные папки, в которых лежат cert/key для других сервисов
    extra_cert_dirs_raw = env.get("EXTRA_CERT_DIRS", "")
    extra_cert_dirs = [p.strip() for p in extra_cert_dirs_raw.split(",") if p.strip()]

    # какие пути мы вообще разрешаем менять
    # если MANAGED_PREFIXES не задан — разрешаем CERT_STORE_DIR + EXTRA_CERT_DIRS
    default_prefixes = [cert_store_dir] + extra_cert_dirs if extra_cert_dirs else [cert_store_dir]
    managed_prefixes = env.get("MANAGED_PREFIXES", ",".join(default_prefixes))
    managed_prefixes_list = [p.strip() for p in managed_prefixes.split(",") if p.strip()]
    # На сколько "должен быть новее" remote, чтобы обновлять (в минутах)
    min_diff_minutes = int(env.get("MIN_EXPIRE_DIFF_MINUTES", "60"))

    now_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    updated_any = False

    try:
        token = get_selectel_project_token(
            identity_url=identity_url,
            username=username,
            account_id=account_id,
            password=password,
            project_name=project_name,
            timeout=http_timeout,
        )
        logging.info("IAM-токен проекта получен.")

        items = list_selectel_le_certs(le_base_url, token, timeout=http_timeout)
        logging.info("Список LE сертификатов Selectel получен: %d шт.", len(items))

        latest = build_latest_cert_map(items)

        pairs_nginx = parse_nginx_ssl_pairs(nginx_bin) or []
        pairs_extra = scan_extra_ssl_pairs(extra_cert_dirs) if extra_cert_dirs else []

        if not pairs_nginx and not pairs_extra:
            logging.warning("Не нашёл ни одной пары SSL ни в nginx, ни в EXTRA_CERT_DIRS.")
            return 0

        # объединяем пары без дублей; если пара есть в nginx — считаем её nginx (для reload)
        nginx_set = set((os.path.abspath(c), os.path.abspath(k)) for c, k in pairs_nginx)
        extra_set = set((os.path.abspath(c), os.path.abspath(k)) for c, k in pairs_extra)
        all_pairs = sorted(nginx_set.union(extra_set))

        logging.info("Нашёл SSL-пары: nginx=%d, extra=%d, итого=%d", len(nginx_set), len(extra_set), len(all_pairs))

        updated_nginx_any = False

        for cert_path, key_path in all_pairs:
            is_nginx_pair = (cert_path, key_path) in nginx_set
            if not os.path.exists(cert_path):
                logging.warning("cert_path не существует: %s (пропускаю)", cert_path)
                continue
            if not os.path.exists(key_path):
                logging.warning("key_path не существует: %s (пропускаю)", key_path)
                continue

            local_exp = get_cert_not_after(cert_path)
            if not local_exp:
                logging.warning("Не смог определить срок действия локального сертификата: %s", cert_path)
                continue

            domen = infer_domain_from_cert(cert_path) or infer_domain_from_path(cert_path)
            if not domen:
                logging.warning("Не смог определить домен для сертификата: %s (пропускаю)", cert_path)
                continue

            remote = latest.get(domen)

            if not remote:
                logging.info("В Selectel не нашёл сертификат для домена %s (пропускаю)", domen)
                continue

            remote_exp = parse_selectel_date(remote.get("expire_at") or "")
            if not remote_exp:
                logging.warning("У Selectel сертификата нет expire_at или не распарсилось: домен=%s", domen)
                continue

            diff = remote_exp - local_exp
            logging.info(
                "Домен %s: local_exp=%s, remote_exp=%s, diff=%s",
                domen,
                local_exp.isoformat(sep=" "),
                remote_exp.isoformat(sep=" "),
                diff,
            )

            if diff <= timedelta(minutes=min_diff_minutes):
                continue  # локальный не хуже (или почти равен)

            knox_id = remote.get("knox_cert_id") or remote.get("id")
            if not knox_id:
                logging.warning("Нет knox_cert_id/id у remote сертификата для %s (пропускаю)", domen)
                continue

            # скачиваем bundle
            logging.info("Найден более новый сертификат для %s. Скачиваю knox_cert_id=%s", domen, knox_id)
            certs, privkey = download_selectel_cert_bundle(cert_manager_url, token, knox_id, timeout=http_timeout)

            # раскладываем по файлам
            leaf = certs[0].strip() + "\n"
            chain = "\n".join([c.strip() for c in certs[1:]]).strip()
            chain = (chain + "\n") if chain else ""
            fullchain = leaf + chain

            # создаём папку хранения
            dom_dir = os.path.join(cert_store_dir, domen)
            ver_dir = os.path.join(dom_dir, remote_exp.strftime("%Y-%m-%d_%H-%M-%S"))
            logging.info("Пишу сертификаты в: %s", ver_dir)

            if not args.dry_run:
                ensure_dir(ver_dir)

            cert_p = os.path.join(ver_dir, "cert.pem")
            chain_p = os.path.join(ver_dir, "chain.pem")
            fullchain_p = os.path.join(ver_dir, "fullchain.pem")
            key_p = os.path.join(ver_dir, "privkey.pem")

            if args.dry_run:
                logging.info("[dry-run] Записал бы: %s, %s, %s, %s", cert_p, chain_p, fullchain_p, key_p)
            else:
                write_file(cert_p, leaf, 0o644)
                write_file(chain_p, chain or "", 0o644)
                write_file(fullchain_p, fullchain, 0o644)
                write_file(key_p, privkey, 0o600)

            # обновляем пути из nginx конфига (только если разрешены)
            if not path_allowed(cert_path, managed_prefixes_list):
                logging.error(
                    "cert_path вне разрешённых префиксов (%s): %s (пропускаю обновление этого пути)",
                    managed_prefixes_list,
                    cert_path,
                )
                continue
            if not path_allowed(key_path, managed_prefixes_list):
                logging.error(
                    "key_path вне разрешённых префиксов (%s): %s (пропускаю обновление этого пути)",
                    managed_prefixes_list,
                    key_path,
                )
                continue

            new_cert_file = os.path.join(ver_dir, pick_cert_filename_for_nginx_target(cert_path))
            new_key_file = key_p

            logging.info("Переключаю nginx пути:\n  %s -> %s\n  %s -> %s", cert_path, new_cert_file, key_path,
                         new_key_file)
            atomic_update_link_or_file(cert_path, new_cert_file, now_stamp, args.dry_run)
            atomic_update_link_or_file(key_path, new_key_file, now_stamp, args.dry_run)

            updated_any = True
            if is_nginx_pair:
                updated_nginx_any = True

        # reload/restart nginx — только если обновлялись nginx-пары
        if updated_nginx_any:
            nginx_reload_or_restart(systemctl_bin, nginx_bin, args.dry_run)
        elif updated_any:
            logging.info("Сертификаты обновлены (extra), nginx не трогаю.")
        else:
            logging.info("Обновлений не требуется.")

        return 0

    except Exception:
        logging.exception("Фатальная ошибка")
        return 1


if __name__ == "__main__":
    sys.exit(main())
