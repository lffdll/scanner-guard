# Scanner Guard (standalone)

Блокирует входящие соединения из подсетей известных сканеров (РКН и госсети) на любом Linux-сервере — с 3x-ui или без. Панель не нужна и не затрагивается.

- Бэкенд: ipset + iptables, а если их нет — нативный nftables.
- Режутся только новые входящие соединения (`ctstate NEW`) от адресов из списка; клиенты и уже установленные соединения не затрагиваются.
- Список обновляется каждые 6 часов и после перезагрузки (systemd-таймер, без systemd — cron).
- Если список не скачался, остаётся прежний.

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/lffdll/scanner-guard/main/scanner-guard.sh -o /tmp/scanner-guard.sh && sudo bash /tmp/scanner-guard.sh install
```

С белым списком и своим источником:

```bash
sudo bash /tmp/scanner-guard.sh install --whitelist 203.0.113.0/24 --source https://example.com/list.txt
```

## Управление

```bash
sudo scanner-guard status
```

```bash
sudo scanner-guard update
```

```bash
sudo scanner-guard uninstall
```

## Настройки

| Файл | Назначение |
| --- | --- |
| `/etc/scanner-guard/sources.list` | URL списков, по одному в строке |
| `/etc/scanner-guard/whitelist.list` | IP или CIDR, которые никогда не блокируются |

После правки файлов выполните `sudo scanner-guard update`.

## Ограничения

- Подсети короче /8 (IPv4) и /16 (IPv6) из списков отбрасываются — защита от ошибочной строки в чужом списке.
- Правило ставится в цепочку `INPUT` и, если есть Docker, в `DOCKER-USER`.
- Недостающие пакеты (curl, ipset, iptables) ставятся через apt, dnf или yum.
