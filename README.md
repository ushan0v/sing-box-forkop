# sing-box-forkop

## Что нового

- **AmneziaWG 2.0 и 3.x** — обфускация WireGuard
- **Cloudflare WARP** — WARP через WireGuard с обфускацией AmneziaWG
- **TrustTunnel** — протокол AdGuard, клиент и сервер
- **mieru** — клиент и сервер
- **VLESS Encryption** — шифрование VLESS из Xray
- **XHTTP** — транспорт Xray, в том числе поверх HTTP/3
- **Fallback** — первый рабочий сервер по уровням приоритета
- **Отбор URLTest по скорости** — ограниченные HTTP-замеры и выбор по задержке среди серверов, прошедших порог пропускной способности
- **Единая задержка** — время запроса без установки соединения
- **Подписки** — ссылки, base64, Clash и mihomo, sing-box, Xray, SIP008
- **Парсер ссылок** — сервер задаётся одной ссылкой
- **DNS Fallback** — несколько DNS-серверов, переключение при сбоях
- **Текстовые rule set** — домены и подсети по одному в строке
- **Экспорт подсетей** — адреса наборов правил через Clash API для nftables
- **Адрес выхода** — IP и страна выхода подключения через Clash API
- **Tailscale в Clash API** — состояние, выходной узел и пинг устройств сети
- **Оптимизация под роутеры**
- **Улучшения и исправления**

## Сборки

Сборка задаётся тегами Go. `with_clash_api` и `with_utls` есть в любой сборке, остальные необязательны.

| Тег | Что добавляет | tiny | base | full |
| --- | --- | :---: | :---: | :---: |
| `with_quic` | Hysteria, Hysteria2, TUIC, QUIC, DNS over QUIC и HTTP/3, XHTTP поверх HTTP/3 | ✓ | ✓ | ✓ |
| `with_gvisor` | сетевой стек в памяти для туннелей | | ✓ | ✓ |
| `with_wireguard` | WireGuard, AmneziaWG, WARP | | ✓ | ✓ |
| `with_openvpn` | OpenVPN, клиент и сервер | | ✓ | ✓ |
| `with_trusttunnel` | TrustTunnel, клиент и сервер | | ✓ | ✓ |
| `with_vmess` | VMess | | ✓ | ✓ |
| `with_anytls` | AnyTLS | | ✓ | ✓ |
| `with_tailscale` | Tailscale | | | ✓ |
| `with_openconnect` | OpenConnect | | | ✓ |
| `with_naive` | NaiveProxy, клиент и сервер | | | ✓ |
| `with_mieru` | mieru | | | ✓ |
| `with_snell`, `with_ssh`, `with_shadowtls`, `with_tor` | Snell, SSH, ShadowTLS, Tor | | | ✓ |

На `386-softfloat`, `armv6`, `armv5`, `mipsle-mips32`, `mips`, `mips64le` и `mips64` сборка full выходит без NaiveProxy, для них не собирается библиотека cronet.

Теги туннелей `with_wireguard`, `with_openvpn`, `with_openconnect` и `with_tailscale` работают только вместе с `with_gvisor`. Набор тегов, который не совпадает ни с одной сборкой, называется **custom**.

## Сборка

Понадобятся Linux или WSL, git, а для пакетов apk ещё apk-tools. Нужную версию Go `build.sh` скачает сам.

```sh
./build.sh --list                          # сборки, теги, цели и архитектуры
./build.sh --arch aarch64_cortex-a53       # пакеты ipk и apk для архитектуры роутера
./build.sh arm64 mipsle                    # пакеты для выбранных целей
./build.sh --variant full arm64            # сборка full
./build.sh --binary-only amd64             # только бинарник
```

Готовые пакеты появятся в `dist/`. Сборка full при первом запуске скачивает исходники cronet и тулчейн Chromium, а это несколько гигабайт.

### Своя сборка

Параметр `--tags` меняет набор тегов выбранной сборки:

```sh
./build.sh --tags +with_openconnect arm64                     # base и OpenConnect
./build.sh --variant full --tags -with_tor,-with_ssh arm64    # full без Tor и SSH
./build.sh --tags with_quic,with_gvisor,with_wireguard arm64  # только эти теги
```

Такой пакет получает сборку `custom`. Forkop с ним работает и показывает на странице только то, что в нём есть.

## Зависимости

Исправленные зависимости лежат в [`third_party`](third_party). Это wireguard-go с AmneziaWG, gVisor, sing-openvpn и sing-vmess.

## Лицензия

Ядро распространяется по лицензии [GPL-3.0-or-later](LICENSE).
