#!/bin/bash

# ===================================================================================
# Итоговый интерактивный скрипт для полной настройки Ubuntu в качестве VPN-роутера
# на базе Xray. Автоматизирует очистку, установку и настройку.
# Версия: 0.10.
# ===================================================================================

# Этот скрипт поможет вам полностью настроить сервер как VPN-роутер.
# Не требуется опыт работы с Linux — просто следуйте инструкциям на экране.
# На каждом этапе будут пояснения и подсказки.

# --- Цвета для красивого вывода ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Глобальные переменные ---
WAN_INTERFACE=""
LAN_INTERFACE=""
LAN_IP=""
VLESS_LINK_FILE="./vless_link.txt"

# --- Функции для организации кода ---
print_header() {
    echo -e "\n${GREEN}=======================================================${NC}"
    echo -e "${GREEN} $1${NC}"
    echo -e "${GREEN}=======================================================${NC}"
}

show_menu() {
    while true; do
        print_header "Выберите режим работы скрипта"
        echo -e "${YELLOW}Что вы хотите сделать?${NC}"
        echo -e "  ${GREEN}1)${NC} Удаление и установка (полная настройка VPN-роутера)"
        echo -e "  ${GREEN}2)${NC} Обновление конфигурации Xray (только перенастройка VPN)"
        echo -e "  ${GREEN}3)${NC} Только удаление (очистка системы от предыдущих настроек)"
        echo -e "  $ ======================================================================== "
        echo -e "  $ Следующие команды выполняется в ручном режиме "
        echo -e "  $ ======================================================================== "
        echo -e "  ${GREEN}4)${NC} Отключение визуальной оболочки Ubuntu"
        echo -e "  ${GREEN}5)${NC} Включение визуальной оболочки Ubuntu"
        echo -e "  ${GREEN}6)${NC} Настройка SSH"
        echo -e "  ${GREEN}7)${NC} Выход из программы"
        echo ""
        echo -e "${YELLOW}По умолчанию будет выполнен пункт 1 (если просто нажать Enter)${NC}"
        echo ""
        read -p "Введите ваш выбор [1]: " -n 1 -r
        echo ""
        
        if [[ -z "$REPLY" ]]; then
            REPLY="1"
        fi
        
        case $REPLY in
            1)
                echo -e "${GREEN}Выбран режим: Удаление и установка${NC}"
                return 1
                ;;
            2)
                echo -e "${GREEN}Выбран режим: Обновление конфигурации Xray${NC}"
                return 2
                ;;
            3)
                echo -e "${GREEN}Выбран режим: Только удаление${NC}"
                return 3
                ;;
            4)
                echo -e "${GREEN}Выбран режим: Отключение визуальной оболочки Ubuntu${NC}"
                return 4
                ;;
            5)
                echo -e "${GREEN}Выбран режим: Включение визуальной оболочки Ubuntu${NC}"
                return 5
                ;;
            6)
                echo -e "${GREEN}Выбран режим: Настройка SSH${NC}"
                return 6
                ;;
            7)
                echo -e "${GREEN}Выход из программы${NC}"
                return 7
                ;;
            *)
                echo -e "${RED}Неверный выбор. Пожалуйста, выберите число от 1 до 7${NC}"
                echo ""
                ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}Ошибка: Этот скрипт необходимо запустить с правами root (используя sudo).${NC}"
       echo -e "\n${YELLOW}Подсказка: Введите 'sudo bash ./{название скрипта}'${NC}"
       exit 1
    fi
}

check_vless_link() {
    print_header "Проверка VLESS-ссылки"
    echo -e "${YELLOW}Для настройки VPN необходима VLESS-ссылка от вашего провайдера.${NC}"
    
    if [[ ! -f "$VLESS_LINK_FILE" ]]; then
        echo -e "${RED}Файл с VLESS-ссылкой ($VLESS_LINK_FILE) не найден.${NC}"
        echo
        echo -e "${YELLOW}Выберите способ предоставления VLESS-ссылки:${NC}"
        echo -e "  ${GREEN}1)${NC} Ввести название файла с конфигурацией"
        echo -e "  ${GREEN}2)${NC} Ввести VLESS-ссылку с клавиатуры"
        echo -e "  ${GREEN}3)${NC} Отменить установку"
        echo
        read -p "Введите ваш выбор (1-3): " -n 1 -r
        echo
        
        case $REPLY in
            1)
                echo -e "${GREEN}Выбран ввод названия файла${NC}"
                echo
                echo -e "${YELLOW}Файлы в текущей директории:${NC}"
                
                # Проверяем наличие файлов с нужными расширениями
                FILES_FOUND=false
                for ext in txt json conf; do
                    if ls *.$ext 1>/dev/null 2>&1; then
                        FILES_FOUND=true
                        break
                    fi
                done
                
                if [ "$FILES_FOUND" = true ]; then
                    # Показываем файлы с нужными расширениями
                    for ext in txt json conf; do
                        ls -la *.$ext 2>/dev/null
                    done
                    echo
                    read -p "Введите название файла с VLESS-ссылкой: " USER_FILE
                    if [[ -z "$USER_FILE" ]]; then
                        echo -e "${RED}Название файла не может быть пустым.${NC}"
                        echo
                        check_vless_link
                        return
                    fi
                    if [[ ! -f "$USER_FILE" ]]; then
                        echo -e "${RED}Файл '$USER_FILE' не найден.${NC}"
                        echo
                        check_vless_link
                        return
                    fi
                    VLESS_LINK_FILE="$USER_FILE"
                    echo -e "${GREEN}Файл '$VLESS_LINK_FILE' будет использован для чтения VLESS-ссылки.${NC}"
                else
                    echo "  (нет файлов с расширениями .txt, .json, .conf)"
                    echo
                    echo -e "${YELLOW}Возвращаемся к выбору способа предоставления VLESS-ссылки...${NC}"
                    echo
                    check_vless_link
                    return
                fi
                ;;
            2)
                echo -e "${GREEN}Выбран ввод VLESS-ссылки с клавиатуры${NC}"
                echo
                echo -e "${YELLOW}Введите или вставьте VLESS-ссылку (формат: vless://...):${NC}"
                read -r USER_VLESS_URL
                if [[ -z "$USER_VLESS_URL" ]]; then
                    echo -e "${RED}VLESS-ссылка не может быть пустой.${NC}"
                    exit 1
                fi
                if [[ ! "$USER_VLESS_URL" =~ ^vless:// ]]; then
                    echo -e "${RED}Неверный формат VLESS-ссылки. Должна начинаться с 'vless://'${NC}"
                    exit 1
                fi
                # Создаем временный файл с введенной ссылкой
                echo "# VLESS-ссылка введена с клавиатуры" > "$VLESS_LINK_FILE"
                echo "$USER_VLESS_URL" >> "$VLESS_LINK_FILE"
                echo -e "${GREEN}VLESS-ссылка сохранена в файл '$VLESS_LINK_FILE'${NC}"
                ;;
            3)
                echo -e "${YELLOW}Установка отменена пользователем.${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Неверный выбор. Установка отменена.${NC}"
                echo
                check_vless_link
                return
                ;;
        esac
    else
        echo -e "${GREEN}Файл с VLESS-ссылкой найден.${NC}"
    fi
}

cleanup_previous_install() {
    print_header "Этап 1: Полная очистка предыдущих установок"
    echo -e "${YELLOW}Этот этап удалит старые настройки и подготовит систему к новой установке.\nЕсли вы уже настраивали VPN/роутер ранее — все старые параметры будут сброшены.${NC}"
    echo "Останавливаем и отключаем старые сервисы..."
    systemctl stop xray xray-local isc-dhcp-server pppd-dns 2>/dev/null || true
    systemctl disable xray xray-local isc-dhcp-server pppd-dns 2>/dev/null || true
    poff my-pppoe-provider 2>/dev/null || true

    echo "Удаляем пакеты и их конфигурации..."
    apt-get purge -y isc-dhcp-server iptables-persistent pppoeconf 2>/dev/null || true
    
    echo "Удаляем Xray с помощью официального скрипта..."
    if [ -f /usr/local/bin/xray ]; then
        bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ remove --purge > /dev/null 2>&1
    fi

    echo "Удаляем оставшиеся конфигурационные файлы..."
    rm -rf /usr/local/etc/xray /usr/local/etc/xray-local /etc/dhcp/dhcpd.conf* /etc/default/isc-dhcp-server* /etc/gai.conf /etc/ppp/peers/my-pppoe-provider /etc/ppp/chap-secrets /etc/ppp/pap-secrets

    echo "Сбрасываем правила брандмауэра iptables до состояния по умолчанию..."
    iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
    netfilter-persistent flush

    echo -e "${GREEN}Очистка завершена.${NC}"
}

setup_pppoe_interactive() {
    print_header "Этап 1.5 (Опционально): Настройка PPPoE"
    echo -e "${YELLOW}Если ваш интернет-провайдер требует PPPoE (логин/пароль для подключения), выберите 'y'.\nЕсли не уверены — скорее всего, это не ваш случай, выберите 'n'.${NC}"
    read -p "Вам необходимо настроить PPPoE соединение для выхода в интернет? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Пропускаем настройку PPPoE."
        return
    fi

    echo -e "${YELLOW}Текущая информация о сетевых интерфейсах:${NC}"
    ip a
    echo
    # Собираем Ethernet-интерфейсы в массив (eth и enp)
    mapfile -t pppoe_eths < <(ip -br a | awk '$1 ~ /^(eth|enp)/ {print $1}')
    if [ ${#pppoe_eths[@]} -eq 0 ]; then
        echo -e "${RED}Не найдено ни одного Ethernet-интерфейса (eth*/enp*). Скрипт не может продолжить.${NC}"
        return
    fi
    echo "Пожалуйста, выберите интерфейс для PPPoE из списка:"
    for i in "${!pppoe_eths[@]}"; do echo "  $((i+1))) ${pppoe_eths[$i]}"; done
    while true; do
        read -p "Введите номер интерфейса для PPPoE (1-${#pppoe_eths[@]}): " pppoe_choice
        if [[ "$pppoe_choice" =~ ^[0-9]+$ ]] && (( pppoe_choice >= 1 && pppoe_choice <= ${#pppoe_eths[@]} )); then
            PPPOE_ETH_INTERFACE="${pppoe_eths[$((pppoe_choice-1))]}"
            break
        else
            echo -e "${RED}Неверный выбор. Пожалуйста, введите число от 1 до ${#pppoe_eths[@]}.${NC}"
        fi
    done

    read -p "Введите ваш PPPoE логин: " PPPOE_USER
    read -s -p "Введите ваш PPPoE пароль: " PPPOE_PASS
    echo

    echo "Создаём PPPoE-подключение через NetworkManager..."
    nmcli con delete DSL 2>/dev/null || true # Удаляем старое подключение, если было
    nmcli con add type pppoe con-name "DSL" ifname "$PPPOE_ETH_INTERFACE" username "$PPPOE_USER" password "$PPPOE_PASS"
    nmcli con up "DSL"

    sleep 5
    if ip link show ppp0 >/dev/null 2>&1; then
        echo -e "${GREEN}PPPoE соединение успешно установлено на интерфейсе ppp0!${NC}"
        WAN_INTERFACE="ppp0"
    else
        echo -e "${RED}Не удалось установить PPPoE соединение через nmcli.${NC}"
        echo "Скрипт продолжит работу, вам нужно будет выбрать WAN-интерфейс вручную."
    fi
}

install_dependencies() {
    print_header "Этап 2: Установка необходимых пакетов"
    echo -e "${YELLOW}Сейчас будут установлены все необходимые программы для работы роутера и VPN.\nПожалуйста, дождитесь завершения этого этапа.${NC}"
    apt-get update >/dev/null
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y curl unzip isc-dhcp-server iptables-persistent net-tools >/dev/null
}

configure_network_interactive() {
    print_header "Этап 3: Интерактивная настройка сети"
    echo -e "${YELLOW}Сейчас вы выберете, какой сетевой интерфейс будет использоваться для интернета (WAN), а какой — для локальной сети (LAN).\nЕсли не знаете, какой выбрать — ориентируйтесь по выводу 'ip a' и физическим портам на сервере.${NC}"
    
    # === Собираем интерфейсы в массив ===
    mapfile -t interfaces < <(ip -br a | awk '$1 != "lo" {print $1}')
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo -e "${RED}Не найдено ни одного сетевого интерфейса (кроме lo). Скрипт не может продолжить.${NC}"
        exit 1
    fi

    if [[ -n "$WAN_INTERFACE" ]]; then
        echo -e "${GREEN}WAN-интерфейс уже определен как '$WAN_INTERFACE' (PPPoE).${NC}"
    else
        echo -e "${YELLOW}Текущая информация о сетевых интерфейсах:${NC}"
        ip a
        echo
        echo -e "Пожалуйста, выберите ваш ${YELLOW}WAN-интерфейс${NC} (тот, что смотрит в интернет) из списка:"
        for i in "${!interfaces[@]}"; do echo "  $((i+1))) ${interfaces[$i]}"; done
        
        while true; do
            read -p "Введите номер WAN-интерфейса (1-${#interfaces[@]}): " wan_choice
            if [[ "$wan_choice" =~ ^[0-9]+$ ]] && (( wan_choice >= 1 && wan_choice <= ${#interfaces[@]} )); then
                WAN_INTERFACE="${interfaces[$((wan_choice-1))]}"
                break
            else
                echo -e "${RED}Неверный выбор. Пожалуйста, введите число от 1 до ${#interfaces[@]}.${NC}"
            fi
        done
    fi
    
    echo; echo -e "Теперь выберите ваш ${YELLOW}LAN-интерфейс${NC} (тот, что смотрит в локальную сеть):"
    for i in "${!interfaces[@]}"; do echo "  $((i+1))) ${interfaces[$i]}"; done
    
    while true; do
        read -p "Введите номер LAN-интерфейса (1-${#interfaces[@]}): " lan_choice
        if [[ "$lan_choice" =~ ^[0-9]+$ ]] && (( lan_choice >= 1 && lan_choice <= ${#interfaces[@]} )); then
            SELECTED_LAN="${interfaces[$((lan_choice-1))]}"
            if [[ "$SELECTED_LAN" == "$WAN_INTERFACE" ]]; then
                echo -e "${RED}LAN и WAN не могут быть одним и тем же интерфейсом. Выберите другой.${NC}"
            else
                LAN_INTERFACE="$SELECTED_LAN"
                break
            fi
        else
            echo -e "${RED}Неверный выбор. Пожалуйста, введите число от 1 до ${#interfaces[@]}.${NC}"
        fi
    done
    
    # === НОВЫЙ БЛОК: Улучшенный ввод IP ===
    echo
    echo -e "${YELLOW}Если оставить поле пустым, будет использован IP по умолчанию: 192.168.100.1${NC}"
    read -p "Введите статический IP-адрес для LAN-интерфейса [рекомендуется: 192.168.100.1]: " LAN_IP
    if [[ -z "$LAN_IP" ]]; then
        LAN_IP="192.168.100.1"
        echo -e "${GREEN}Ничего не введено. Использован IP-адрес по умолчанию: $LAN_IP${NC}"
    fi

    echo -e "${GREEN}Итоговая конфигурация сети: WAN: $WAN_INTERFACE, LAN: $LAN_INTERFACE, LAN IP: $LAN_IP.${NC}"
    
    if systemctl is-active --quiet NetworkManager; then RENDERER="NetworkManager"; else RENDERER="networkd"; fi
    echo "Используем сетевой менеджер (renderer): $RENDERER"
    
    NETPLAN_FILE=$(find /etc/netplan -name "*.yaml" -type f | head -n 1); if [[ -z "$NETPLAN_FILE" ]]; then NETPLAN_FILE="/etc/netplan/01-router-config.yaml"; fi
    
    echo "Создаем постоянную конфигурацию сети в файле $NETPLAN_FILE...";
    
    cat <<EOF > "$NETPLAN_FILE"
network:
  version: 2
  renderer: $RENDERER
  ethernets:
    $LAN_INTERFACE:
      dhcp4: no
      addresses:
        - $LAN_IP/24
EOF

    if [[ "$WAN_INTERFACE" == wlp* || "$WAN_INTERFACE" == wlan* ]]; then
        cat <<EOF >> "$NETPLAN_FILE"
  wifis:
    $WAN_INTERFACE:
      dhcp4: true
      optional: true
EOF
    elif [[ "$WAN_INTERFACE" != "ppp0" ]]; then
        sed -i "/ethernets:/a \ \ \ \ $WAN_INTERFACE:\n      dhcp4: true\n      optional: true" "$NETPLAN_FILE"
    fi

    echo "Применяем сетевую конфигурацию..."; netplan apply
    
    echo "Ожидание 5 секунд для стабилизации сети..."
    sleep 5
    echo "Проверяем доступность DNS..."
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        echo -e "${RED}Критическая ошибка: нет доступа к интернету после настройки сети. Скрипт не может продолжить.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Доступ к интернету подтвержден.${NC}"
}

configure_system_core() {
    print_header "Этап 4: Настройка параметров ядра Linux"
    echo -e "${YELLOW}Включаем маршрутизацию между сетями и отключаем ненужный IPv6-форвардинг.\nЭто нужно для корректной работы роутера и безопасности.${NC}"
    echo "Включаем IPv4-форвардинг и отключаем IPv6-форвардинг..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sed -i -e '/^#net.ipv4.ip_forward=1/s/^#//' -e '/^net.ipv4.ip_forward=0/s/0/1/' /etc/sysctl.conf
    sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
    sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.conf
    echo "Настройка ядра завершена."
}

generate_xray_config() {
    echo "Обновляем конфигурацию Xray из файла VLESS-ссылки...";
    
    # --- Чтение VLESS-ссылки и парсинг ---
    VLESS_URL=$(grep -v '^#' "$VLESS_LINK_FILE" | grep -v '^$' | head -n1 | tr -d '\r\n')
    if [[ ! "$VLESS_URL" =~ ^vless:// ]]; then
        echo -e "${RED}VLESS-ссылка в файле некорректна.${NC}"
        exit 1
    fi

    # --- Парсим ссылку ---
    # Используем grep/sed/awk для извлечения параметров
    VLESS_ID=$(echo "$VLESS_URL" | sed -n 's#vless://\([^@]*\)@.*#\1#p')
    VLESS_HOST=$(echo "$VLESS_URL" | sed -n 's#vless://[^@]*@\([^:]*\):.*#\1#p')
    VLESS_PORT=$(echo "$VLESS_URL" | sed -n 's#vless://[^@]*@[^:]*:\([0-9]*\).*#\1#p')
    VLESS_PBK=$(echo "$VLESS_URL" | grep -oP 'pbk=\K[^&]*')
    VLESS_FP=$(echo "$VLESS_URL" | grep -oP 'fp=\K[^&]*')
    VLESS_SNI=$(echo "$VLESS_URL" | grep -oP 'sni=\K[^&]*')
    VLESS_SID=$(echo "$VLESS_URL" | grep -oP 'sid=\K[^&]*')
    VLESS_SPX_RAW=$(echo "$VLESS_URL" | grep -oP 'spx=\K[^&]*')
    VLESS_FLOW=$(echo "$VLESS_URL" | grep -oP 'flow=\K[^&#]*')

    # --- Декодирование URL для spx ---
    url_decode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }
    VLESS_SPX=$(printf '%b' "$(echo $VLESS_SPX_RAW | sed 's/+/ /g;s/%/\\x/g')")

    # Проверка обязательных параметров
    if [[ -z "$VLESS_ID" || -z "$VLESS_HOST" || -z "$VLESS_PORT" || -z "$VLESS_PBK" ]]; then
        echo -e "${RED}Не удалось корректно распарсить VLESS-ссылку. Проверьте формат.${NC}"
        exit 1
    fi

    # --- Генерируем config.json ---
    echo "Создаем рабочую конфигурацию Xray для роутера...";
    cat <<EOF > /usr/local/etc/xray/config.json
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door","settings":{"network":"tcp,udp","followRedirect":true},"sniffing":{"enabled":true,"destOverride":["http","tls"]},"tag":"tproxy-in"},{"listen":"0.0.0.0","port":53,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","network":"tcp,udp","port":53},"tag":"dns-in"}],"outbounds":[{"protocol":"vless","tag":"vless-reality","settings":{"vnext":[{"address":"$VLESS_HOST","port":$VLESS_PORT,"users":[{"id":"$VLESS_ID","flow":"$VLESS_FLOW","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"fingerprint":"$VLESS_FP","serverName":"$VLESS_SNI","publicKey":"$VLESS_PBK","shortId":"$VLESS_SID","spiderX":"$VLESS_SPX"}}},{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},{"protocol":"dns","tag":"dns-out"}],"routing":{"rules":[{"type":"field","inboundTag":["dns-in"],"outboundTag":"direct"},{"inboundTag":["tproxy-in"],"outboundTag":"block","type":"field","network":"udp","port":"135, 137, 138, 139"},{"inboundTag":["tproxy-in"],"outboundTag":"block","type":"field","domain":["appcenter.ms"]},{"inboundTag":["tproxy-in"],"outboundTag":"direct","type":"field","network":"udp","port":"4004","ip":["94.79.52.202"]},{"inboundTag":["tproxy-in"],"outboundTag":"direct","type":"field","domain":["vpn.iac.mchs.ru","regexp:^([a-zA-Z0-9_.-]+\\\\.)ru$","regexp:^([a-zA-Z0-9_.-]+\\\\.)su$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--p1ai$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--p1acf$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--80asehdb$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--c1avg$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--80aswg$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--80adxhks$","regexp:^([a-zA-Z0-9_.-]+\\\\.)moscow$","regexp:^([a-zA-Z0-9_.-]+\\\\.)xn--d1acj3b$","geosite:category-gov-ru","geosite:private","geosite:yandex","geosite:steam","geosite:vk"]},{"inboundTag":["tproxy-in"],"outboundTag":"direct","type":"field","protocol":["bittorrent"]},{"inboundTag":["tproxy-in"],"outboundTag":"vless-reality","type":"field"}]},"dns":{"servers":["https://1.1.1.1/dns-query","8.8.8.8"]}}

EOF
}

setup_xray() {
    print_header "Этап 5: Установка и настройка Xray"
    echo -e "${YELLOW}Xray — это современный VPN-прокси.\nСейчас будет скачан и настроен по вашей ссылке из файла vless_link.txt.${NC}"
    echo "Устанавливаем Xray...";
    bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install > /dev/null 2>&1
    echo "Скачиваем дополнительные файлы правил...";
    curl -L -o /usr/local/share/xray/geosite_zkeen.dat https://github.com/SukkaW/v2ray-rules-dat/raw/master/geosite.dat

    # Генерируем конфигурацию
    generate_xray_config
}

setup_dhcp_interactive() {
    print_header "Этап 6 (Опционально): Настройка DHCP-сервера"
    echo -e "${YELLOW}DHCP-сервер будет автоматически выдавать IP-адреса вашим устройствам в локальной сети.\nЕсли вы планируете настраивать IP-адреса на устройствах вручную, можете пропустить этот этап.${NC}"
    read -p "Вам необходимо настроить DHCP-сервер для автоматической выдачи IP-адресов? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Пропускаем настройку DHCP-сервера."
        return
    fi

    echo "Указываем LAN-интерфейс '$LAN_INTERFACE' для DHCP..."
    sed -i "s/INTERFACESv4=.*/INTERFACESv4=\"$LAN_INTERFACE\"/" /etc/default/isc-dhcp-server
    LAN_SUBNET=$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".0"}')
    LAN_BROADCAST=$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".255"}')
    RANGE_START=$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".100"}')
    RANGE_END=$(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".200"}')
    echo "Создаем конфигурацию для подсети $LAN_SUBNET..."
    cat <<EOF > /etc/dhcp/dhcpd.conf
option domain-name-servers $LAN_IP; default-lease-time 600; max-lease-time 7200; ddns-update-style none; authoritative;
subnet $LAN_SUBNET netmask 255.255.255.0 { range $RANGE_START $RANGE_END; option routers $LAN_IP; option broadcast-address $LAN_BROADCAST; }
EOF
}

setup_firewall() {
    print_header "Этап 7: Настройка брандмауэра iptables"
    echo -e "${YELLOW}Брандмауэр защитит ваш сервер и обеспечит правильную маршрутизацию трафика.\nВсе правила будут настроены автоматически.${NC}"
    echo "Создаем правила для перехвата трафика только из LAN..."
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p udp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp -j REDIRECT --to-port 12345
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p udp -j REDIRECT --to-port 12345
    echo "Создаем правило для выхода в интернет (NAT)..."
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 67:68 --sport 67:68 -j ACCEPT
    iptables -A OUTPUT -o "$LAN_INTERFACE" -p udp --dport 67:68 --sport 67:68 -j ACCEPT
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -o "$LAN_INTERFACE" -p udp --sport 53 -j ACCEPT
    echo "Сохраняем правила брандмауэра..."
    netfilter-persistent save
}

finalize() {
    print_header "Этап 8: Перезапуск и включение сервисов"
    echo -e "${YELLOW}Финальный этап! Все сервисы будут перезапущены и включены в автозагрузку.\nЧерез несколько секунд ваш сервер будет готов к работе как VPN-роутер.${NC}"

    # Проверяем, был ли настроен DHCP-сервер
    if [[ -f /etc/dhcp/dhcpd.conf ]] && grep -q "subnet.*netmask" /etc/dhcp/dhcpd.conf 2>/dev/null; then
        echo "Настройка зависимости DHCP-сервера от сети для корректного старта..."
        mkdir -p /etc/systemd/system/isc-dhcp-server.service.d
        cat <<EOF > /etc/systemd/system/isc-dhcp-server.service.d/override.conf
[Unit]
After=network-online.target
Wants=network-online.target
EOF
        systemctl daemon-reload
        systemctl restart isc-dhcp-server >/dev/null 2>&1
        systemctl enable isc-dhcp-server >/dev/null 2>&1
        DHCP_CONFIGURED=true
    else
        echo "DHCP-сервер пропущен, не настраиваем."
        DHCP_CONFIGURED=false
    fi
    
    systemctl restart xray >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
    print_header "Настройка полностью завершена!"
    echo -e "${GREEN}Ваш Ubuntu-сервер успешно настроен как VPN-шлюз.${NC}"
    echo ""
    echo -e "  - ${YELLOW}LAN-интерфейс:${NC} $LAN_INTERFACE с IP-адресом $LAN_IP"
    echo -e "  - ${YELLOW}WAN-интерфейс:${NC} $WAN_INTERFACE"
    if [[ "$DHCP_CONFIGURED" == "true" ]]; then
        echo -e "  - ${YELLOW}DHCP-сервер:${NC} раздает адреса с $(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".100"}') по $(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".200"}')"
    else
        echo -e "  - ${YELLOW}DHCP-сервер:${NC} не настроен (IP-адреса нужно настраивать вручную)"
    fi
    echo ""
    echo -e "${YELLOW}Что делать дальше:${NC}"
    echo "1. Подключите ваш ноутбук к LAN-порту '$LAN_INTERFACE' этого сервера."
    if [[ "$DHCP_CONFIGURED" == "true" ]]; then
        echo "2. Убедитесь, что в сетевых настройках ноутбука стоит получение IP и DNS 'Автоматически (DHCP)'."
    else
        echo "2. Настройте на ноутбуке статический IP из подсети $(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".0"}')/24, шлюз: $LAN_IP, DNS: $LAN_IP"
    fi
    echo "3. Интернет на ноутбуке будет работать согласно правилам Xray."
    echo "4. Интернет на самом сервере будет работать напрямую (YouTube и др. сайты будут открываться без VPN)."
    echo ""
    echo -e "${GREEN}Все готово. Спасибо за ваше терпение!${NC}"
    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
}

cleanup_only() {
    print_header "Режим: Только удаление"
    echo -e "${YELLOW}Будет выполнена полная очистка системы от всех VPN и роутерных настроек.${NC}"
    echo -e "${RED}Внимание: Все настройки будут удалены безвозвратно!${NC}"
    echo ""
    read -p "Продолжить? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Операция отменена пользователем.${NC}"
        echo ""
        echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
        read -n 1 -s
        return 1
    fi
    
    cleanup_previous_install
    
    print_header "Удаление завершено!"
    echo -e "${GREEN}Система полностью очищена от VPN и роутерных настроек.${NC}"
    echo ""
    echo -e "${YELLOW}Что было удалено:${NC}"
    echo "  - Все сервисы Xray и DHCP остановлены и отключены"
    echo "  - Удален Xray и все его конфигурации"
    echo "  - Удален DHCP-сервер и его настройки"
    echo "  - Сброшены все правила iptables"
    echo "  - Удалены PPPoE настройки"
    echo "  - Очищены конфигурационные файлы"
    echo ""
    echo -e "${GREEN}Система готова к новой настройке или к обычному использованию.${NC}"
    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
}

update_xray_config() {
    print_header "Режим: Обновление конфигурации Xray"
    echo -e "${YELLOW}Этот режим обновит только конфигурацию Xray и перезапустит сервис.${NC}"
    echo -e "${YELLOW}Используется для применения новой VLESS-ссылки без полной переустановки системы.${NC}"
    echo ""
    
    # Проверяем, что Xray установлен
    if [[ ! -f /usr/local/bin/xray ]]; then
        echo -e "${RED}Ошибка: Xray не установлен. Сначала выполните полную установку (пункт 1).${NC}"
        exit 1
    fi
    
    # Проверяем наличие VLESS-ссылки
    check_vless_link
    
    # Останавливаем сервис Xray
    echo "Останавливаем сервис Xray..."
    systemctl stop xray
    
    # Создаем резервную копию старого конфига
    BACKUP_FILE=""
    if [[ -f /usr/local/etc/xray/config.json ]]; then
        echo "Создаем резервную копию старого конфига..."
        BACKUP_FILE="/usr/local/etc/xray/config.json.backup.$(date +%Y%m%d_%H%M%S)"
        cp /usr/local/etc/xray/config.json "$BACKUP_FILE"
    fi
    
    # Генерируем новый конфиг
    generate_xray_config
    
    # Проверяем, что конфиг создан и не пустой
    echo "Проверяем, что конфиг создан..."
    if [[ ! -f /usr/local/etc/xray/config.json ]] || [[ ! -s /usr/local/etc/xray/config.json ]]; then
        echo -e "${RED}Ошибка: Не удалось создать конфиг. Восстанавливаем предыдущий конфиг.${NC}"
        if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
            mv "$BACKUP_FILE" /usr/local/etc/xray/config.json
        fi
        exit 1
    fi
    
    # Запускаем сервис Xray
    echo "Запускаем сервис Xray с новым конфигом..."
    systemctl start xray
    systemctl enable xray
    
    # Проверяем статус сервиса
    sleep 3
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}Сервис Xray успешно запущен с новым конфигом!${NC}"
    else
        echo -e "${RED}Ошибка: Не удалось запустить сервис Xray. Проверьте логи: journalctl -u xray${NC}"
        exit 1
    fi
    
    print_header "Обновление конфигурации завершено!"
    echo -e "${GREEN}Конфигурация Xray успешно обновлена и сервис перезапущен.${NC}"
    echo ""
    echo -e "${YELLOW}Проверить статус сервиса:${NC} systemctl status xray"
    echo -e "${YELLOW}Посмотреть логи:${NC} journalctl -u xray -f"
    echo ""
    echo -e "${GREEN}VPN-роутер готов к работе с новыми настройками!${NC}"
    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
}

disable_gui() {
    print_header "Режим: Отключение визуальной оболочки Ubuntu"
    echo -e "${YELLOW}Этот режим отключит графическую оболочку и переведет систему в текстовый режим.${NC}"
    echo -e "${YELLOW}После выполнения система будет загружаться в консольный режим без GUI.${NC}"
    echo ""
    echo -e "${RED}Внимание: После отключения GUI для работы понадобится SSH или прямой доступ к консоли!${NC}"
    echo ""
    read -p "Продолжить отключение визуальной оболочки? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Операция отменена пользователем.${NC}"
        echo ""
        echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
        read -n 1 -s
        return 1
    fi

    echo "Определяем текущий display manager..."
    DISPLAY_MANAGER=""
    
    # Check for common display managers
    if systemctl is-enabled gdm3 >/dev/null 2>&1; then
        DISPLAY_MANAGER="gdm3"
    elif systemctl is-enabled gdm >/dev/null 2>&1; then
        DISPLAY_MANAGER="gdm"
    elif systemctl is-enabled lightdm >/dev/null 2>&1; then
        DISPLAY_MANAGER="lightdm"
    elif systemctl is-enabled sddm >/dev/null 2>&1; then
        DISPLAY_MANAGER="sddm"
    elif systemctl is-enabled xdm >/dev/null 2>&1; then
        DISPLAY_MANAGER="xdm"
    fi

    if [[ -n "$DISPLAY_MANAGER" ]]; then
        echo "Найден display manager: $DISPLAY_MANAGER"
        echo "Останавливаем и отключаем display manager..."
        systemctl stop "$DISPLAY_MANAGER" 2>/dev/null || true
        systemctl disable "$DISPLAY_MANAGER" 2>/dev/null || true
    else
        echo "Display manager не найден или уже отключен."
    fi

    echo "Устанавливаем multi-user target как цель по умолчанию..."
    systemctl set-default multi-user.target

    echo "Останавливаем графическую сессию..."
    systemctl stop graphical.target 2>/dev/null || true

    print_header "Отключение визуальной оболочки завершено!"
    echo -e "${GREEN}Визуальная оболочка Ubuntu успешно отключена.${NC}"
    echo ""
    echo -e "${YELLOW}Изменения:${NC}"
    echo "  - Display manager ($DISPLAY_MANAGER) остановлен и отключен"
    echo "  - Система переведена в multi-user режим"
    echo "  - При следующей перезагрузке система загрузится в текстовом режиме"
    echo ""
    echo -e "${YELLOW}Для доступа к системе:${NC}"
    echo "  - Используйте SSH подключение"
    echo "  - Или прямой доступ к консоли (Ctrl+Alt+F1-F6)"
    echo ""
    echo -e "${YELLOW}Для включения GUI обратно используйте пункт 5 этого скрипта${NC}"
    echo ""
    echo -e "${GREEN}Операция завершена успешно!${NC}"
    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
    return 0
}

enable_gui() {
    print_header "Режим: Включение визуальной оболочки Ubuntu"
    echo -e "${YELLOW}Этот режим включит графическую оболочку и переведет систему в графический режим.${NC}"
    echo -e "${YELLOW}После выполнения система будет загружаться с GUI.${NC}"
    echo ""

    echo "Устанавливаем graphical target как цель по умолчанию..."
    systemctl set-default graphical.target

    echo "Определяем и устанавливаем display manager..."
    DISPLAY_MANAGER=""
    
    # Try to detect installed display managers
    if dpkg -l | grep -q "^ii.*gdm3"; then
        DISPLAY_MANAGER="gdm3"
    elif dpkg -l | grep -q "^ii.*gdm"; then
        DISPLAY_MANAGER="gdm"
    elif dpkg -l | grep -q "^ii.*lightdm"; then
        DISPLAY_MANAGER="lightdm"
    elif dpkg -l | grep -q "^ii.*sddm"; then
        DISPLAY_MANAGER="sddm"
    elif dpkg -l | grep -q "^ii.*xdm"; then
        DISPLAY_MANAGER="xdm"
    fi

    if [[ -n "$DISPLAY_MANAGER" ]]; then
        echo "Найден установленный display manager: $DISPLAY_MANAGER"
        echo "Включаем и запускаем display manager..."
        systemctl enable "$DISPLAY_MANAGER"
        systemctl start "$DISPLAY_MANAGER" 2>/dev/null || true
    else
        echo "Display manager не найден. Устанавливаем gdm3..."
        apt-get update >/dev/null 2>&1
        apt-get install -y gdm3 >/dev/null 2>&1
        DISPLAY_MANAGER="gdm3"
        echo "Включаем и запускаем gdm3..."
        systemctl enable gdm3
        systemctl start gdm3 2>/dev/null || true
    fi

    echo "Запускаем графическую цель..."
    systemctl start graphical.target 2>/dev/null || true

    # Wait a bit for services to start
    sleep 3

    print_header "Включение визуальной оболочки завершено!"
    echo -e "${GREEN}Визуальная оболочка Ubuntu успешно включена.${NC}"
    echo ""
    echo -e "${YELLOW}Изменения:${NC}"
    echo "  - Display manager ($DISPLAY_MANAGER) включен и запущен"
    echo "  - Система переведена в graphical режим"
    echo "  - При следующей перезагрузке система загрузится с GUI"
    echo ""
    echo -e "${YELLOW}Для немедленного доступа к GUI:${NC}"
    echo "  - Если вы подключены через SSH, используйте VNC или подключитесь напрямую к монитору"
    echo "  - Если работаете локально, GUI должен появиться автоматически"
    echo ""
    echo -e "${GREEN}Операция завершена успешно!${NC}"
    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
    return 0
}

setup_ssh() {
    print_header "Режим: Настройка SSH"
    echo -e "${YELLOW}Этот режим настроит SSH-сервер для удаленного доступа к системе.${NC}"
    echo -e "${YELLOW}Вы можете изменить порт и настроить пароль для пользователя.${NC}"
    echo ""

    # Проверяем установлен ли SSH
    if ! dpkg -l | grep -q "^ii.*openssh-server"; then
        echo "Устанавливаем SSH-сервер..."
        apt-get update >/dev/null 2>&1
        apt-get install -y openssh-server >/dev/null 2>&1
    fi

    # Спрашиваем порт
    echo -e "${YELLOW}Настройка порта SSH:${NC}"
    echo -e "${YELLOW}Если оставить поле пустым, будет использован порт по умолчанию: 2213${NC}"
    read -p "Введите порт для SSH [по умолчанию: 2213]: " SSH_PORT
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="2213"
        echo -e "${GREEN}Ничего не введено. Использован порт по умолчанию: $SSH_PORT${NC}"
    fi

    # Валидация порта
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        echo -e "${RED}Неверный порт. Используется порт по умолчанию: 2213${NC}"
        SSH_PORT="2213"
    fi

    echo ""
    echo -e "${YELLOW}Настройка пользователя для SSH:${NC}"
    
    # Показываем доступных пользователей
    echo -e "${YELLOW}Доступные пользователи в системе:${NC}"
    awk -F: '$3>=1000 && $3<65534 {print "  - " $1}' /etc/passwd
    echo "  - root"
    echo ""
    
    # Спрашиваем пользователя
    read -p "Введите имя пользователя для SSH доступа [по умолчанию: root]: " SSH_USER
    if [[ -z "$SSH_USER" ]]; then
        SSH_USER="root"
        echo -e "${GREEN}Использован пользователь по умолчанию: $SSH_USER${NC}"
    fi

    # Проверяем существование пользователя
    if ! id "$SSH_USER" >/dev/null 2>&1; then
        echo -e "${RED}Пользователь '$SSH_USER' не существует. Используется root.${NC}"
        SSH_USER="root"
    fi

    # Обязательно требуем пароль
    echo ""
    echo -e "${RED}Внимание: Необходимо установить пароль для пользователя '$SSH_USER'${NC}"
    while true; do
        read -s -p "Введите новый пароль для пользователя '$SSH_USER': " SSH_PASSWORD
        echo ""
        if [[ -z "$SSH_PASSWORD" ]]; then
            echo -e "${RED}Пароль не может быть пустым. Попробуйте ещё раз.${NC}"
            continue
        fi
        read -s -p "Подтвердите пароль: " SSH_PASSWORD_CONFIRM
        echo ""
        if [[ "$SSH_PASSWORD" != "$SSH_PASSWORD_CONFIRM" ]]; then
            echo -e "${RED}Пароли не совпадают. Попробуйте ещё раз.${NC}"
            continue
        fi
        break
    done

    echo ""
    echo -e "${GREEN}Применяем настройки SSH...${NC}"

    # Устанавливаем пароль пользователю
    echo "$SSH_USER:$SSH_PASSWORD" | chpasswd
    echo "Пароль для пользователя '$SSH_USER' установлен."

    # Создаем резервную копию конфига SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

    # Настраиваем SSH конфигурацию
    sed -i "s/#*Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/#*PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config
    sed -i "s/#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
    sed -i "s/#*PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config

    # Добавляем настройки, если их нет
    if ! grep -q "^Port" /etc/ssh/sshd_config; then
        echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
    fi

    # Настраиваем файрвол (если iptables активен)
    iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    netfilter-persistent save 2>/dev/null || true

    # Перезапускаем SSH
    systemctl restart ssh
    systemctl enable ssh

    # Проверяем статус
    sleep 2
    if systemctl is-active --quiet ssh; then
        print_header "Настройка SSH завершена!"
        echo -e "${GREEN}SSH-сервер успешно настроен и запущен.${NC}"
        echo ""
        echo -e "${YELLOW}Параметры подключения:${NC}"
        echo "  - Порт: $SSH_PORT"
        echo "  - Пользователь: $SSH_USER"
        echo "  - Пароль: *** (установлен)"
        echo ""
        echo -e "${YELLOW}Для подключения используйте:${NC}"
        echo "  ssh -p $SSH_PORT $SSH_USER@<IP_адрес_сервера>"
        echo ""
        echo -e "${YELLOW}IP-адреса этого сервера:${NC}"
        ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1'
        echo ""
        echo -e "${GREEN}SSH готов к использованию!${NC}"
    else
        echo -e "${RED}Ошибка: Не удалось запустить SSH-сервер. Проверьте логи: journalctl -u ssh${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Нажмите любую клавишу для возврата к меню...${NC}"
    read -n 1 -s
    return 0
}

# --- Основной поток выполнения ---
check_root

# Основной цикл для повторного показа меню при отмене операций
while true; do
    # Показываем меню выбора режима
    show_menu
    MODE=$?

    case $MODE in
        1)
            # Режим: Удаление и установка (полная настройка)
            check_vless_link
            cleanup_previous_install
            setup_pppoe_interactive
            install_dependencies
            configure_network_interactive
            configure_system_core
            setup_xray
            setup_dhcp_interactive
            setup_firewall
            finalize
            # Возвращаемся к меню после выполнения
            ;;
        2)
            # Режим: Обновление конфигурации Xray
            update_xray_config
            # Возвращаемся к меню после выполнения
            ;;
        3)
            # Режим: Только удаление
            cleanup_only
            # Возвращаемся к меню после выполнения
            ;;
        4)
            # Режим: Отключение визуальной оболочки Ubuntu
            disable_gui
            # Всегда возвращаемся к меню после выполнения
            ;;
        5)
            # Режим: Включение визуальной оболочки Ubuntu
            enable_gui
            # Всегда возвращаемся к меню после выполнения
            ;;
        6)
            # Режим: Настройка SSH
            setup_ssh
            # Всегда возвращаемся к меню после выполнения
            ;;
        7)
            # Выход из программы
            echo -e "${YELLOW}Спасибо за использование скрипта! До свидания!${NC}"
            break
            ;;
    esac
done

exit 0