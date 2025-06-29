#!/bin/bash

# VLESS Proxy Server Auto Setup Script
# Автоматизированная установка VLESS прокси-сервера
# Версия: 1.0

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Проверка запуска от root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен от имени root"
        exit 1
    fi
}

# Получение пользовательского ввода
get_user_input() {
    print_step "Сбор конфигурационных данных"
    
    # SSH порт
    while true; do
        read -p "Введите новый SSH порт (по умолчанию 2323): " SSH_PORT
        SSH_PORT=${SSH_PORT:-2323}
        if [[ $SSH_PORT =~ ^[0-9]+$ ]] && [ $SSH_PORT -ge 1024 ] && [ $SSH_PORT -le 65535 ]; then
            break
        else
            print_error "Порт должен быть числом от 1024 до 65535"
        fi
    done
    
    # Имя нового пользователя
    while true; do
        read -p "Введите имя нового пользователя (по умолчанию vlessuser): " NEW_USER
        NEW_USER=${NEW_USER:-vlessuser}
        if [[ $NEW_USER =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            break
        else
            print_error "Имя пользователя должно содержать только строчные буквы, цифры, _ и -"
        fi
    done
    
    # IP адрес сервера
    SERVER_IP=$(curl -4 -s ifconfig.me || curl -4 -s ipinfo.io/ip || curl -4 -s icanhazip.com || curl -s ipv4.icanhazip.com)
    read -p "IP адрес сервера (автоопределен: $SERVER_IP): " CUSTOM_IP
    SERVER_IP=${CUSTOM_IP:-$SERVER_IP}
    
    print_status "Конфигурация:"
    print_status "SSH порт: $SSH_PORT"
    print_status "Новый пользователь: $NEW_USER"
    print_status "IP сервера: $SERVER_IP"
    
    read -p "Продолжить? (y/N): " CONFIRM
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        print_error "Установка отменена"
        exit 1
    fi
}

# Обновление системы
update_system() {
    print_step "Обновление системы"
    apt update && apt upgrade -y
    print_status "Система обновлена"
}

# Смена пароля root
change_root_password() {
    print_step "Смена пароля root"
    print_warning "Сейчас будет предложено сменить пароль root"
    passwd
    print_status "Пароль root изменен"
}

# Настройка SSH
configure_ssh() {
    print_step "Настройка SSH"
    
    # Создание резервной копии конфига SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Изменение порта SSH
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    
    print_status "SSH порт изменен на $SSH_PORT"
}

# Настройка firewall
configure_firewall() {
    print_step "Настройка firewall"
    
    # Разрешение нового SSH порта
    ufw allow $SSH_PORT/tcp

    # Разрешить HTTPS запросы
    ufw allow 443
    
    # Включение UFW
    ufw --force enable
    
    print_status "Firewall настроен"
}

# Перезапуск SSH
restart_ssh() {
    print_step "Перезапуск SSH сервиса"
    systemctl restart sshd
    print_status "SSH сервис перезапущен"
    print_warning "Новое подключение: ssh -p $SSH_PORT root@$SERVER_IP"
}

# Создание нового пользователя
create_user() {
    print_step "Создание нового пользователя: $NEW_USER"
    
    # Создание пользователя
    adduser --gecos "" $NEW_USER
    
    # Добавление в группу sudo
    usermod -aG sudo $NEW_USER
    
    print_status "Пользователь $NEW_USER создан и добавлен в группу sudo"
}

# Настройка SSH для нового пользователя
configure_ssh_security() {
    print_step "Настройка безопасности SSH"
    
    # Отключение входа root
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Включение аутентификации по ключам (но оставляем пароли для нового пользователя)
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # Убеждаемся что аутентификация по паролю включена для настройки SSH-ключей
    sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # Добавление строк если их нет
    grep -q "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
    grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    
    print_status "SSH безопасность настроена (аутентификация по паролю временно включена)"
}

# Установка пакетов
install_packages() {
    print_step "Установка необходимых пакетов"
    
    apt install -y git nmap net-tools curl docker.io docker-compose openssl python3 python3-pip wget unzip jq
    
    # Запуск Docker
    systemctl enable docker
    systemctl start docker
    
    print_status "Пакеты установлены"
}

# Скачивание RealiTLScanner
download_realitlscanner() {
    print_step "Скачивание RealiTLScanner"
    
    cd /opt
    wget https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.1/RealiTLScanner-linux-64
    chmod +x RealiTLScanner-linux-64
    
    print_status "RealiTLScanner скачан в /opt/"
}

# Установка 3X-UI панели
install_3xui() {
    print_step "Установка панели 3X-UI"
    
    cd /opt
    git clone https://github.com/MHSanaei/3x-ui.git
    cd 3x-ui
    
    # Переключение на стабильную версию
    git checkout v2.4.5
    
    # Изменение docker-compose.yml для использования конкретной версии
    sed -i 's/latest/v2.4.5/g' docker-compose.yml
    
    # Запуск панели
    docker-compose up -d
    
    # Открытие порта для панели
    ufw allow 2053/tcp
    
    print_status "Панель 3X-UI установлена и запущена"
    
    # Ожидание запуска панели
    # print_status "Ожидание запуска панели (30 секунд)..."
    # sleep 30
}

# Настройка 3X-UI панели
# todo доработать, сейчас не устанавливается автоматом 
configure_3xui() {
    print_step "Автоматическая настройка панели 3X-UI"
    
    print_status "Создание базовой конфигурации Xray с блокировками..."
    
    # Создание директории для конфигурации
    mkdir -p /opt/3x-ui/config
    
    # Создание базовой конфигурации Xray с блокировками
    cat > /opt/3x-ui/config/xray_template.json << 'EOF'
{
    "api": {
        "tag": "api",
        "services": ["HandlerService", "LoggerService", "StatsService"]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 62789,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            },
            "tag": "api"
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "inboundTag": ["api"],
                "outboundTag": "api",
                "type": "field"
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all",
                    "geosite:category-porn"
                ],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ru",
                    "regexp:.*\\.ru$",
                    "regexp:.*\\.su$"
                ],
                "outboundTag": "blocked"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": false,
                "statsUserDownlink": false,
                "bufferSize": 10240
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }
    },
    "stats": {}
}
EOF
    
    # Создание скрипта для настройки панели
    print_status "Создание скрипта настройки панели..."
    cat > /opt/configure_3xui_panel.sh << 'EOF'
#!/bin/bash

# Скрипт для настройки 3X-UI панели
# Запускается после установки для применения настроек

API_BASE="http://127.0.0.1:2053"
COOKIE_JAR="/tmp/3xui_cookies.txt"

echo "Ожидание запуска панели..."
sleep 30

echo "Попытка настройки панели через API..."

# Получение CSRF токена
LOGIN_PAGE=$(curl -s -c "$COOKIE_JAR" "$API_BASE/login" 2>/dev/null)
CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -o 'name="_csrf" value="[^"]*"' | cut -d'"' -f4)

if [ -n "$CSRF_TOKEN" ]; then
    echo "CSRF токен получен: $CSRF_TOKEN"
    
    # Авторизация
    curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -X POST "$API_BASE/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=admin&_csrf=$CSRF_TOKEN" > /dev/null 2>&1
    
    echo "Авторизация выполнена"
    
    # Попытка настройки через разные endpoints
    echo "Настройка webListen и webDomain..."
    
    # Способ 1: через /panel/setting
    curl -s -b "$COOKIE_JAR" \
        -X POST "$API_BASE/panel/setting" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "webListen=127.0.0.1&webDomain=127.0.0.1&webPort=2053&_csrf=$CSRF_TOKEN" > /dev/null 2>&1
    
    # Способ 2: через API
    curl -s -b "$COOKIE_JAR" \
        -X POST "$API_BASE/panel/api/inbounds/setting" \
        -H "Content-Type: application/json" \
        -d '{"webListen":"127.0.0.1","webDomain":"127.0.0.1","webPort":2053}' > /dev/null 2>&1
    
    echo "Настройки применены"
else
    echo "Не удалось получить CSRF токен"
fi

# Очистка
rm -f "$COOKIE_JAR"

echo "Настройка завершена"
echo "Проверьте настройки в веб-интерфейсе: http://127.0.0.1:23456/panel/settings"
EOF
    
    chmod +x /opt/configure_3xui_panel.sh
    
    print_status "Базовая конфигурация создана:"
    print_status "- Шаблон Xray с блокировками: /opt/3x-ui/config/xray_template.json"
    print_status "- Скрипт настройки панели: /opt/configure_3xui_panel.sh"
    print_status "- Блокировка BitTorrent: включена"
    print_status "- Блокировка рекламы и контента 18+: включена"
    print_status "- Блокировка российских сайтов: включена"
    
    print_warning "Для применения настроек панели выполните после перезагрузки:"
    print_warning "sudo /opt/configure_3xui_panel.sh"
}

# Создание скрипта для сканирования
create_scanner_script() {
    print_step "Создание скрипта для сканирования"
    
    cat > /opt/scan_reality.sh << EOF
#!/bin/bash
echo "Запуск сканирования Reality сайтов для IP: $SERVER_IP"
cd /opt
./RealiTLScanner-linux-64 -addr $SERVER_IP
EOF
    
    chmod +x /opt/scan_reality.sh
    print_status "Скрипт сканирования создан: /opt/scan_reality.sh"
}

# Создание информационного файла
create_info_file() {
    print_step "Создание информационного файла"
    
    cat > /root/vless_setup_info.txt << EOF
=== VLESS Proxy Server Setup Complete ===

Конфигурация сервера:
- SSH порт: $SSH_PORT
- Пользователь: $NEW_USER
- IP сервера: $SERVER_IP

Подключение к серверу:
ssh -p $SSH_PORT $NEW_USER@$SERVER_IP

Панель управления 3X-UI:
- Порт: 2053
- Логин: admin
- Пароль: admin
- Доступ через SSH туннель: ssh -L 23456:127.0.0.1:2053 $NEW_USER@$SERVER_IP -p $SSH_PORT
- URL панели: http://127.0.0.1:23456/

Полезные команды:
- Сканирование Reality сайтов: /opt/scan_reality.sh
- Настройка панели: /opt/configure_3xui_panel.sh (todo доработается позже)
- Проверка портов: ss -lntup
- Статус Docker: docker ps
- Логи 3X-UI: cd /opt/3x-ui && docker-compose logs

Следующие шаги:
1. Настройте SSH ключи для пользователя $NEW_USER
2. Запустите настройку панели: sudo /opt/configure_3xui_panel.sh
3. Запустите сканирование Reality: /opt/scan_reality.sh
4. Подключитесь к панели 3X-UI и настройте VLESS соединения

ВАЖНО: Сохраните этот файл в безопасном месте!
EOF
    
    print_status "Информационный файл создан: /root/vless_setup_info.txt"
}

# Финальные инструкции
show_final_instructions() {
    print_step "Установка завершена!"
    
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  VLESS Proxy Setup Complete!  ${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
    echo -e "${YELLOW}ВАЖНО:${NC} Сейчас сервер будет перезагружен для применения всех изменений."
    echo ""
    echo -e "${BLUE}После перезагрузки:${NC}"
    echo "1. Подключитесь как новый пользователь: ssh -p $SSH_PORT $NEW_USER@$SERVER_IP"
    echo "2. Настройте SSH ключи для безопасного доступа"
    echo "3. Запустите настройку панели: sudo /opt/configure_3xui_panel.sh (todo доработается позже)" 
    echo "4. Запустите сканирование: sudo /opt/scan_reality.sh"
    echo "5. Подключитесь к панели через SSH туннель"
    echo ""
    echo -e "${BLUE}Панель 3X-UI:${NC}"
    echo "- SSH туннель: ssh -L 23456:127.0.0.1:2053 $NEW_USER@$SERVER_IP -p $SSH_PORT"
    echo "- URL: http://127.0.0.1:23456/"
    echo "- Логин/Пароль: admin/admin"
    echo ""
    echo -e "${YELLOW}Все детали сохранены в: /root/vless_setup_info.txt${NC}"
    echo ""
    
    read -p "Нажмите Enter для перезагрузки сервера..."
}

# Основная функция
main() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "   VLESS Proxy Auto Setup v1.0   "
    echo "=================================="
    echo -e "${NC}"
    
    check_root
    get_user_input
    
    update_system
    change_root_password
    configure_ssh
    configure_firewall
    restart_ssh
    
    print_warning "Теперь создайте нового пользователя. SSH будет перенастроен после создания пользователя."
    create_user
    configure_ssh_security
    
    install_packages
    download_realitlscanner
    install_3xui
    # configure_3xui (донастроить позже)
    create_scanner_script
    create_info_file
    
    # Финальный перезапуск SSH
    systemctl restart sshd
    
    show_final_instructions
    
    # Перезагрузка
    reboot
}

# Запуск основной функции
main "$@"