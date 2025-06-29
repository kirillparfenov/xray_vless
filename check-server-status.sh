#!/bin/bash

# VLESS Proxy Server Status Check Script
# Скрипт проверки статуса VLESS прокси-сервера
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
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Проверка системы
check_system() {
    print_header "=== Проверка системы ==="
    
    # Время работы системы
    uptime_info=$(uptime -p)
    print_info "Время работы: $uptime_info"
    
    # Использование памяти
    memory_usage=$(free -h | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
    print_info "Использование памяти: $memory_usage"
    
    # Использование диска
    disk_usage=$(df -h / | awk 'NR==2{print $5}')
    print_info "Использование диска: $disk_usage"
    
    # Загрузка CPU
    cpu_load=$(uptime | awk -F'load average:' '{print $2}')
    print_info "Загрузка CPU:$cpu_load"
    
    echo ""
}

# Проверка SSH
check_ssh() {
    print_header "=== Проверка SSH ==="
    
    if systemctl is-active --quiet sshd; then
        print_status "SSH сервис активен"
        
        # Проверка порта SSH
        ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
        if [ -n "$ssh_port" ]; then
            print_info "SSH порт: $ssh_port"
        else
            print_warning "SSH порт не изменен (используется 22)"
        fi
        
        # Проверка настроек безопасности
        if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
            print_status "Root вход отключен"
        else
            print_warning "Root вход разрешен"
        fi
        
        if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
            print_status "Аутентификация по паролю отключена"
        else
            print_warning "Аутентификация по паролю включена"
        fi
    else
        print_error "SSH сервис не активен"
    fi
    
    echo ""
}

# Проверка firewall
check_firewall() {
    print_header "=== Проверка Firewall ==="
    
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status | head -1)
        if echo "$ufw_status" | grep -q "active"; then
            print_status "UFW активен"
            
            # Показать открытые порты
            print_info "Открытые порты:"
            ufw status numbered | grep -E "^\[.*\]" | while read line; do
                echo "  $line"
            done
        else
            print_warning "UFW неактивен"
        fi
    else
        print_warning "UFW не установлен"
    fi
    
    echo ""
}

# Проверка Docker
check_docker() {
    print_header "=== Проверка Docker ==="
    
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker; then
            print_status "Docker активен"
            
            # Версия Docker
            docker_version=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
            print_info "Версия Docker: $docker_version"
            
            # Запущенные контейнеры
            running_containers=$(docker ps --format "table {{.Names}}\t{{.Status}}" | tail -n +2)
            if [ -n "$running_containers" ]; then
                print_info "Запущенные контейнеры:"
                echo "$running_containers" | while read line; do
                    echo "  $line"
                done
            else
                print_warning "Нет запущенных контейнеров"
            fi
        else
            print_error "Docker не активен"
        fi
    else
        print_error "Docker не установлен"
    fi
    
    echo ""
}

# Проверка 3X-UI
check_3xui() {
    print_header "=== Проверка 3X-UI ==="
    
    if [ -d "/opt/3x-ui" ]; then
        print_status "Директория 3X-UI найдена"
        
        cd /opt/3x-ui
        
        # Проверка статуса контейнера
        if docker-compose ps | grep -q "Up"; then
            print_status "3X-UI контейнер запущен"
            
            # Проверка порта 2053
            if ss -lntup | grep -q ":2053"; then
                print_status "Порт 2053 прослушивается"
            else
                print_warning "Порт 2053 не прослушивается"
            fi

            # Проверка порта 443
            if ss -lntup | grep -q ":443"; then
                print_status "Порт 443 прослушивается"
            else
                print_warning "Порт 443 не прослушивается"
            fi
            
            # Проверка логов (последние 5 строк)
            print_info "Последние логи 3X-UI:"
            docker-compose logs --tail=5 | sed 's/^/  /'
            
        else
            print_error "3X-UI контейнер не запущен"
        fi
    else
        print_error "3X-UI не установлен"
    fi
    
    echo ""
}

# Проверка RealiTLScanner
check_realitlscanner() {
    print_header "=== Проверка RealiTLScanner ==="
    
    if [ -f "/opt/RealiTLScanner-linux-64" ]; then
        print_status "RealiTLScanner найден"
        
        if [ -x "/opt/RealiTLScanner-linux-64" ]; then
            print_status "RealiTLScanner исполняемый"
        else
            print_warning "RealiTLScanner не исполняемый"
        fi
        
        if [ -f "/opt/scan_reality.sh" ]; then
            print_status "Скрипт сканирования найден"
        else
            print_warning "Скрипт сканирования не найден"
        fi
    else
        print_error "RealiTLScanner не найден"
    fi
    
    echo ""
}

# Проверка сетевых соединений
check_network() {
    print_header "=== Проверка сети ==="
    
    # Внешний IP
    external_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "Не удалось определить")
    print_info "Внешний IP: $external_ip"
    
    # Прослушиваемые порты
    print_info "Прослушиваемые порты:"
    ss -lntup | grep LISTEN | awk '{print $5}' | sort -u | while read port; do
        echo "  $port"
    done
    
    # Проверка подключения к интернету
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        print_status "Подключение к интернету работает"
    else
        print_error "Нет подключения к интернету"
    fi
    
    echo ""
}

# Показать полезные команды
show_useful_commands() {
    print_header "=== Полезные команды ==="
    
    echo -e "${BLUE}Управление 3X-UI:${NC}"
    echo "  cd /opt/3x-ui && docker-compose restart  # Перезапуск"
    echo "  cd /opt/3x-ui && docker-compose logs     # Просмотр логов"
    echo "  cd /opt/3x-ui && docker-compose down     # Остановка"
    echo "  cd /opt/3x-ui && docker-compose up -d    # Запуск"
    echo ""
    
    echo -e "${BLUE}Сканирование Reality:${NC}"
    echo "  /opt/scan_reality.sh                     # Запуск сканирования"
    echo ""
    
    echo -e "${BLUE}Мониторинг системы:${NC}"
    echo "  htop                                     # Мониторинг процессов"
    echo "  ss -lntup                               # Открытые порты"
    echo "  ufw status                              # Статус firewall"
    echo "  docker ps                               # Docker контейнеры"
    echo ""
    
    echo -e "${BLUE}SSH туннель к панели:${NC}"
    echo "  ssh -L 23456:127.0.0.1:2053 user@server -p port"
    echo "  Затем откройте: http://127.0.0.1:23456/"
    echo ""
}

# Основная функция
main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "   VLESS Proxy Server Status Check     "
    echo "========================================"
    echo -e "${NC}"
    
    check_system
    check_ssh
    check_firewall
    check_docker
    check_3xui
    check_realitlscanner
    check_network
    show_useful_commands
    
    echo -e "${GREEN}========================================"
    echo "         Проверка завершена            "
    echo "========================================${NC}"
}

# Запуск основной функции
main "$@"