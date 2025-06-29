#!/bin/bash

# SSH Keys Setup Script for VLESS Proxy Server
# Скрипт настройки SSH-ключей для VLESS прокси-сервера
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

# Получение параметров
get_server_info() {
    print_step "Настройка SSH-ключей"
    
    read -p "Введите IP адрес сервера: " SERVER_IP
    read -p "Введите SSH порт (по умолчанию 2323): " SSH_PORT
    SSH_PORT=${SSH_PORT:-2323}
    read -p "Введите имя пользователя на сервере: " USERNAME
    
    # Генерация уникального имени для SSH config
    read -p "Введите имя для SSH конфига (по умолчанию vless-proxy-${SERVER_IP##*.}): " SSH_HOST_NAME
    SSH_HOST_NAME=${SSH_HOST_NAME:-vless-proxy-${SERVER_IP##*.}}
    
    print_status "Сервер: $USERNAME@$SERVER_IP:$SSH_PORT"
    print_status "SSH имя: $SSH_HOST_NAME"
}

# Проверка существования ключей
check_existing_keys() {
    print_step "Проверка существующих SSH-ключей"
    
    if [ -f ~/.ssh/id_rsa ]; then
        print_status "SSH-ключи уже существуют"
        read -p "Использовать существующие ключи? (Y/n): " USE_EXISTING
        if [[ $USE_EXISTING =~ ^[Nn]$ ]]; then
            GENERATE_NEW=true
        else
            GENERATE_NEW=false
        fi
    else
        print_status "SSH-ключи не найдены, будут созданы новые"
        GENERATE_NEW=true
    fi
}

# Генерация новых ключей
generate_keys() {
    if [ "$GENERATE_NEW" = true ]; then
        print_step "Генерация новых SSH-ключей"
        
        # Создание директории если не существует
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        
        # Генерация ключей
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
        
        print_status "SSH-ключи созданы"
    fi
}

# Копирование ключа на сервер
copy_key_to_server() {
    print_step "Копирование публичного ключа на сервер"
    
    print_warning "Вам потребуется ввести пароль пользователя $USERNAME"
    
    # Копирование ключа
    ssh-copy-id -p $SSH_PORT $USERNAME@$SERVER_IP
    
    print_status "Публичный ключ скопирован на сервер"
}

# Тестирование подключения
test_connection() {
    print_step "Тестирование подключения по ключу"
    
    print_status "Попытка подключения без пароля..."
    
    if ssh -p $SSH_PORT -o PasswordAuthentication=no $USERNAME@$SERVER_IP "echo 'SSH ключи работают корректно!'"; then
        print_status "Подключение по SSH-ключам успешно!"
    else
        print_error "Ошибка подключения по SSH-ключам"
        exit 1
    fi
}

# Отключение аутентификации по паролю
disable_password_authentication() {
    print_step "Отключение аутентификации по паролю на сервере"
    
    print_status "Настройка SSH для работы только с ключами..."
    print_warning "Потребуется ввести пароль пользователя $USERNAME для sudo команд"
    
    # Создаем временный скрипт на сервере
    print_status "Создание временного скрипта на сервере..."
    ssh -p $SSH_PORT $USERNAME@$SERVER_IP "cat > /tmp/disable_ssh_password.sh << 'SCRIPT_EOF'
#!/bin/bash
echo 'Настройка SSH конфигурации...'

# Отключение аутентификации по паролю
echo '1. Отключение PasswordAuthentication...'
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Включение аутентификации по ключам
echo '2. Настройка PubkeyAuthentication...'
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Запрет пустых паролей
echo '3. Настройка PermitEmptyPasswords...'
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Проверка и добавление недостающих строк
echo '4. Проверка настроек...'
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config
grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' | sudo tee -a /etc/ssh/sshd_config
grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config

# Показать текущие настройки
echo '5. Текущие настройки SSH:'
sudo grep -E '^(PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config

# Перезапуск SSH
echo '6. Перезапуск SSH сервиса...'
sudo systemctl restart sshd

echo 'SSH настроен для работы только с ключами!'
SCRIPT_EOF"
    
    # Делаем скрипт исполняемым
    ssh -p $SSH_PORT $USERNAME@$SERVER_IP "chmod +x /tmp/disable_ssh_password.sh"
    
    # Запускаем скрипт с интерактивным терминалом
    print_status "Запуск настройки SSH (потребуется ввод пароля)..."
    ssh -t -p $SSH_PORT $USERNAME@$SERVER_IP "/tmp/disable_ssh_password.sh"
    
    # Удаляем временный скрипт
    ssh -p $SSH_PORT $USERNAME@$SERVER_IP "rm -f /tmp/disable_ssh_password.sh"
    
    if [ $? -eq 0 ]; then
        print_status "Аутентификация по паролю отключена, SSH работает только с ключами"
    else
        print_error "Ошибка при настройке SSH. Проверьте настройки вручную."
    fi
}

# Создание SSH конфига
create_ssh_config() {
    print_step "Создание SSH конфигурации"
    
    SSH_CONFIG_ENTRY="
# VLESS Proxy Server ($SERVER_IP)
Host $SSH_HOST_NAME
    HostName $SERVER_IP
    Port $SSH_PORT
    User $USERNAME
    IdentityFile ~/.ssh/id_rsa
    PasswordAuthentication no
"
    
    # Проверка существования записи
    if grep -q "Host $SSH_HOST_NAME" ~/.ssh/config 2>/dev/null; then
        print_warning "Запись $SSH_HOST_NAME уже существует в SSH config"
        read -p "Заменить существующую запись? (y/N): " REPLACE_CONFIG
        if [[ $REPLACE_CONFIG =~ ^[Yy]$ ]]; then
            # Удаление старой записи
            sed -i "/^# VLESS Proxy Server ($SERVER_IP)$/,/^$/d" ~/.ssh/config 2>/dev/null || true
            sed -i "/^Host $SSH_HOST_NAME$/,/^$/d" ~/.ssh/config 2>/dev/null || true
            echo "$SSH_CONFIG_ENTRY" >> ~/.ssh/config
            print_status "SSH конфигурация обновлена"
        else
            print_warning "SSH конфигурация не изменена"
        fi
    else
        # Создание SSH config если не существует
        mkdir -p ~/.ssh
        touch ~/.ssh/config
        echo "$SSH_CONFIG_ENTRY" >> ~/.ssh/config
        print_status "SSH конфигурация создана"
    fi
    
    chmod 600 ~/.ssh/config
    print_status "Теперь можно подключаться командой: ssh $SSH_HOST_NAME"
}

# Создание скрипта для SSH туннеля
create_tunnel_script() {
    print_step "Создание скрипта для SSH туннеля к панели 3X-UI"
    
    TUNNEL_SCRIPT="#!/bin/bash
# SSH Tunnel to 3X-UI Panel
echo 'Создание SSH туннеля к панели 3X-UI...'
echo 'Панель будет доступна по адресу: http://127.0.0.1:23456/'
echo 'Логин/Пароль: admin/admin'
echo 'Для остановки нажмите Ctrl+C'
echo ''
ssh -L 23456:127.0.0.1:2053 $SSH_HOST_NAME
"
    
    echo "$TUNNEL_SCRIPT" > ~/vless-tunnel-${SSH_HOST_NAME}.sh
    chmod +x ~/vless-tunnel-${SSH_HOST_NAME}.sh
    
    print_status "Скрипт туннеля создан: ~/vless-tunnel-${SSH_HOST_NAME}.sh"
}

# Показать финальные инструкции
show_instructions() {
    print_step "Настройка SSH-ключей завершена!"
    
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}   SSH Keys Setup Complete!    ${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
    echo -e "${BLUE}Доступные команды:${NC}"
    echo "1. Подключение к серверу: ssh $SSH_HOST_NAME"
    echo "2. SSH туннель к панели: ~/vless-tunnel-${SSH_HOST_NAME}.sh"
    echo "3. Прямое подключение: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
    echo ""
    echo -e "${BLUE}Панель 3X-UI:${NC}"
    echo "1. Запустите: ~/vless-tunnel-${SSH_HOST_NAME}.sh"
    echo "2. Откройте браузер: http://127.0.0.1:23456/"
    echo "3. Логин/Пароль: admin/admin"
    echo ""
    echo -e "${BLUE}Следующие шаги:${NC}"
    echo "1. Подключитесь к серверу: ssh $SSH_HOST_NAME"
    echo "2. Запустите сканирование Reality: sudo /opt/scan_reality.sh"
    echo "3. Настройте VLESS соединения через веб-панель"
    echo ""
    echo -e "${YELLOW}Все готово для настройки VLESS прокси!${NC}"
}

# Основная функция
main() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "     SSH Keys Setup v1.0         "
    echo "=================================="
    echo -e "${NC}"
    
    get_server_info
    check_existing_keys
    generate_keys
    copy_key_to_server
    test_connection
    disable_password_authentication
    create_ssh_config
    create_tunnel_script
    show_instructions
}

# Запуск основной функции
main "$@"