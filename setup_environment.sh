#!/bin/bash
# setup_environment.sh - Настройка окружения для перехвата трафика

set -e  # Выход при ошибке

echo "========================================"
echo "НАСТРОЙКА ОКРУЖЕНИЯ ДЛЯ АНАЛИЗА ТРАФИКА"
echo "========================================"

echo -e "\n1. Установка зависимостей Python..."
python3 -m pip install --upgrade pip
pip install -r requirements.txt

echo -e "\n2. Проверка установки Scapy..."
python3 -c "import scapy; print('✅ Scapy установлен:', scapy.__version__)"

echo -e "\n3. Настройка правил iptables для перехвата трафика..."
echo "ВНИМАНИЕ: Требуются права sudo для настройки iptables!"

# Проверяем, есть ли уже правило
if ! sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null; then
    echo "Добавляем правило для отключения RST-пакетов..."
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    echo "✅ Правило добавлено"
else
    echo "✅ Правило уже существует"
fi

echo -e "\n4. Информация о сетевых интерфейсах..."
ip addr show | grep -E "^[0-9]+:" | grep -v "lo:" | head -5

echo -e "\n5. Рекомендации по запуску Google Gruyere:"
echo "   Вариант 1: Локальный запуск (рекомендуется для анализа):"
echo "   $ git clone https://github.com/google/gruyere"
echo "   $ cd gruyere && python3 gruyere.py"
echo ""
echo "   Вариант 2: Облачный доступ (HTTPS, сложнее для анализа):"
echo "   https://google-gruyere.appspot.com"
echo ""
echo "   Вариант 3: Свой сервер (нужен публичный IP):"
echo "   $ python3 gruyere.py --port=8080 --address=0.0.0.0"

echo -e "\n6. Проверка доступных портов..."
echo "   Порт 8080: $(sudo lsof -i :8080 2>/dev/null | wc -l) процессов"
echo "   Порт 80: $(sudo lsof -i :80 2>/dev/null | wc -l) процессов"
echo "   Порт 443: $(sudo lsof -i :443 2>/dev/null | wc -l) процессов"

echo -e "\n========================================"
echo "НАСТРОЙКА ЗАВЕРШЕНА!"
echo -e "\nВАЖНО: После завершения работы восстановите правила:"
echo "   $ sudo ./restore_environment.sh"
echo "========================================"
