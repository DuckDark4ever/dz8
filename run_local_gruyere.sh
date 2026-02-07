#!/bin/bash
# Скрипт для локального запуска Google Gruyere без шифрования

set -e  # Выход при ошибке

echo "========================================"
echo "ЛОКАЛЬНЫЙ ЗАПУСК GOOGLE GRUYERE"
echo "========================================"

GRUYERE_DIR="gruyere"
GRUYERE_PORT=8080

# Проверяем наличие Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Ошибка: Python3 не установлен"
    exit 1
fi

# Клонируем или обновляем репозиторий
if [ ! -d "$GRUYERE_DIR" ]; then
    echo "1. Клонирование репозитория Google Gruyere..."
    git clone https://github.com/google/gruyere.git "$GRUYERE_DIR"
else
    echo "1. Обновление репозитория Google Gruyere..."
    cd "$GRUYERE_DIR"
    git pull origin master
    cd ..
fi

# Проверяем наличие файла gruyere.py
if [ ! -f "$GRUYERE_DIR/gruyere.py" ]; then
    echo "❌ Ошибка: Файл gruyere.py не найден"
    exit 1
fi

# Проверяем, свободен ли порт
echo "2. Проверка порта $GRUYERE_PORT..."
if lsof -Pi :$GRUYERE_PORT -sTCP:LISTEN -t >/dev/null; then
    echo "⚠️ Порт $GRUYERE_PORT уже занят"
    read -p "Использовать другой порт? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Введите номер порта: " GRUYERE_PORT
    else
        echo "Остановка..."
        exit 1
    fi
fi

# Запускаем Gruyere
echo "3. Запуск Google Gruyere на порту $GRUYERE_PORT..."
echo "   Для остановки нажмите Ctrl+C"
echo "   URL: http://localhost:$GRUYERE_PORT"
echo "   Дата запуска: $(date '+%d.%m.%Y %H:%M:%S')"
echo ""

cd "$GRUYERE_DIR"

# Создаем папку для логов
mkdir -p logs

# Запускаем Gruyere с логированием
echo "=== ЛОГ ЗАПУСКА GRUYERE ===" > logs/gruyere.log
echo "Дата: $(date '+%d.%m.%Y %H:%M:%S')" >> logs/gruyere.log
echo "Порт: $GRUYERE_PORT" >> logs/gruyere.log
echo "==========================" >> logs/gruyere.log

python3 gruyere.py --port=$GRUYERE_PORT 2>&1 | tee -a logs/gruyere.log

echo ""
echo "========================================"
echo "Google Gruyere остановлен"
echo "Дата остановки: $(date '+%d.%m.%Y %H:%M:%S')"
echo "========================================"
