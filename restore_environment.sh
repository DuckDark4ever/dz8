#!/bin/bash
# restore_environment.sh - Восстановление настроек окружения

echo "Восстановление правил iptables..."

# Удаляем правило для RST-пакетов
if sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null; then
    sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
    echo "✅ Правило удалено"
else
    echo "✅ Правило не найдено (уже удалено)"
fi

echo -e "\nТекущие правила iptables OUTPUT chain:"
sudo iptables -L OUTPUT -n --line-numbers | head -20

echo -e "\n✅ Восстановление завершено!"
