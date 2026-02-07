#!/usr/bin/env python3
"""
Визуализация и сравнение сетевого трафика.
Генерация отчетов для Этапа 4 задания.
"""
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import rdpcap, IP, TCP, HTTPRequest, HTTPResponse
from datetime import datetime
import json

def load_pcap_stats(filename):
    """Загружает статистику из pcap файла"""
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"❌ Файл {filename} не найден")
        return None
    
    stats = {
        'filename': filename,
        'total_packets': len(packets),
        'http_requests': 0,
        'http_responses': 0,
        'packet_sizes': [],
        'timestamps': [],
        'source_ips': {},
        'destination_ips': {},
        'ports': {}
    }
    
    for packet in packets:
        # Размер пакета
        stats['packet_sizes'].append(len(packet))
        
        # Время (если есть временные метки)
        if hasattr(packet, 'time'):
            stats['timestamps'].append(float(packet.time))
        
        # IP адреса
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            stats['source_ips'][src] = stats['source_ips'].get(src, 0) + 1
            stats['destination_ips'][dst] = stats['destination_ips'].get(dst, 0) + 1
        
        # Порты
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            stats['ports'][sport] = stats['ports'].get(sport, 0) + 1
            stats['ports'][dport] = stats['ports'].get(dport, 0) + 1
        
        # HTTP статистика
        if packet.haslayer(HTTPRequest):
            stats['http_requests'] += 1
        elif packet.haslayer(HTTPResponse):
            stats['http_responses'] += 1
    
    return stats

def compare_traffic_stats(normal_stats, xss_stats):
    """Сравнивает статистику двух файлов pcap"""
    
    comparison = {
        'packet_count_diff': xss_stats['total_packets'] - normal_stats['total_packets'],
        'packet_count_ratio': xss_stats['total_packets'] / normal_stats['total_packets'] if normal_stats['total_packets'] > 0 else 0,
        'avg_size_diff': np.mean(xss_stats['packet_sizes']) - np.mean(normal_stats['packet_sizes']),
        'http_requests_diff': xss_stats['http_requests'] - normal_stats['http_requests'],
        'http_responses_diff': xss_stats['http_responses'] - normal_stats['http_responses']
    }
    
    return comparison

def create_comparison_report(normal_file, xss_file):
    """Создает полный отчет сравнения трафика"""
    
    print("=" * 70)
    print("ВИЗУАЛЬНЫЙ АНАЛИЗ И СРАВНЕНИЕ ТРАФИКА")
    print("=" * 70)
    
    normal_stats = load_pcap_stats(normal_file)
    xss_stats = load_pcap_stats(xss_file)
    
    if not normal_stats or not xss_stats:
        return
    
    comparison = compare_traffic_stats(normal_stats, xss_stats)
    
    # Создаем графики
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    fig.suptitle('Сравнение сетевого трафика: нормальный vs XSS атака', fontsize=14)
    
    # 1. Количество пакетов
    axes[0, 0].bar(['Нормальный', 'XSS атака'], 
                   [normal_stats['total_packets'], xss_stats['total_packets']],
                   color=['green', 'red'])
    axes[0, 0].set_title('Общее количество пакетов')
    axes[0, 0].set_ylabel('Количество')
    
    # 2. Средний размер пакета
    normal_avg = np.mean(normal_stats['packet_sizes'])
    xss_avg = np.mean(xss_stats['packet_sizes'])
    axes[0, 1].bar(['Нормальный', 'XSS атака'], 
                   [normal_avg, xss_avg],
                   color=['green', 'red'])
    axes[0, 1].set_title('Средний размер пакета')
    axes[0, 1].set_ylabel('Байты')
    
    # 3. HTTP запросы и ответы
    x = np.arange(2)
    width = 0.35
    axes[0, 2].bar(x - width/2, 
                   [normal_stats['http_requests'], normal_stats['http_responses']],
                   width, label='Нормальный', color='green')
    axes[0, 2].bar(x + width/2, 
                   [xss_stats['http_requests'], xss_stats['http_responses']],
                   width, label='XSS атака', color='red')
    axes[0, 2].set_title('HTTP трафик')
    axes[0, 2].set_ylabel('Количество')
    axes[0, 2].set_xticks(x)
    axes[0, 2].set_xticklabels(['Запросы', 'Ответы'])
    axes[0, 2].legend()
    
    # 4. Распределение размеров пакетов (гистограмма)
    axes[1, 0].hist([normal_stats['packet_sizes'], xss_stats['packet_sizes']],
                    bins=20, label=['Нормальный', 'XSS атака'],
                    color=['green', 'red'], alpha=0.7)
    axes[1, 0].set_title('Распределение размеров пакетов')
    axes[1, 0].set_xlabel('Размер (байты)')
    axes[1, 0].set_ylabel('Частота')
    axes[1, 0].legend()
    
    # 5. Топ 5 IP адресов источников
    normal_top_src = sorted(normal_stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
    xss_top_src = sorted(xss_stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
    
    src_labels = [ip for ip, _ in normal_top_src]
    normal_counts = [count for _, count in normal_top_src]
    xss_counts = [xss_stats['source_ips'].get(ip, 0) for ip, _ in normal_top_src]
    
    x = np.arange(len(src_labels))
    axes[1, 1].bar(x - width/2, normal_counts, width, label='Нормальный', color='green')
    axes[1, 1].bar(x + width/2, xss_counts, width, label='XSS атака', color='red')
    axes[1, 1].set_title('Топ 5 IP источников')
    axes[1, 1].set_ylabel('Количество пакетов')
    axes[1, 1].set_xticks(x)
    axes[1, 1].set_xticklabels(src_labels, rotation=45, ha='right')
    axes[1, 1].legend()
    
    # 6. Разница в статистике
    metrics = ['Пакеты', 'Ср. размер', 'HTTP запр.', 'HTTP отв.']
    differences = [
        comparison['packet_count_diff'],
        comparison['avg_size_diff'],
        comparison['http_requests_diff'],
        comparison['http_responses_diff']
    ]
    
    colors = ['red' if diff > 0 else 'green' for diff in differences]
    axes[1, 2].bar(metrics, differences, color=colors)
    axes[1, 2].set_title('Разница (XSS - нормальный)')
    axes[1, 2].set_ylabel('Разница')
    axes[1, 2].axhline(y=0, color='black', linestyle='-', linewidth=0.5)
    
    plt.tight_layout()
    plt.savefig('traffic_comparison_chart.png', dpi=300)
    plt.show()
    
    # Создаем текстовый отчет
    report = {
        'analysis_date': datetime.now().isoformat(),
        'files': {
            'normal': normal_file,
            'xss': xss_file
        },
        'statistics': {
            'normal': {
                'total_packets': normal_stats['total_packets'],
                'avg_packet_size': float(normal_avg),
                'http_requests': normal_stats['http_requests'],
                'http_responses': normal_stats['http_responses'],
                'unique_source_ips': len(normal_stats['source_ips']),
                'unique_destination_ips': len(normal_stats['destination_ips'])
            },
            'xss': {
                'total_packets': xss_stats['total_packets'],
                'avg_packet_size': float(xss_avg),
                'http_requests': xss_stats['http_requests'],
                'http_responses': xss_stats['http_responses'],
                'unique_source_ips': len(xss_stats['source_ips']),
                'unique_destination_ips': len(xss_stats['destination_ips'])
            }
        },
        'comparison': comparison,
        'findings': []
    }
    
    # Анализируем различия
    if comparison['packet_count_ratio'] > 1.5:
        report['findings'].append({
            'type': 'significant_increase',
            'metric': 'packet_count',
            'ratio': comparison['packet_count_ratio'],
            'description': f'При XSS атаке количество пакетов увеличилось в {comparison["packet_count_ratio"]:.1f} раза'
        })
    
    if comparison['avg_size_diff'] > 100:
        report['findings'].append({
            'type': 'size_increase',
            'metric': 'packet_size',
            'difference': comparison['avg_size_diff'],
            'description': f'При XSS атаке средний размер пакета увеличился на {comparison["avg_size_diff"]:.0f} байт'
        })
    
    if comparison['http_requests_diff'] > 10:
        report['findings'].append({
            'type': 'http_activity',
            'metric': 'http_requests',
            'difference': comparison['http_requests_diff'],
            'description': f'При XSS атаке количество HTTP запросов увеличилось на {comparison["http_requests_diff"]}'
        })
    
    # Сохраняем отчет
    with open('traffic_comparison_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    with open('traffic_comparison_summary.txt', 'w') as f:
        f.write("ОТЧЕТ О СРАВНЕНИИ ТРАФИКА\n")
        f.write("="*60 + "\n\n")
        f.write(f"Нормальный трафик: {normal_file}\n")
        f.write(f"Трафик с XSS атакой: {xss_file}\n\n")
        
        f.write("СТАТИСТИКА:\n")
        f.write(f"  Нормальный трафик:\n")
        f.write(f"    Всего пакетов: {normal_stats['total_packets']}\n")
        f.write(f"    Средний размер: {normal_avg:.0f} байт\n")
        f.write(f"    HTTP запросов: {normal_stats['http_requests']}\n")
        f.write(f"    HTTP ответов: {normal_stats['http_responses']}\n\n")
        
        f.write(f"  XSS трафик:\n")
        f.write(f"    Всего пакетов: {xss_stats['total_packets']}\n")
        f.write(f"    Средний размер: {xss_avg:.0f} байт\n")
        f.write(f"    HTTP запросов: {xss_stats['http_requests']}\n")
        f.write(f"    HTTP ответов: {xss_stats['http_responses']}\n\n")
        
        f.write("РАЗЛИЧИЯ (XSS - нормальный):\n")
        f.write(f"  Разница в пакетах: {comparison['packet_count_diff']}\n")
        f.write(f"  Отношение: {comparison['packet_count_ratio']:.1f}x\n")
        f.write(f"  Разница в среднем размере: {comparison['avg_size_diff']:.0f} байт\n")
        f.write(f"  Разница в HTTP запросах: {comparison['http_requests_diff']}\n")
        f.write(f"  Разница в HTTP ответах: {comparison['http_responses_diff']}\n\n")
        
        if report['findings']:
            f.write("ВАЖНЫЕ НАХОДКИ:\n")
            for finding in report['findings']:
                f.write(f"  • {finding['description']}\n")
        
        f.write("\nВЫВОДЫ:\n")
        if report['findings']:
            f.write("  Обнаружены значительные различия в трафике при XSS атаке.\n")
            f.write("  Это подтверждает успешную эксплуатацию уязвимости.\n")
        else:
            f.write("  Значительных различий не обнаружено.\n")
            f.write("  XSS payload могли быть в теле запросов/ответов.\n")
    
    print(f"\n✅ Визуализация сохранена в traffic_comparison_chart.png")
    print(f"✅ Отчет сохранен в traffic_comparison_report.json")
    print(f"✅ Сводка сохранена в traffic_comparison_summary.txt")

def main():
    print("ВИЗУАЛИЗАТОР ТРАФИКА ДЛЯ СРАВНЕНИЯ")
    print("Этап 4: Визуальный анализ различий в трафике\n")
    
    normal_file = input("Введите имя pcap файла с нормальным трафиком (gruyere_traffic.pcap): ").strip()
    if not normal_file:
        normal_file = "gruyere_traffic.pcap"
    
    xss_file = input("Введите имя pcap файла с XSS трафиком (xss_attack.pcap): ").strip()
    if not xss_file:
        xss_file = "xss_attack.pcap"
    
    create_comparison_report(normal_file, xss_file)

if __name__ == "__main__":
    # Проверяем наличие matplotlib
    try:
        import matplotlib
        main()
    except ImportError:
        print("❌ Для работы визуализатора требуется matplotlib")
        print("Установите: pip install matplotlib")
