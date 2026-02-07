#!/usr/bin/env python3
"""
Анализ захваченного трафика с XSS атаками.
Этап 4 задания: анализ результатов
"""
from scapy.all import rdpcap, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import gzip
import io
import re
from datetime import datetime

def extract_http_content(packet):
    """Извлекает HTTP содержимое из пакета"""
    if Raw in packet:
        raw_data = packet[Raw].load
        
        # Пытаемся декодировать как текст
        try:
            # Проверяем на gzip
            if b'Content-Encoding' in raw_data and b'gzip' in raw_data:
                try:
                    body_start = raw_data.find(b'\r\n\r\n') + 4
                    if body_start > 3:
                        gzip_body = raw_data[body_start:]
                        with gzip.GzipFile(fileobj=io.BytesIO(gzip_body)) as f:
                            return f.read().decode('utf-8', errors='ignore')
                except:
                    pass
            
            # Если не gzip или ошибка распаковки
            return raw_data.decode('utf-8', errors='ignore')
        except:
            return str(raw_data)
    
    return ""

def analyze_xss_pcap(pcap_file="xss_attack.pcap"):
    """Анализирует pcap файл на наличие XSS payload"""
    
    print("=" * 70)
    print(f"АНАЛИЗ XSS ТРАФИКА ИЗ ФАЙЛА: {pcap_file}")
    print("=" * 70)
    print(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"❌ Файл {pcap_file} не найден!")
        print("Сначала запустите xss_exploit.py для захвата трафика")
        return
    
    print(f"Загружено {len(packets)} пакетов\n")
    
    # Паттерны для поиска XSS
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'onerror\s*=\s*["\'].*?["\']',
        r'onload\s*=\s*["\'].*?["\']',
        r'onclick\s*=\s*["\'].*?["\']',
        r'javascript:',
        r'alert\s*\(\s*[\'"]',
        r'<iframe[^>]*>',
        r'<svg[^>]*>',
        r'<img[^>]*>',
        r'<body[^>]*>',
    ]
    
    # Статистика
    total_packets = len(packets)
    http_requests = 0
    http_responses = 0
    xss_found = 0
    xss_details = []
    
    for i, packet in enumerate(packets):
        # Проверяем, является ли пакет HTTP
        is_http_request = packet.haslayer(HTTPRequest)
        is_http_response = packet.haslayer(HTTPResponse)
        
        if is_http_request:
            http_requests += 1
            packet_type = "REQUEST"
        elif is_http_response:
            http_responses += 1
            packet_type = "RESPONSE"
        else:
            continue
        
        # Извлекаем содержимое
        content = extract_http_content(packet)
        
        # Ищем XSS паттерны
        found_xss = []
        for pattern in xss_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_xss.extend(matches)
        
        if found_xss:
            xss_found += 1
            
            # Извлекаем информацию о пакете
            src_ip = packet[IP].src if IP in packet else "Unknown"
            dst_ip = packet[IP].dst if IP in packet else "Unknown"
            
            # Получаем URL для запросов
            url = ""
            if is_http_request:
                http_layer = packet[HTTPRequest]
                if http_layer.Path:
                    url = http_layer.Path.decode('utf-8', errors='ignore')
            
            # Сохраняем детали
            xss_details.append({
                'packet_num': i,
                'type': packet_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'url': url,
                'xss_patterns': found_xss,
                'content_preview': content[:500]
            })
            
            # Выводим информацию
            print(f"\n{'='*60}")
            print(f"НАЙДЕН XSS PAYLOAD в пакете #{i}")
            print(f"{'='*60}")
            print(f"Тип: {packet_type}")
            print(f"От: {src_ip} -> Кому: {dst_ip}")
            if url:
                print(f"URL: {url}")
            
            print("\nОбнаруженные XSS паттерны:")
            for pattern in found_xss[:3]:  # Показываем первые 3
                print(f"  - {pattern[:100]}")
            
            print(f"\nПредпросмотр содержимого ({len(content)} символов):")
            print(content[:300])
    
    # Генерация отчета
    print(f"\n{'='*70}")
    print("ИТОГОВЫЙ ОТЧЕТ ПО АНАЛИЗУ XSS ТРАФИКА")
    print(f"{'='*70}")
    print(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print(f"Анализируемый файл: {pcap_file}")
    print(f"Всего пакетов в файле: {total_packets}")
    print(f"HTTP запросов: {http_requests}")
    print(f"HTTP ответов: {http_responses}")
    print(f"Пакетов с XSS payload: {xss_found}")
    
    if xss_found > 0:
        print(f"\n✅ XSS УЯЗВИМОСТИ ОБНАРУЖЕНЫ!")
        print("\nДетали найденных XSS payload:")
        
        # Группируем по типу атаки
        attack_types = {}
        for detail in xss_details:
            for pattern in detail['xss_patterns']:
                # Определяем тип атаки по паттерну
                if '<script>' in pattern.lower():
                    attack_type = 'Script Tag Injection'
                elif 'onerror' in pattern.lower():
                    attack_type = 'Event Handler (onerror)'
                elif 'onload' in pattern.lower():
                    attack_type = 'Event Handler (onload)'
                elif 'javascript:' in pattern.lower():
                    attack_type = 'JavaScript URI'
                elif 'alert(' in pattern.lower():
                    attack_type = 'Alert Popup'
                else:
                    attack_type = 'Other XSS'
                
                if attack_type not in attack_types:
                    attack_types[attack_type] = 0
                attack_types[attack_type] += 1
        
        print("\nТипы обнаруженных XSS атак:")
        for attack_type, count in attack_types.items():
            print(f"  {attack_type}: {count}")
        
        # Анализ векторов атаки
        print("\nАнализ векторов доставки XSS:")
        
        # По методам
        get_requests = sum(1 for d in xss_details if d['type'] == 'REQUEST')
        post_responses = sum(1 for d in xss_details if d['type'] == 'RESPONSE' and 'POST' in d['content_preview'])
        
        print(f"  GET запросы с XSS: {get_requests}")
        print(f"  POST ответы с XSS: {post_responses}")
        
        # Поиск рефлексированного XSS
        reflected_xss = 0
        for detail in xss_details:
            if detail['type'] == 'RESPONSE':
                # Проверяем, есть ли в ответе то, что выглядит как пользовательский ввод
                for pattern in detail['xss_patterns']:
                    if len(pattern) < 100:  # Не слишком длинные паттерны
                        reflected_xss += 1
                        break
        
        print(f"  Рефлексированный XSS: {reflected_xss}")
        
        # Анализ эффективности защиты
        print("\nАнализ эффективности защиты:")
        if reflected_xss > 0:
            print("  ❌ Сайт уязвим к рефлексированному XSS")
            print("  Рекомендация: Валидация и экранирование пользовательского ввода")
        else:
            print("  ✅ Рефлексированный XSS не обнаружен")
        
        # Сохраняем подробный отчет
        with open("xss_traffic_analysis.txt", "w", encoding='utf-8') as f:
            f.write("ПОДРОБНЫЙ АНАЛИЗ XSS ТРАФИКА\n")
            f.write("="*60 + "\n\n")
            f.write(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
            f.write(f"Анализируемый файл: {pcap_file}\n")
            f.write(f"Всего пакетов: {total_packets}\n")
            f.write(f"HTTP запросов: {http_requests}\n")
            f.write(f"HTTP ответов: {http_responses}\n")
            f.write(f"Пакетов с XSS: {xss_found}\n\n")
            
            f.write("ДЕТАЛИ ОБНАРУЖЕННЫХ XSS:\n")
            f.write("="*60 + "\n")
            
            for detail in xss_details:
                f.write(f"\nПакет #{detail['packet_num']} - {detail['type']}\n")
                f.write(f"От: {detail['src_ip']} -> Кому: {detail['dst_ip']}\n")
                if detail['url']:
                    f.write(f"URL: {detail['url']}\n")
                
                f.write("XSS паттерны:\n")
                for pattern in detail['xss_patterns'][:5]:  # Первые 5 паттернов
                    f.write(f"  - {pattern[:200]}\n")
                
                f.write(f"\nПредпросмотр содержимого:\n")
                f.write(detail['content_preview'])
                f.write("\n" + "-"*50 + "\n")
            
            f.write("\nАНАЛИЗ И РЕКОМЕНДАЦИИ:\n")
            f.write("="*60 + "\n\n")
            
            if reflected_xss > 0:
                f.write("❌ КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Рефлексированный XSS\n")
                f.write("   Пользовательский ввод отображается без экранирования.\n")
                f.write("   Рекомендации:\n")
                f.write("   1. Экранировать HTML специальные символы (<, >, &, \", ')\n")
                f.write("   2. Использовать Content Security Policy (CSP)\n")
                f.write("   3. Валидировать все пользовательские данные\n")
                f.write("   4. Использовать безопасные API (textContent вместо innerHTML)\n")
            else:
                f.write("✅ Рефлексированный XSS не обнаружен\n")
                f.write("   Это может указывать на наличие базовой защиты.\n")
            
            f.write("\nТИПЫ ОБНАРУЖЕННЫХ XSS АТАК:\n")
            for attack_type, count in attack_types.items():
                f.write(f"  {attack_type}: {count} случаев\n")
        
        print(f"\n✅ Подробный отчет сохранен в xss_traffic_analysis.txt")
        
    else:
        print("\n❌ XSS payload не обнаружены в трафике")
        print("Возможные причины:")
        print("  1. Сайт защищен от XSS")
        print("  2. XSS payload не были доставлены")
        print("  3. Трафик захвачен некорректно")
    
    print(f"\n{'='*70}")
    print("АНАЛИЗ ЗАВЕРШЕН")

def compare_traffic(normal_pcap="gruyere_traffic.pcap", xss_pcap="xss_attack.pcap"):
    """Сравнивает нормальный трафик и трафик с XSS атакой"""
    
    print("\n" + "="*70)
    print("СРАВНЕНИЕ НОРМАЛЬНОГО ТРАФИКА И ТРАФИКА С XSS")
    print("="*70)
    
    try:
        normal_packets = rdpcap(normal_pcap)
        xss_packets = rdpcap(xss_pcap)
    except FileNotFoundError as e:
        print(f"❌ Ошибка: {e}")
        return
    
    # Анализ размеров пакетов
    normal_sizes = [len(p) for p in normal_packets if IP in p]
    xss_sizes = [len(p) for p in xss_packets if IP in p]
    
    print(f"\nСтатистика пакетов:")
    print(f"  Нормальный трафик: {len(normal_packets)} пакетов")
    print(f"  XSS трафик: {len(xss_packets)} пакетов")
    
    if normal_sizes and xss_sizes:
        print(f"\nСредний размер пакета:")
        print(f"  Нормальный: {sum(normal_sizes)/len(normal_sizes):.0f} байт")
        print(f"  XSS атака: {sum(xss_sizes)/len(xss_sizes):.0f} байт")
        
        # Ищем большие пакеты (возможно, с XSS payload)
        large_packets = [s for s in xss_sizes if s > max(normal_sizes + [0]) * 1.5]
        if large_packets:
            print(f"\n⚠️ Обнаружены аномально большие пакеты в XSS трафике")
            print(f"  Количество: {len(large_packets)}")
            print(f"  Максимальный размер: {max(large_packets)} байт")
            print("  Это могут быть пакеты с XSS payload")
    
    # Анализ HTTP методов
    def count_http_methods(packets):
        methods = {'GET': 0, 'POST': 0, 'OTHER': 0}
        for packet in packets:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                if http_layer.Method:
                    method = http_layer.Method.decode('utf-8', errors='ignore')
                    if method in methods:
                        methods[method] += 1
                    else:
                        methods['OTHER'] += 1
        return methods
    
    normal_methods = count_http_methods(normal_packets)
    xss_methods = count_http_methods(xss_packets)
    
    print(f"\nHTTP методы:")
    print("  Нормальный трафик:")
    for method, count in normal_methods.items():
        if count > 0:
            print(f"    {method}: {count}")
    
    print("  XSS трафик:")
    for method, count in xss_methods.items():
        if count > 0:
            print(f"    {method}: {count}")
    
    # Сохраняем сравнение
    with open("traffic_comparison.txt", "w", encoding='utf-8') as f:
        f.write("СРАВНЕНИЕ ТРАФИКА: НОРМАЛЬНЫЙ VS XSS АТАКА\n")
        f.write("="*60 + "\n\n")
        f.write(f"Дата сравнения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
        f.write(f"Нормальный трафик: {normal_pcap}\n")
        f.write(f"XSS трафик: {xss_pcap}\n\n")
        
        f.write("РАЗМЕРЫ ПАКЕТОВ:\n")
        f.write(f"Нормальный трафик: {len(normal_packets)} пакетов\n")
        f.write(f"XSS трафик: {len(xss_packets)} пакетов\n\n")
        
        if normal_sizes and xss_sizes:
            f.write(f"Средний размер пакета:\n")
            f.write(f"  Нормальный: {sum(normal_sizes)/len(normal_sizes):.0f} байт\n")
            f.write(f"  XSS атака: {sum(xss_sizes)/len(xss_sizes):.0f} байт\n\n")
        
        f.write("HTTP МЕТОДЫ:\n")
        f.write("Нормальный трафик:\n")
        for method, count in normal_methods.items():
            if count > 0:
                f.write(f"  {method}: {count}\n")
        
        f.write("\nXSS трафик:\n")
        for method, count in xss_methods.items():
            if count > 0:
                f.write(f"  {method}: {count}\n")
        
        f.write("\nВЫВОДЫ:\n")
        f.write("="*60 + "\n")
        
        differences = []
        if len(xss_packets) > len(normal_packets) * 1.5:
            differences.append("Увеличение количества пакетов при XSS атаке")
        
        if xss_methods.get('POST', 0) > normal_methods.get('POST', 0) * 2:
            differences.append("Увеличение POST запросов (возможна отправка форм с XSS)")
        
        if differences:
            f.write("ОБНАРУЖЕНЫ СЛЕДУЮЩИЕ ОТЛИЧИЯ:\n")
            for diff in differences:
                f.write(f"  • {diff}\n")
        else:
            f.write("Значительных отличий в статистике не обнаружено.\n")
            f.write("XSS payload могут быть скрыты в теле запросов/ответов.\n")
    
    print(f"\n✅ Сравнение сохранено в traffic_comparison.txt")

def analyze_gruyere_upload_vulnerability(pcap_file="xss_attack.pcap"):
    """Анализирует конкретную уязвимость Upload из ETAP_3_RESULTS.md"""
    
    print("\n" + "="*70)
    print("АНАЛИЗ КОНКРЕТНОЙ УЯЗВИМОСТИ: XSS НА СТРАНИЦЕ UPLOAD")
    print("="*70)
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"❌ Файл {pcap_file} не найден!")
        return
    
    upload_requests = []
    upload_responses = []
    
    for packet in packets:
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            if http_layer.Path and b'/upload' in http_layer.Path:
                upload_requests.append(packet)
        elif packet.haslayer(HTTPResponse):
            # Ищем ответы, связанные с upload
            if Raw in packet:
                content = extract_http_content(packet)
                if 'upload' in content.lower() or 'Upload' in content:
                    upload_responses.append(packet)
    
    print(f"\nНайдено запросов к /upload: {len(upload_requests)}")
    print(f"Найдено ответов, связанных с upload: {len(upload_responses)}")
    
    if upload_requests:
        print("\nАнализ запросов на загрузку:")
        for i, packet in enumerate(upload_requests[:3]):  # Первые 3 запроса
            http_layer = packet[HTTPRequest]
            print(f"\nЗапрос {i+1}:")
            print(f"  Метод: {http_layer.Method.decode() if http_layer.Method else 'Unknown'}")
            print(f"  Путь: {http_layer.Path.decode() if http_layer.Path else 'Unknown'}")
            
            # Ищем XSS payload в запросах
            if Raw in packet:
                content = extract_http_content(packet)
                if '<script>' in content.lower():
                    print(f"  ✅ ОБНАРУЖЕН XSS PAYLOAD В ЗАПРОСЕ!")
                    print(f"     Содержимое: {content[:200]}...")
    
    if upload_responses:
        print("\nАнализ ответов на загрузку:")
        for i, packet in enumerate(upload_responses[:3]):
            print(f"\nОтвет {i+1}:")
            
            # Ищем XSS payload в ответах
            content = extract_http_content(packet)
            
            # Проверяем, отражен ли пользовательский ввод
            xss_indicators = ['<script>', 'onerror=', 'onload=', 'javascript:']
            for indicator in xss_indicators:
                if indicator in content.lower():
                    print(f"  ✅ ОБНАРУЖЕН XSS В ОТВЕТЕ!")
                    print(f"     Индикатор: {indicator}")
                    
                    # Показываем контекст
                    idx = content.lower().find(indicator)
                    context = content[max(0, idx-50):min(len(content), idx+100)]
                    print(f"     Контекст: ...{context}...")
                    
                    # Сохраняем в отдельный файл
                    with open(f"upload_xss_detailed_{i+1}.txt", "w", encoding='utf-8') as f:
                        f.write(f"ОБНАРУЖЕН XSS В ОТВЕТЕ НА UPLOAD\n")
                        f.write("="*60 + "\n\n")
                        f.write(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                        f.write(f"Индикатор: {indicator}\n")
                        f.write(f"Контекст (100 символов вокруг):\n")
                        f.write(content[max(0, idx-100):min(len(content), idx+200)])
                        f.write("\n\nПолный ответ (первые 2000 символов):\n")
                        f.write(content[:2000])
                    
                    print(f"     Детали сохранены в upload_xss_detailed_{i+1}.txt")
                    break
    
    # Создаем итоговый отчет по уязвимости Upload
    with open("upload_vulnerability_report.txt", "w", encoding='utf-8') as f:
        f.write("ОТЧЕТ ПО УЯЗВИМОСТИ XSS НА СТРАНИЦЕ UPLOAD\n")
        f.write("="*60 + "\n\n")
        f.write(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
        f.write(f"Источник данных: {pcap_file}\n")
        f.write(f"Согласно ETAP_3_RESULTS.md: найдена критическая XSS уязвимость\n")
        f.write(f"на странице Upload.\n\n")
        
        f.write("АНАЛИЗ ТРАФИКА:\n")
        f.write(f"  Всего запросов к /upload: {len(upload_requests)}\n")
        f.write(f"  Ответов, связанных с upload: {len(upload_responses)}\n\n")
        
        if upload_requests or upload_responses:
            f.write("ОБНАРУЖЕНЫ СЛЕДУЮЩИЕ ПРОБЛЕМЫ:\n")
            
            # Анализируем запросы
            for i, packet in enumerate(upload_requests):
                content = extract_http_content(packet)
                xss_found = False
                
                for indicator in ['<script>', 'onerror=', 'onload=', 'javascript:']:
                    if indicator in content.lower():
                        f.write(f"  1. XSS payload в запросе #{i+1}: {indicator}\n")
                        xss_found = True
                
                if xss_found:
                    f.write(f"     Проблема: Пользовательский ввод не валидируется\n")
                    f.write(f"     Риск: Внедрение произвольного JavaScript кода\n\n")
            
            # Анализируем ответы
            for i, packet in enumerate(upload_responses):
                content = extract_http_content(packet)
                xss_found = False
                
                for indicator in ['<script>', 'onerror=', 'onload=', 'javascript:']:
                    if indicator in content.lower():
                        f.write(f"  2. XSS отражен в ответе #{i+1}: {indicator}\n")
                        xss_found = True
                
                if xss_found:
                    f.write(f"     Проблема: Пользовательский ввод отображается без экранирования\n")
                    f.write(f"     Риск: Выполнение вредоносного кода в браузере пользователя\n\n")
        
        f.write("РЕКОМЕНДАЦИИ ПО ЗАЩИТЕ:\n")
        f.write("  1. Валидация всех пользовательских данных на стороне сервера\n")
        f.write("  2. Экранирование HTML специальных символов (<, >, &, \", ')\n")
        f.write("  3. Использование Content Security Policy (CSP)\n")
        f.write("  4. Регулярное тестирование безопасности (penetration testing)\n")
        f.write("  5. Обучение разработчиков безопасному кодированию\n")
    
    print(f"\n✅ Отчет по уязвимости Upload сохранен в upload_vulnerability_report.txt")

def main():
    print("АНАЛИЗАТОР XSS ТРАФИКА ДЛЯ GOOGLE GRUYERE")
    print("Этап 4: Анализ результатов XSS атаки\n")
    print(f"Дата запуска: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    
    # Анализ основного XSS трафика
    pcap_file = input("Введите имя pcap файла с XSS трафиком (по умолчанию xss_attack.pcap): ").strip()
    if not pcap_file:
        pcap_file = "xss_attack.pcap"
    
    analyze_xss_pcap(pcap_file)
    
    # Анализ конкретной уязвимости Upload
    print("\nХотите проанализировать конкретную уязвимость Upload?")
    choice = input("(y/n, по умолчанию y): ").strip().lower()
    if choice != 'n':
        analyze_gruyere_upload_vulnerability(pcap_file)
    
    # Сравнение с нормальным трафиком (если есть)
    compare = input("\nСравнить с нормальным трафиком? (y/n): ").strip().lower()
    if compare == 'y':
        normal_file = input("Введите имя pcap файла с нормальным трафиком (по умолчанию gruyere_traffic.pcap): ").strip()
        if not normal_file:
            normal_file = "gruyere_traffic.pcap"
        
        compare_traffic(normal_file, pcap_file)
    
    print("\n" + "="*70)
    print("АНАЛИЗ ЗАВЕРШЕН")
    print(f"Дата завершения: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print("\nПроверьте созданные файлы:")
    print("  - xss_traffic_analysis.txt - детальный анализ XSS")
    print("  - upload_vulnerability_report.txt - анализ уязвимости Upload")
    print("  - traffic_comparison.txt - сравнение трафика")
    print("  - upload_xss_detailed_*.txt - детали найденных XSS")

if __name__ == "__main__":
    main()
