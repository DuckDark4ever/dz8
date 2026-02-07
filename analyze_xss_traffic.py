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
                    with open(f"upload_xss_detailed_{i+1}.txt", "w") as f:
                        f.write(f"ОБНАРУЖЕН XSS В ОТВЕТЕ НА UPLOAD\n")
                        f.write("="*60 + "\n\n")
                        f.write(f"Индикатор: {indicator}\n")
                        f.write(f"Контекст (100 символов вокруг):\n")
                        f.write(content[max(0, idx-100):min(len(content), idx+200)])
                        f.write("\n\nПолный ответ (первые 2000 символов):\n")
                        f.write(content[:2000])
                    
                    print(f"     Детали сохранены в upload_xss_detailed_{i+1}.txt")
                    break
    
    # Создаем итоговый отчет по уязвимости Upload
    with open("upload_vulnerability_report.txt", "w") as f:
        f.write("ОТЧЕТ ПО УЯЗВИМОСТИ XSS НА СТРАНИЦЕ UPLOAD\n")
        f.write("="*60 + "\n\n")
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

# Обновить функцию main() в analyze_xss_traffic.py:
def main():
    print("АНАЛИЗАТОР XSS ТРАФИКА ДЛЯ GOOGLE GRUYERE")
    print("Этап 4: Анализ результатов XSS атаки\n")
    
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
    print("Проверьте созданные файлы:")
    print("  - xss_traffic_analysis.txt - детальный анализ XSS")
    print("  - upload_vulnerability_report.txt - анализ уязвимости Upload")
    print("  - traffic_comparison.txt - сравнение трафика")
    print("  - upload_xss_detailed_*.txt - детали найденных XSS")
