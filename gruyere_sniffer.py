#!/usr/bin/env python3
"""
Скрипт для перехвата и анализа трафика Google Gruyere.
Поддержка HTTP (порт 80/8080) и HTTPS (порт 443) с раздельным анализом.
"""
from scapy.all import sniff, wrpcap, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import gzip
import io
import argparse
from datetime import datetime
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gruyere_sniffer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """Класс для анализа сетевого трафика"""
    
    def __init__(self):
        self.captured_packets: List = []
        self.http_requests: List[Dict] = []
        self.http_responses: List[Dict] = []
        self.https_packets: List = []  # HTTPS трафик (шифрованный)
        
    def extract_http_headers(self, raw_data: bytes) -> Dict[str, str]:
        """Извлекает HTTP заголовки из сырых данных"""
        headers = {}
        try:
            # Разделяем заголовки и тело
            parts = raw_data.split(b'\r\n\r\n', 1)
            if len(parts) > 0:
                header_lines = parts[0].decode('utf-8', errors='ignore').split('\r\n')
                for line in header_lines[1:]:  # Пропускаем первую строку
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.strip()] = value.strip()
        except Exception as e:
            logger.debug(f"Ошибка извлечения заголовков: {e}")
        return headers
    
    def is_gzip_encoded(self, headers: Dict[str, str]) -> bool:
        """Проверяет, сжато ли содержимое gzip"""
        content_encoding = headers.get('Content-Encoding', '').lower()
        return 'gzip' in content_encoding
    
    def decode_gzip_content(self, content: bytes) -> str:
        """Декодирует gzip сжатое содержимое"""
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:
                return f.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Ошибка декодирования gzip: {e}")
            return content.decode('utf-8', errors='ignore')
    
    def analyze_http_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Анализирует HTTP пакет и извлекает полезную информацию"""
        try:
            result = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet[IP].src if IP in packet else 'Unknown',
                'dst_ip': packet[IP].dst if IP in packet else 'Unknown',
                'src_port': packet[TCP].sport if TCP in packet else 0,
                'dst_port': packet[TCP].dport if TCP in packet else 0,
            }
            
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                result['type'] = 'REQUEST'
                result['method'] = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else 'UNKNOWN'
                result['path'] = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
                result['host'] = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''
                
                # Извлекаем тело запроса
                if Raw in packet:
                    raw_data = packet[Raw].load
                    headers = self.extract_http_headers(raw_data)
                    result['headers'] = headers
                    
                    # Пытаемся извлечь тело
                    parts = raw_data.split(b'\r\n\r\n', 1)
                    if len(parts) > 1 and parts[1]:
                        result['body'] = parts[1].decode('utf-8', errors='ignore')
                    else:
                        result['body'] = ''
                
                self.http_requests.append(result)
                
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]
                result['type'] = 'RESPONSE'
                result['status_code'] = http_layer.Status_Code.decode('utf-8', errors='ignore') if http_layer.Status_Code else '000'
                result['reason'] = http_layer.Reason_Phrase.decode('utf-8', errors='ignore') if http_layer.Reason_Phrase else ''
                
                # Обрабатываем тело ответа
                if Raw in packet:
                    raw_data = packet[Raw].load
                    headers = self.extract_http_headers(raw_data)
                    result['headers'] = headers
                    
                    # Извлекаем тело
                    parts = raw_data.split(b'\r\n\r\n', 1)
                    if len(parts) > 1 and parts[1]:
                        body_content = parts[1]
                        
                        # Проверяем сжатие
                        if self.is_gzip_encoded(headers):
                            result['body'] = self.decode_gzip_content(body_content)
                            result['compression'] = 'gzip'
                        else:
                            result['body'] = body_content.decode('utf-8', errors='ignore')
                            result['compression'] = 'none'
                    else:
                        result['body'] = ''
                        result['compression'] = 'none'
                
                self.http_responses.append(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка анализа HTTP пакета: {e}")
            return None
    
    def packet_callback(self, packet):
        """Callback функция для обработки каждого пакета"""
        try:
            self.captured_packets.append(packet)
            
            # Проверяем порт для определения типа трафика
            if TCP in packet:
                dst_port = packet[TCP].dport
                src_port = packet[TCP].sport
                
                # HTTPS трафик (порт 443)
                if dst_port == 443 or src_port == 443:
                    self.https_packets.append(packet)
                    logger.debug(f"HTTPS пакет: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}")
                    return None
            
            # Анализируем HTTP трафик
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                analysis = self.analyze_http_packet(packet)
                
                if analysis:
                    # Логируем информацию
                    if analysis['type'] == 'REQUEST':
                        logger.info(f"HTTP Request: {analysis['method']} {analysis['path']}")
                        print(f"\n[REQUEST] {analysis['method']} {analysis['path']}")
                        print(f"  Host: {analysis['host']}")
                        print(f"  From: {analysis['src_ip']}:{analysis['src_port']}")
                    else:
                        logger.info(f"HTTP Response: {analysis['status_code']} {analysis['reason']}")
                        print(f"\n[RESPONSE] {analysis['status_code']} {analysis['reason']}")
                        print(f"  To: {analysis['dst_ip']}:{analysis['dst_port']}")
                        
                        # Выводим информацию о сжатии
                        if analysis.get('compression') == 'gzip':
                            print(f"  Compression: gzip")
                        
                        # Выводим первые 200 символов тела для анализа
                        if 'body' in analysis and analysis['body']:
                            body_preview = analysis['body'][:200]
                            print(f"  Body preview: {body_preview}")
                    
                    return analysis
            
        except Exception as e:
            logger.error(f"Ошибка обработки пакета: {e}")
            return None
    
    def save_results(self, pcap_filename: str):
        """Сохраняет результаты анализа"""
        # Сохраняем весь трафик в pcap
        if self.captured_packets:
            logger.info(f"Сохранение {len(self.captured_packets)} пакетов в {pcap_filename}")
            wrpcap(pcap_filename, self.captured_packets)
            print(f"✅ Трафик сохранен в {pcap_filename}")
        
        # Сохраняем анализ в текстовый файл
        with open('traffic_analysis.txt', 'w', encoding='utf-8') as f:
            f.write("АНАЛИЗ ТРАФИКА GOOGLE GRUYERE\n")
            f.write("="*60 + "\n\n")
            f.write(f"Дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
            f.write(f"Всего пакетов: {len(self.captured_packets)}\n")
            f.write(f"HTTP запросов: {len(self.http_requests)}\n")
            f.write(f"HTTP ответов: {len(self.http_responses)}\n")
            f.write(f"HTTPS пакетов (шифрованных): {len(self.https_packets)}\n")
            
            if self.https_packets:
                f.write("\n⚠️ ВНИМАНИЕ: Обнаружен HTTPS трафик (порт 443)\n")
                f.write("   Содержимое HTTPS пакетов зашифровано и не доступно для анализа.\n")
                f.write("   Для анализа используйте локальный Google Gruyere на порту 8080.\n")
            
            f.write("\n" + "="*50 + "\n")
            
            for req in self.http_requests:
                f.write(f"\n[REQUEST] {req['method']} {req['path']}\n")
                f.write(f"Host: {req['host']}\n")
                f.write(f"From: {req['src_ip']}:{req['src_port']}\n")
                if 'body' in req and req['body']:
                    f.write(f"Body: {req['body'][:500]}\n")
            
            for resp in self.http_responses:
                f.write(f"\n[RESPONSE] {resp['status_code']} {resp['reason']}\n")
                f.write(f"To: {resp['dst_ip']}:{resp['dst_port']}\n")
                if resp.get('compression') == 'gzip':
                    f.write(f"Compression: gzip\n")
                if 'body' in resp and resp['body']:
                    # Ищем потенциальные XSS уязвимости
                    body_lower = resp['body'].lower()
                    if '<script>' in body_lower or 'onerror=' in body_lower:
                        f.write("⚠️ ВОЗМОЖНАЯ XSS УЯЗВИМОСТЬ В ТЕЛЕ ОТВЕТА!\n")
                    f.write(f"Body preview: {resp['body'][:500]}\n")
        
        print(f"✅ Анализ сохранен в traffic_analysis.txt")
        
        # Сохраняем статистику
        print(f"\n📊 СТАТИСТИКА:")
        print(f"  Всего пакетов: {len(self.captured_packets)}")
        print(f"  HTTP запросов: {len(self.http_requests)}")
        print(f"  HTTP ответов: {len(self.http_responses)}")
        print(f"  HTTPS пакетов: {len(self.https_packets)}")
        
        if self.https_packets:
            print(f"\n⚠️ ОБНАРУЖЕН HTTPS ТРАФИК!")
            print("   Содержимое зашифровано. Для анализа XSS используйте:")
            print("   1. Локальный Google Gruyere (python3 gruyere.py)")
            print("   2. MITM-прокси для расшифровки HTTPS")

def validate_url(url: str) -> bool:
    """Проверяет валидность URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description='Анализатор трафика Google Gruyere')
    parser.add_argument('--interface', default=None, help='Сетевой интерфейс для прослушивания')
    parser.add_argument('--output', default='gruyere_traffic.pcap', help='Имя выходного .pcap файла')
    parser.add_argument('--count', type=int, default=0, help='Количество пакетов для захвата (0 = бесконечно)')
    parser.add_argument('--timeout', type=int, default=300, help='Таймаут захвата в секундах')
    parser.add_argument('--port', type=int, default=8080, help='Порт для захвата HTTP трафика')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("АНАЛИЗАТОР ТРАФИКА GOOGLE GRUYERE")
    print("=" * 70)
    print(f"Дата запуска: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print("\nВАЖНО: Рекомендуется локальный запуск Google Gruyere:")
    print("  $ git clone https://github.com/google/gruyere")
    print("  $ cd gruyere && python3 gruyere.py")
    print("\nОблачная версия (HTTPS) сложнее для анализа!")
    print("=" * 70 + "\n")
    
    analyzer = TrafficAnalyzer()
    
    try:
        # Универсальный фильтр для захвата HTTP/HTTPS трафика
        # Используем указанный порт или стандартные порты HTTP/HTTPS
        if args.port == 8080:
            filter_str = f"tcp port {args.port} or tcp port 80 or tcp port 443"
        else:
            filter_str = f"tcp port {args.port}"
        
        logger.info(f"Запуск сниффера с фильтром: {filter_str}")
        print(f"Захват трафика на портах: {filter_str}")
        print("Нажмите Ctrl+C для остановки захвата...\n")
        
        sniff(
            prn=analyzer.packet_callback,
            filter=filter_str,
            store=False,
            count=args.count,
            timeout=args.timeout,
            iface=args.interface
        )
        
    except KeyboardInterrupt:
        print("\n\nЗахват трафика остановлен пользователем")
        logger.info("Захват трафика остановлен по команде пользователя")
    
    except PermissionError:
        print("\n❌ ОШИБКА: Требуются права администратора!")
        print("Запустите скрипт с sudo: sudo python3 gruyere_sniffer.py")
        logger.error("PermissionError: Требуются права администратора")
        return
    
    except Exception as e:
        print(f"\n❌ ОШИБКА: {e}")
        logger.error(f"Ошибка при захвате трафика: {e}")
    
    finally:
        analyzer.save_results(args.output)

if __name__ == "__main__":
    main()
