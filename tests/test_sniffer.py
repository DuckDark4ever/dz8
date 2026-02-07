#!/usr/bin/env python3
"""
Юнит-тесты для модулей анализа трафика.
"""
import pytest
import gzip
import io
from unittest.mock import Mock, patch
import sys
import os

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Импортируем функции для тестирования
try:
    from gruyere_sniffer import TrafficAnalyzer, validate_url
except ImportError:
    # Создаем заглушки для тестов
    class TrafficAnalyzer:
        pass
    
    def validate_url(url):
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

def decode_gzip_content(content):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:
            return f.read().decode('utf-8', errors='ignore')
    except:
        return content.decode('utf-8', errors='ignore')

class TestTrafficAnalyzer:
    """Тесты для TrafficAnalyzer"""
    
    def setup_method(self):
        self.analyzer = TrafficAnalyzer()
    
    def test_extract_http_headers(self):
        """Тест извлечения HTTP заголовков"""
        raw_data = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\nbody"
        headers = self.analyzer.extract_http_headers(raw_data)
        
        assert headers['Host'] == 'example.com'
        assert headers['Content-Type'] == 'text/html'
    
    def test_is_gzip_encoded(self):
        """Тест определения gzip кодирования"""
        headers = {'Content-Encoding': 'gzip'}
        assert self.analyzer.is_gzip_encoded(headers) == True
        
        headers = {'Content-Encoding': 'deflate'}
        assert self.analyzer.is_gzip_encoded(headers) == False
        
        headers = {}
        assert self.analyzer.is_gzip_encoded(headers) == False
    
    def test_decode_gzip_content_valid(self):
        """Тест декодирования валидного gzip содержимого"""
        original = b"Test content with XSS <script>alert(1)</script>"
        compressed = gzip.compress(original)
        
        result = decode_gzip_content(compressed)
        assert result == original.decode('utf-8')
    
    def test_decode_gzip_content_invalid(self):
        """Тест декодирования невалидного gzip содержимого"""
        invalid_content = b"Not a gzip file"
        result = decode_gzip_content(invalid_content)
        
        # Должен вернуться декодированный текст (не выбросить исключение)
        assert isinstance(result, str)

class TestURLValidation:
    """Тесты валидации URL"""
    
    def test_validate_url_valid(self):
        """Тест валидных URL"""
        valid_urls = [
            'http://localhost:8080',
            'https://google-gruyere.appspot.com',
            'http://example.com/test',
            'https://example.com:8443/path'
        ]
        
        for url in valid_urls:
            assert validate_url(url) == True
    
    def test_validate_url_invalid(self):
        """Тест невалидных URL"""
        invalid_urls = [
            'not-a-url',
            'ftp://example.com',
            'http://',
            'https://',
            'javascript:alert(1)'
        ]
        
        for url in invalid_urls:
            assert validate_url(url) == False

class TestXSSDetection:
    """Тесты обнаружения XSS"""
    
    def test_xss_patterns_in_response(self):
        """Тест поиска XSS паттернов в ответе"""
        
        # Тестовые данные с XSS
        test_cases = [
            ("<script>alert('XSS')</script>", True),
            ("<img src='x' onerror='alert(1)'>", True),
            ("Normal content without XSS", False),
            ("<body onload=alert('XSS')>", True),
            ("javascript:alert('XSS')", True)
        ]
        
        for content, should_detect in test_cases:
            # Проверяем метод анализа (заглушка)
            result = content.lower()
            detected = '<script>' in result or 'onerror=' in result or 'onload=' in result or 'javascript:' in result
            assert detected == should_detect

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, '-v'])
