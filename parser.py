import re
import yaml
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache

@dataclass(frozen=True)
class ParserConfig:
    """Конфигурация парсера."""
    max_workers: int
    chunk_size: int
    max_path_depth: int
    log_pattern: str
    encoding: str
    ignore_paths: tuple

class NginxLogParser:
    """Многопоточный парсер логов nginx."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self._counter_lock = threading.Lock()
        self._path_counter = defaultdict(int)
    
    def _load_config(self, config_path: str) -> ParserConfig:
        """Загружает конфигурацию из YAML файла."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            log_parser_config = config_data['log_parser']
            log_format = log_parser_config['settings']['default_log_format']
            pattern = log_parser_config['log_formats'][log_format]
            
            return ParserConfig(
                max_workers=log_parser_config['settings']['max_workers'],
                chunk_size=log_parser_config['settings']['chunk_size'],
                max_path_depth=log_parser_config['settings']['max_path_depth'],
                log_pattern=pattern,
                encoding=log_parser_config['settings']['encoding'],
                ignore_paths=tuple(log_parser_config.get('ignore_paths', []))
            )
        except Exception as e:
            raise ValueError(f"Ошибка загрузки конфигурации: {e}")
    
    @lru_cache(maxsize=1000)
    def _process_path(self, path: str) -> Optional[str]:
        """
        Обрабатывает путь: декодирует URL и ограничивает глубину.
        Использует кэширование для оптимизации.
        """
        if not path or path == '/':
            return '/'
        
        # Проверяем игнорируемые пути
        if path in self.config.ignore_paths:
            return None
        
        try:
            # Декодируем URL-encoded символы
            decoded_path = urllib.parse.unquote(path)
            
            # Разделяем путь на компоненты и ограничиваем глубину
            parts = decoded_path.strip('/').split('/')
            limited_parts = parts[:self.config.max_path_depth]
            
            # Собираем путь обратно
            result_path = '/' + '/'.join(limited_parts)
            
            return result_path
            
        except Exception:
            # В случае ошибки возвращаем исходный путь, ограниченный по глубине
            parts = path.strip('/').split('/')[:self.config.max_path_depth]
            return '/' + '/'.join(parts)
    
    def _parse_chunk(self, chunk: List[str]) -> Dict[str, int]:
        """Парсит чанк строк лога."""
        local_counter = defaultdict(int)
        pattern = re.compile(self.config.log_pattern)
        
        for line in chunk:
            if not line.strip():
                continue
                
            match = pattern.search(line)
            if match:
                try:
                    path = match.group('path')
                    processed_path = self._process_path(path)
                    if processed_path:
                        local_counter[processed_path] += 1
                except (IndexError, KeyError):
                    # Пропускаем строки, не соответствующие формату
                    continue
        
        return local_counter
    
    def _read_file_chunks(self, file_path: str) -> List[List[str]]:
        """Читает файл и разбивает на чанки для многопоточной обработки."""
        try:
            with open(file_path, 'r', encoding=self.config.encoding) as file:
                lines = file.readlines()
            
            # Разбиваем на чанки
            chunks = [
                lines[i:i + self.config.chunk_size] 
                for i in range(0, len(lines), self.config.chunk_size)
            ]
            return chunks
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл {file_path} не найден")
        except UnicodeDecodeError:
            # Пробуем другие кодировки
            try:
                with open(file_path, 'r', encoding='cp1251') as file:
                    lines = file.readlines()
                chunks = [
                    lines[i:i + self.config.chunk_size] 
                    for i in range(0, len(lines), self.config.chunk_size)
                ]
                return chunks
            except:
                raise ValueError(f"Не удалось прочитать файл {file_path}")
    
    def parse_log_file(self, log_file_path: str) -> Dict[str, int]:
        """
        Парсит лог-файл nginx многопоточно и возвращает уникальные пути 
        с количеством вхождений.
        
        Args:
            log_file_path (str): Путь к файлу логов nginx
            
        Returns:
            Dict[str, int]: Словарь с путями и количеством их вхождений,
                           отсортированный по убыванию частоты
        """
        # Сбрасываем счетчик и кэш перед новым парсингом
        self._path_counter.clear()
        self._process_path.cache_clear()
        
        try:
            chunks = self._read_file_chunks(log_file_path)
        except Exception as e:
            print(f"Ошибка при чтении файла: {e}")
            return {}
        
        # Многопоточная обработка чанков
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_chunk = {
                executor.submit(self._parse_chunk, chunk): i 
                for i, chunk in enumerate(chunks)
            }
            
            for future in as_completed(future_to_chunk):
                try:
                    chunk_result = future.result()
                    # Безопасное объединение результатов
                    with self._counter_lock:
                        for path, count in chunk_result.items():
                            self._path_counter[path] += count
                except Exception as e:
                    print(f"Ошибка при обработке чанка: {e}")
        
        # Сортируем по убыванию количества вхождений
        return dict(sorted(
            self._path_counter.items(), 
            key=lambda x: x[1], 
            reverse=True
        ))

# Функция для обратной совместимости
def parse_nginx_logs(
    log_file_path: str, 
    config_path: str = "config.yaml"
) -> Dict[str, int]:
    """
    Упрощенная функция для обратной совместимости.
    
    Args:
        log_file_path (str): Путь к файлу логов nginx
        config_path (str): Путь к конфигурационному файлу
        
    Returns:
        Dict[str, int]: Словарь с путями и количеством их вхождений
    """
    parser = NginxLogParser(config_path)
    return parser.parse_log_file(log_file_path)

# Пример использования и тестирования
if __name__ == "__main__":
    import time
    
    # Создаем тестовый лог-файл
    test_logs = [
        '192.168.1.1 - - [01/Jan/2023:10:00:00 +0000] "GET /api/v1/users/list HTTP/1.1" 200 1234',
        '192.168.1.2 - - [01/Jan/2023:10:00:01 +0000] "POST /api/v1/auth/login HTTP/1.1" 200 567',
        '192.168.1.3 - - [01/Jan/2023:10:00:02 +0000] "GET /static/css/style.css HTTP/1.1" 200 8910',
        '192.168.1.1 - - [01/Jan/2023:10:00:03 +0000] "GET /api/v1/users/list HTTP/1.1" 200 1234',
        '192.168.1.4 - - [01/Jan/2023:10:00:04 +0000] "GET /api/v1/products/categories/electronics/computers HTTP/1.1" 200 2345',
        '192.168.1.5 - - [01/Jan/2023:10:00:05 +0000] "GET / HTTP/1.1" 200 123',
        '192.168.1.6 - - [01/Jan/2023:10:00:06 +0000] "GET /health HTTP/1.1" 200 45',  # Игнорируемый путь
    ]
    
    with open('test_nginx.log', 'w', encoding='utf-8') as f:
        f.write('\n'.join(test_logs))
    
    # Тестируем
    parser = NginxLogParser()
    
    start_time = time.time()
    result = parser.parse_log_file('test_nginx.log')
    end_time = time.time()
    
    print(f"Парсинг занял: {end_time - start_time:.4f} секунд")
    print("\nРезультат парсинга:")
    for path, count in result.items():
        print(f"{path}: {count}")
    
    # Тестируем функцию обратной совместимости
    print("\nРезультат через функцию обратной совместимости:")
    simple_result = parse_nginx_logs('test_nginx.log')
    for path, count in simple_result.items():
        print(f"{path}: {count}")
