import re
import yaml
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, NamedTuple, Set, Union
from pathlib import Path
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from datetime import datetime, date

class PathInfo(NamedTuple):
    """Информация о пути: количество обращений, последняя дата и IP."""
    count: int
    last_access: date
    last_ip: str

@dataclass(frozen=True)
class ParserConfig:
    """Конфигурация парсера."""
    max_workers: int
    chunk_size: int
    max_path_depth: int
    log_pattern: str
    encoding: str
    ignore_paths: Tuple[str, ...]
    exclude_ips: Tuple[str, ...]
    include_ips: Tuple[str, ...]
    date_format: str

class IPFilter:
    """Класс для фильтрации IP-адресов."""
    
    def __init__(self, exclude_ips: Tuple[str, ...], include_ips: Tuple[str, ...]):
        self.exclude_ips = self._parse_ip_list(exclude_ips)
        self.include_ips = self._parse_ip_list(include_ips)
        self.include_mode = len(include_ips) > 0
    
    def _parse_ip_list(self, ip_list: Tuple[str, ...]) -> Set[ipaddress.IPv4Address]:
        """Парсит список IP-адресов в множество объектов IPv4Address."""
        result = set()
        for ip_str in ip_list:
            try:
                ip = ipaddress.IPv4Address(ip_str.strip())
                result.add(ip)
            except ipaddress.AddressValueError:
                print(f"Предупреждение: некорректный IP-адрес '{ip_str}' будет проигнорирован")
        return result
    
    def should_process(self, ip_str: str) -> bool:
        """
        Определяет, нужно ли обрабатывать запрос от данного IP-адреса.
        """
        try:
            ip = ipaddress.IPv4Address(ip_str.strip())
        except ipaddress.AddressValueError:
            return False
        
        if self.include_mode:
            return ip in self.include_ips
        else:
            return ip not in self.exclude_ips

class NginxLogParser:
    """Многопоточный парсер логов nginx с фильтрацией по IP и отслеживанием последнего IP."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.ip_filter = IPFilter(self.config.exclude_ips, self.config.include_ips)
        self._data_lock = threading.Lock()
        self._path_data = defaultdict(lambda: {
            'count': 0, 
            'last_access': date.min,
            'last_ip': 'неизвестно'
        })
    
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
                ignore_paths=tuple(log_parser_config.get('ignore_paths', [])),
                exclude_ips=tuple(log_parser_config.get('exclude_ips', [])),
                include_ips=tuple(log_parser_config.get('include_ips', [])),
                date_format=log_parser_config['settings']['date_format']
            )
        except Exception as e:
            raise ValueError(f"Ошибка загрузки конфигурации: {e}")
    
    def _parse_date(self, date_str: str) -> Optional[date]:
        """Парсит дату из строки лога."""
        try:
            dt = datetime.strptime(date_str, self.config.date_format)
            return dt.date()
        except (ValueError, TypeError):
            return None
    
    @lru_cache(maxsize=1000)
    def _process_path(self, path: str) -> Optional[str]:
        """
        Обрабатывает путь: декодирует URL и ограничивает глубину.
        """
        if not path or path == '/':
            return '/'
        
        if path in self.config.ignore_paths:
            return None
        
        try:
            decoded_path = urllib.parse.unquote(path)
            parts = decoded_path.strip('/').split('/')
            limited_parts = parts[:self.config.max_path_depth]
            result_path = '/' + '/'.join(limited_parts)
            return result_path
            
        except Exception:
            parts = path.strip('/').split('/')[:self.config.max_path_depth]
            return '/' + '/'.join(parts)
    
    def _parse_chunk(self, chunk: List[str]) -> Dict[str, dict]:
        """Парсит чанк строк лога и возвращает данные о путях."""
        local_data = {}
        pattern = re.compile(self.config.log_pattern)
        
        for line in chunk:
            if not line.strip():
                continue
                
            match = pattern.search(line)
            if match:
                try:
                    ip = match.group('remote_addr')
                    path = match.group('path')
                    time_local = match.group('time_local')
                    
                    # Проверяем IP-адрес
                    if not self.ip_filter.should_process(ip):
                        continue
                    
                    processed_path = self._process_path(path)
                    if not processed_path:
                        continue
                    
                    access_date = self._parse_date(time_local)
                    
                    # Обновляем данные для пути
                    if processed_path not in local_data:
                        local_data[processed_path] = {
                            'count': 0, 
                            'last_access': access_date or date.min,
                            'last_ip': ip
                        }
                    
                    local_data[processed_path]['count'] += 1
                    
                    # Обновляем последнюю дату доступа и IP
                    if access_date:
                        if (access_date > local_data[processed_path]['last_access'] or 
                            (access_date == local_data[processed_path]['last_access'] and 
                             line > getattr(local_data[processed_path], '_last_line', ''))):
                            local_data[processed_path]['last_access'] = access_date
                            local_data[processed_path]['last_ip'] = ip
                            local_data[processed_path]['_last_line'] = line  # Для отладки
                        
                except (IndexError, KeyError):
                    continue
        
        # Удаляем служебные поля
        for data in local_data.values():
            data.pop('_last_line', None)
        
        return local_data
    
    def _read_file_chunks(self, file_path: str) -> List[List[str]]:
        """Читает файл и разбивает на чанки для многопоточной обработки."""
        try:
            with open(file_path, 'r', encoding=self.config.encoding) as file:
                lines = file.readlines()
            
            chunks = [
                lines[i:i + self.config.chunk_size] 
                for i in range(0, len(lines), self.config.chunk_size)
            ]
            return chunks
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл {file_path} не найден")
        except UnicodeDecodeError:
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
    
    def parse_log_file(self, log_file_path: str) -> Dict[str, PathInfo]:
        """
        Парсит лог-файл nginx многопоточно с фильтрацией по IP.
        """
        self._path_data.clear()
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
                    with self._data_lock:
                        for path, data in chunk_result.items():
                            if path not in self._path_data:
                                self._path_data[path] = data.copy()
                            else:
                                # Обновляем счетчик
                                self._path_data[path]['count'] += data['count']
                                
                                # Обновляем последнюю дату и IP
                                current_data = self._path_data[path]
                                if (data['last_access'] and 
                                    data['last_access'] > current_data['last_access']):
                                    current_data['last_access'] = data['last_access']
                                    current_data['last_ip'] = data['last_ip']
                                elif (data['last_access'] and 
                                      data['last_access'] == current_data['last_access'] and
                                      data.get('_last_line', '') > getattr(current_data, '_last_line', '')):
                                    # Если дата одинаковая, используем последнюю строку в логе
                                    current_data['last_ip'] = data['last_ip']
                                    
                except Exception as e:
                    print(f"Ошибка при обработке чанка: {e}")
        
        # Конвертируем в именованные кортежи и сортируем
        result = {
            path: PathInfo(data['count'], data['last_access'], data['last_ip'])
            for path, data in self._path_data.items()
        }
        
        return dict(sorted(
            result.items(), 
            key=lambda x: x[1].count, 
            reverse=True
        ))

    def get_filter_info(self) -> str:
        """Возвращает информацию о текущих настройках фильтрации."""
        if self.ip_filter.include_mode:
            mode = "ВКЛЮЧЕНИЕ"
            ips = ", ".join(str(ip) for ip in self.ip_filter.include_ips) or "нет"
            return f"Режим: {mode} | Обрабатываются IP: {ips}"
        else:
            mode = "ИСКЛЮЧЕНИЕ"
            ips = ", ".join(str(ip) for ip in self.ip_filter.exclude_ips) or "нет"
            return f"Режим: {mode} | Исключаются IP: {ips}"

    def format_results(self, results: Dict[str, PathInfo], show_ip: bool = True) -> str:
        """
        Форматирует результаты для красивого вывода.
        
        Args:
            results (Dict[str, PathInfo]): Результаты парсинга
            show_ip (bool): Показывать ли IP-адрес последнего доступа
            
        Returns:
            str: Отформатированная строка с результатами
        """
        if not results:
            return "Нет данных для отображения"
        
        output = []
        output.append("Результаты парсинга логов nginx:")
        output.append(f"Фильтрация: {self.get_filter_info()}")
        output.append("-" * 90)
        
        if show_ip:
            output.append(f"{'ПУТЬ':<45} {'КОЛИЧЕСТВО':<10} {'ПОСЛЕДНИЙ ДОСТУП':<15} {'ПОСЛЕДНИЙ IP':<15}")
            output.append("-" * 90)
            
            for path, info in results.items():
                last_access = info.last_access.strftime("%d.%m.%Y") if info.last_access != date.min else "неизвестно"
                output.append(f"{path:<45} {info.count:<10} {last_access:<15} {info.last_ip:<15}")
        else:
            output.append(f"{'ПУТЬ':<50} {'КОЛИЧЕСТВО':<12} {'ПОСЛЕДНИЙ ДОСТУП':<15}")
            output.append("-" * 80)
            
            for path, info in results.items():
                last_access = info.last_access.strftime("%d.%m.%Y") if info.last_access != date.min else "неизвестно"
                output.append(f"{path:<50} {info.count:<12} {last_access:<15}")
        
        output.append("-" * (90 if show_ip else 80))
        output.append(f"Всего уникальных путей: {len(results)}")
        
        return "\n".join(output)

    def export_to_csv(self, results: Dict[str, PathInfo], csv_file: str = "nginx_stats.csv"):
        """
        Экспортирует результаты в CSV файл.
        
        Args:
            results (Dict[str, PathInfo]): Результаты парсинга
            csv_file (str): Путь к CSV файлу для экспорта
        """
        import csv
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Путь', 'Количество_обращений', 'Последний_доступ', 'Последний_IP'])
                
                for path, info in results.items():
                    last_access = info.last_access.strftime("%d.%m.%Y") if info.last_access != date.min else "неизвестно"
                    writer.writerow([path, info.count, last_access, info.last_ip])
            
            print(f"Результаты экспортированы в {csv_file}")
        except Exception as e:
            print(f"Ошибка при экспорте в CSV: {e}")

# Функции для обратной совместимости
def parse_nginx_logs(
    log_file_path: str, 
    config_path: str = "config.yaml"
) -> Dict[str, PathInfo]:
    """
    Упрощенная функция для обратной совместимости.
    """
    parser = NginxLogParser(config_path)
    return parser.parse_log_file(log_file_path)

def print_nginx_logs_stats(
    log_file_path: str, 
    config_path: str = "config.yaml", 
    show_ip: bool = True
):
    """
    Выводит статистику по логам в удобном формате.
    
    Args:
        log_file_path (str): Путь к файлу логов nginx
        config_path (str): Путь к конфигурационному файлу
        show_ip (bool): Показывать ли IP-адрес последнего доступа
    """
    parser = NginxLogParser(config_path)
    results = parser.parse_log_file(log_file_path)
    print(parser.format_results(results, show_ip=show_ip))

# Пример использования и тестирования
if __name__ == "__main__":
    import time
    
    # Создаем тестовый лог-файл с разными IP и датами
    test_logs = [
        '192.168.1.1 - - [01/Jan/2023:10:00:00 +0000] "GET /api/v1/users/list HTTP/1.1" 200 1234',
        '192.168.1.2 - - [02/Jan/2023:11:00:01 +0000] "POST /api/v1/auth/login HTTP/1.1" 200 567',
        '127.0.0.1 - - [03/Jan/2023:12:00:02 +0000] "GET /static/css/style.css HTTP/1.1" 200 8910',
        '192.168.1.1 - - [04/Jan/2023:13:00:03 +0000] "GET /api/v1/users/list HTTP/1.1" 200 1234',
        '192.168.1.100 - - [05/Jan/2023:14:00:04 +0000] "GET /api/v1/products/categories/electronics/computers HTTP/1.1" 200 2345',
        '192.168.1.3 - - [06/Jan/2023:15:00:05 +0000] "GET / HTTP/1.1" 200 123',
        '10.0.0.1 - - [07/Jan/2023:16:00:06 +0000] "GET /health HTTP/1.1" 200 45',
        '192.168.1.4 - - [08/Jan/2023:17:00:07 +0000] "GET /api/v1/auth/login HTTP/1.1" 200 678',
        '192.168.1.5 - - [01/Feb/2023:18:00:08 +0000] "GET /api/v1/users/list HTTP/1.1" 200 1234',  # Последний доступ с другим IP
    ]
    
    with open('test_nginx.log', 'w', encoding='utf-8') as f:
        f.write('\n'.join(test_logs))
    
    print("=== ТЕСТ С ВЫВОДОМ IP АДРЕСОВ ===")
    parser = NginxLogParser()
    
    start_time = time.time()
    results = parser.parse_log_file('test_nginx.log')
    end_time = time.time()
    
    print(f"Парсинг занял: {end_time - start_time:.4f} секунд\n")
    print(parser.format_results(results, show_ip=True))
    
    # Экспорт в CSV
    parser.export_to_csv(results, "test_results.csv")
    
    print("\n" + "="*90)
    print("=== ДЕТАЛЬНАЯ ИНФОРМАЦИЯ ===")
    for path, info in results.items():
        last_access = info.last_access.strftime("%d.%m.%Y") if info.last_access != date.min else "неизвестно"
        print(f"Путь: {path}")
        print(f"  Обращений: {info.count}")
        print(f"  Последний доступ: {last_access}")
        print(f"  IP последнего обращения: {info.last_ip}")
        print()
