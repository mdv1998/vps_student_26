import re
import socket
import hashlib

def extract_ip(log_line: str) -> str | None:
    # Пример шаблона регулярного выражения для поиска IPv4 после слов 'from'
    if "Failed password" in log_line or "Invalid user" in log_line:
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            return match.group(1)
    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    attacks = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks

def detect_brute_force(attacks: dict[str, int], threshold: int = 5) -> list[str]:
    result = []
    for ip, count in attacks.items():
        if count >= threshold:
            result.append(ip)
    return result


def detect_suspicious_paths(log_line: str) -> bool:
    signatures = ["/etc/passwd", ".env", "wp-admin", "select+union", "union+select", "shell.php"]
    log_lower = log_line.lower()
    for signature in signatures:
        if signature in log_lower:
            return True
    return False

def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    score = (brute_force_alerts * 3) + web_alerts
    if score == 0:
        return "LOW"
    elif score < 5:
        return "MEDIUM"
    else:
        return "HIGH"

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Кейс 6: Безопасный сканер сетевой доступности VPS.
    Проверяет, открыт ли конкретный порт на сервере по протоколу TCP.
    """
    # TODO: Напишите код функции
    # 1. Используйте модуль socket для создания TCP-сокета (AF_INET, SOCK_STREAM)
    # 2. Установите таймаут подключения
    # 3. Попробуйте подключиться к (ip, port) с помощью метода connect_ex
    # 4. Метод возвращает 0 при успешном подключении (порт открыт)
    # 5. Обработайте возможные исключения и верните результат (True/False)
    pass

def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Контроль целостности файлов на VPS (SHA-256).
    Вычисляет криптографический хеш файла для отслеживания изменений.
    """
    # TODO: Напишите код функции
    # 1. Используйте библиотеку hashlib (алгоритм sha256)
    # 2. Попробуйте открыть файл в режиме бинарного чтения 'rb'
    # 3. Прочитайте файл порциями (блоками) и обновите хеш
    # 4. Верните строковое представление хеша в шестнадцатеричном виде (hexdigest)
    # 5. Если файл не найден (FileNotFoundError), верните строку "FILE_NOT_FOUND"
    pass
