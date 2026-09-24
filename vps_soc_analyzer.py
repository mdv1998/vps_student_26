import re
import socket
import hashlib

def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Парсинг реальных логов VPS с регулярными выражениями.
    Ищет IP-адрес в строке лога, сигнализирующей о неудачной попытке входа по SSH.
    """
    if "Failed password" in log_line or "Invalid user" in log_line:
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            return match.group(1)
    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Группировка атак по IP (Агрегация через dict).
    Подсчитывает общее число неудачных попыток входа для каждого IP-адреса.
    """
    attacks: dict[str, int] = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks

def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """
    Кейс 3: Детектор SSH Brute-Force.
    Выявляет IP-адреса, количество неудачных входов которых превышает порог threshold.
    Возвращает список (list) строк.
    """
    trigger_ips: list[str] = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            trigger_ips.append(ip)
    return trigger_ips

def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Поиск сигнатур веб-атак в логах Nginx/Apache.
    Проверяет, содержит ли веб-запрос известные сигнатуры угроз.
    """
    signatures = ['/etc/passwd', '.env', 'wp-admin', 'select+union', 'union+select', 'shell.php']
    line_lower = log_line.lower()
    
    for signature in signatures:
        if signature in line_lower:
            return True
    return False

def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Кейс 5: Расчет условного уровня риска (Risk Scoring).
    На основе количества сработавших алертов вычисляет общий уровень угрозы.
    """
    score = (brute_force_alerts * 3) + (web_alerts * 1)
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Контроль целостности файлов на VPS (SHA-256).
    Вычисляет криптографический хеш файла для отслеживания изменений.
    """
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
