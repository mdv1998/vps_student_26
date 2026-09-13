import re
import socket
import hashlib

# Регулярное выражение для поиска IPv4-адреса после слова 'from'
_IP_PATTERN: re.Pattern[str] = re.compile(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Сигнатуры веб-атак (ищутся в строке лога, приведённой к нижнему регистру)
_SUSPICIOUS_SIGNATURES: tuple[str, ...] = (
    '/etc/passwd',
    '.env',
    'wp-admin',
    'select+union',
    'union+select',
    'shell.php',
)


def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Парсинг реальных логов VPS с регулярными выражениями (re).
    Ищет IP-адрес в строке лога, сигнализирующей о неудачной попытке входа по SSH.
    """
    if 'Failed password' in log_line or 'Invalid user' in log_line:
        match = _IP_PATTERN.search(log_line)
        if match:
            return match.group(1)
    return None


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Группировка атак по IP (Агрегация через dict).
    Подсчитывает общее число неудачных попыток входа для каждого IP-адреса.
    """
    ip_counts: dict[str, int] = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip is not None:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    return ip_counts


def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """
    Кейс 3: Детектор SSH Brute-Force.
    Выявляет IP-адреса, количество неудачных входов которых превышает порог threshold.
    """
    return [ip for ip, count in ip_counts.items() if count >= threshold]


def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Поиск сигнатур веб-атак в логах Nginx/Apache.
    Проверяет, содержит ли веб-запрос известные сигнатуры угроз (LFI, раскрытие путей, инъекции).
    """
    lowered = log_line.lower()
    return any(signature in lowered for signature in _SUSPICIOUS_SIGNATURES)


def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Кейс 5: Расчет условного уровня риска (Risk Scoring).
    На основе количества сработавших алертов вычисляет общий уровень угрозы.
    """
    score = brute_force_alerts * 3 + web_alerts * 1
    if score == 0:
        return 'LOW'
    if score < 5:
        return 'MEDIUM'
    return 'HIGH'


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Кейс 6: Безопасный сканер сетевой доступности VPS.
    Проверяет, открыт ли конкретный порт на сервере по протоколу TCP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False


def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Контроль целостности файлов на VPS (SHA-256).
    Вычисляет криптографический хеш файла для отслеживания изменений.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as file:
            for chunk in iter(lambda: file.read(8192), b''):
                sha256.update(chunk)
    except FileNotFoundError:
        return 'FILE_NOT_FOUND'
    return sha256.hexdigest()
