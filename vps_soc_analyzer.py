import re
import socket
import hashlib

def extract_ip(log_line: str) -> str | None:
    """
    Ищет IP-адрес в строке лога,
    сигнализирующей о неудачной попытке входа по SSH.
    """
    if "Failed password" in log_line:
        match = re.search(
            r"from\s+(\d{1,3}(?:\.\d{1,3}){3})",
            log_line
        )
        if match:
            return match.group(1)

    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Подсчитывает число неудачных попыток входа для каждого IP.
    """
    ip_counts = {}

    for line in log_lines:
        ip = extract_ip(line)

        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return ip_counts

def detect_brute_force(
    ip_counts: dict[str, int],
    threshold: int = 5
) -> list[str]:
    """
    Выявляет IP-адреса с количеством попыток
    больше или равно threshold.
    """
    return [
        ip
        for ip, count in ip_counts.items()
        if count >= threshold
    ]

def detect_suspicious_paths(log_line: str) -> bool:
    """
    Проверяет строку лога на известные сигнатуры веб-атак.
    """
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php",
    ]

    line = log_line.lower()

    return any(signature in line for signature in signatures)

def calculate_risk_score(
    brute_force_alerts: int,
    web_alerts: int
) -> str:
    """
    Вычисляет общий уровень риска.
    """
    risk_score = brute_force_alerts * 3 + web_alerts

    if risk_score == 0:
        return "LOW"
    elif risk_score < 5:
        return "MEDIUM"
    else:
        return "HIGH"

def is_port_open(
    ip: str,
    port: int,
    timeout: float = 1.0
) -> bool:
    """
    Проверяет доступность TCP-порта.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except (socket.error, OSError):
        return False

def get_file_hash(filepath: str) -> str:
    """
    Вычисляет SHA-256 хеш файла.
    """
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except FileNotFoundError:
        return "FILE_NOT_FOUND"