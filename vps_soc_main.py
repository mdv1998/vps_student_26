import os
import sys

# Добавляем текущую директорию в пути импорта Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем студенческий модуль аналитики
try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py. Переименуйте шаблон или создайте его!")
    sys.exit(1)

def run_pipeline():
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS (СТУДЕНЧЕСКИЙ ШАБЛОН)")
    print("=" * 60)

    # Шаг 1: Анализ реальных логов SSH
    print("[1] Анализ логов SSH (/home/student/logs/auth.log):")
    
    ssh_log_path = "/home/student/logs/auth.log"
    
    try:
        with open(ssh_log_path, "r", encoding='utf-8') as f:
            ssh_logs = f.readlines()
    except FileNotFoundError:
        print(f"    [!] Файл {ssh_log_path} не найден! Проверьте путь.")
        return
    
    print(f"    - Всего строк в логе: {len(ssh_logs)}")
    
    # ГРУППИРОВКА АТАК ПО IP
    ip_attempts = analyzer.group_by_ip(ssh_logs)
    
    print(f"    - Всего уникальных IP, совершивших неудачный вход: {len(ip_attempts)}")
    for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"      * IP: {ip} - {count} неудачных попыток")
        
    # ДЕТЕКТОР БРУТФОРС-АТАК
    bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)
    
    print(f"    - ОБНАРУЖЕНО БРУТФОРС-АТАК (>= 5 попыток): {len(bf_alerts)}")
    for ip in bf_alerts:
        print(f"      [ALERT] IP {ip} превысил порог! Рекомендуется блокировка!")
    print("-" * 60)

    # Шаг 2: Оценка риска
    print("[2] Оценка уровня угрозы VPS (Risk Scoring):")
    risk = analyzer.calculate_risk_score(len(bf_alerts), 0)
    print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # Шаг 3: Контроль целостности файлов
    print("[3] Контроль целостности файлов на VPS:")
    dummy_config = "/tmp/vps_secure_config.conf"
    
    with open(dummy_config, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")
    
    hash_original = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма файла {dummy_config} (SHA-256): {hash_original}")
    
    # Симулируем несанкционированное изменение (взлом)
    with open(dummy_config, "a") as f:
        f.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")
        
    hash_modified = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма после изменения: {hash_modified}")
    
    if hash_original != hash_modified:
        print("    - [!] ВНИМАНИЕ: Целостность конфигурационного файла НАРУШЕНА!")
    else:
        print("    - [OK] Файл конфигурации не изменен.")
    print("-" * 60)

    # Шаг 4: Проверка доступности портов
    print("[4] Сетевая разведка (Тестовый сканер портов):")
    ports_to_scan = [22, 80, 443, 8080]
    print(f"    - Сканируем порты на localhost (127.0.0.1): {ports_to_scan}")
    for port in ports_to_scan:
        is_open = analyzer.is_port_open("127.0.0.1", port, timeout=0.5)
        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f"      * Порт {port}: {status}")
    print("-" * 60)

    # Очистка временных файлов
    if os.path.exists(dummy_config):
        os.remove(dummy_config)
            
    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()