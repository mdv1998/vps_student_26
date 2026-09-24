import sys
from vps_soc_analyzer import (
    extract_ip,
    group_by_ip,
    detect_brute_force,
    detect_suspicious_paths,
    calculate_risk_score,
    is_port_open,
    get_file_hash
)

def run_pipeline(log_path: str) -> None:
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log_lines: list[str] = f.readlines()
        
        print(f"[+] Успешно прочитано строк из файла логов: {len(log_lines)}")
        
        attack_counts = group_by_ip(log_lines)
        suspicious_ips = detect_brute_force(attack_counts, threshold=5)
        brute_force_alerts_count = len(suspicious_ips)
        
        web_alerts_count = 0
        for line in log_lines:
            if detect_suspicious_paths(line):
                web_alerts_count += 1

        risk_level = calculate_risk_score(brute_force_alerts_count, web_alerts_count)
        ssh_port_status = is_port_open("127.0.0.1", 22, timeout=0.5)
        log_file_hash = get_file_hash(log_path)

        print("\n" + "="*60)
        print(f"       ОБНОВЛЕННЫЙ ОТЧЕТ БЕЗОПАСНОСТИ MINI-SOC VPS")
        print("="*60)
        print(f"[*] СИСТЕМНЫЙ УРОВЕНЬ УГРОЗЫ: >>> {risk_level} <<<")
        print(f"[*] Хеш-сумма файла логов (SHA-256): {log_file_hash}")
        print(f"[*] Статус SSH порта (22) локально: {'ОТКРЫТ' if ssh_port_status else 'ЗАКРЫТ'}")
        print("-" * 60)
        print(f"[!] Зафиксировано подозрительных веб-запросов: {web_alerts_count}")
        print("-" * 60)
        
        if not suspicious_ips:
            print("[*] Подозрительных SSH IP-адресов не обнаружено.")
        else:
            print(f"[!] Найдено SSH-хостов для блокировки: {len(suspicious_ips)}\n")
            print(f"{'IP-Адрес':<20} | {'Количество попыток':<15}")
            print("-" * 40)
            for ip in sorted(suspicious_ips):
                print(f"{ip:<20} | {attack_counts[ip]:<15}")
                
        print("="*60)

    except FileNotFoundError:
        print(f"[-] Ошибка: Файл по пути '{log_path}' не найден.")
    except Exception as e:
        print(f"[-] Непредвиденная ошибка при обработке: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_log = sys.argv[1]
    else:
        target_log = "/home/student/logs/auth.log"
        
    run_pipeline(target_log)
