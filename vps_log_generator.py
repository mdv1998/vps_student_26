import random
import datetime

def generate_mock_ssh_logs(num_lines=100):
    ips = ["192.168.1." + str(i) for i in range(1, 20)] + ["10.0.0." + str(i) for i in range(1, 10)]
    users = ["root", "admin", "user", "guest", "test", "ubuntu", "debian", "ftpuser"]
    logs = []
    for _ in range(num_lines):
        ip = random.choice(ips)
        user = random.choice(users)
        if random.random() < 0.8:
            log = f"Sep {random.randint(1,30):02d} 12:{random.randint(0,59):02d}:{random.randint(0,59):02d} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(10000,65535)} ssh2"
        else:
            log = f"Sep {random.randint(1,30):02d} 12:{random.randint(0,59):02d}:{random.randint(0,59):02d} server sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(10000,65535)} ssh2"
        logs.append(log)
    return logs

def generate_mock_nginx_logs(num_lines=50):
    ips = ["192.168.1." + str(i) for i in range(1, 10)] + ["10.0.0." + str(i) for i in range(1, 5)]
    paths = [
        "/index.html", "/about", "/contact", "/products", "/images/logo.png",
        "/etc/passwd", "/.env", "/wp-admin", "/admin", "/shell.php",
        "/../../etc/passwd", "/select+union", "/union+select"
    ]
    logs = []
    for _ in range(num_lines):
        ip = random.choice(ips)
        path = random.choice(paths)
        status = random.choice([200, 404, 403, 500])
        size = random.randint(100, 5000)
        log = f'{ip} - - [{datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size}'
        logs.append(log)
    return logs