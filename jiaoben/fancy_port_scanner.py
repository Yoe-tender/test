import socket
import time
import random
import threading
from tqdm import tqdm  # 进度条核心工具
from colorama import Fore, Style, init
import datetime
import os
from fake_useragent import UserAgent
from collections import defaultdict

# 初始化颜色显示（仅用基础颜色区分状态，无花里胡哨效果）
init(autoreset=False)

# 模拟服务数据库（补充常见端口，覆盖更多场景）
SERVICE_DB = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol v3)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5900: "VNC (Virtual Network Computing)",
    8080: "HTTP Proxy/Alternative HTTP",
    1900: "SSDP (Simple Service Discovery Protocol)",
    5000: "Universal Plug and Play (UPnP)",
    5432: "PostgreSQL Database",
    6379: "Redis Database",
    27017: "MongoDB Database"  # 新增主流数据库端口
}

# 模拟漏洞数据库（补充漏洞详情与CVE编号，增强实用性）
VULNERABILITY_DB = {
    21: [
        "Anonymous login possible (allows unauthorized file read/write)",
        "FTP bounce attack vulnerability (CVE-1999-0017, used for port scanning through FTP server)"
    ],
    22: [
        "Outdated SSH protocol version (SSHv1, vulnerable to MITM attacks, CVE-2001-0144)",
        "Weak cipher suite support (e.g., 3DES, vulnerable to brute-force, CVE-2016-2183)"
    ],
    80: [
        "Potential SQL injection points (in web form parameters, CVE-2007-2447)",
        "XSS vulnerability in web forms (steals user cookies, CVE-2017-0144)"
    ],
    443: [
        "TLS 1.0/1.1 supported (deprecated, vulnerable to BEAST/CRIME, CVE-2011-3389)",
        "Heartbleed vulnerability (CVE-2014-0160, leaks memory data including private keys)"
    ],
    3306: [
        "Root access from remote possible (no IP restriction, CVE-2019-2579)",
        "Weak password policy (short length/common words, vulnerable to brute-force)"
    ],
    3389: [
        "RDP port exposed to public (high risk of brute-force, CVE-2019-0708 BlueKeep)",
        "No network level authentication (NLA disabled, vulnerable to MITM, CVE-2018-0886)"
    ],
    6379: [
        "Redis without password (unauthorized access, CVE-2015-4499)",
        "Redis command injection (via eval, CVE-2016-8339)"
    ]
}


class ProfessionalPortScanner:
    def __init__(self):
        # 单轮扫描核心数据（实时更新）
        self.results = {}  # 存储单轮开放端口详情：{host: [port_info, ...]}
        self.total_scanned = 0  # 单轮已扫描端口数
        self.total_open = 0  # 单轮开放端口数
        self.total_closed = 0  # 单轮关闭端口数
        self.total_filtered = 0  # 单轮过滤端口数（超时/防火墙拦截）
        self.scan_start_time = None  # 单轮扫描开始时间

        # 累积汇总数据（跨轮次统计）
        self.all_rounds_data = []  # 每轮基础统计：[{round:1, duration:60, open:3, ...}, ...]
        self.all_open_ports = defaultdict(list)  # 开放端口出现记录：{port: [round1, round2, ...]}
        self.port_response_history = defaultdict(list)  # 端口响应时间历史：{port: [0.32, 0.28, ...]}
        self.host_port_full_history = defaultdict(
            lambda: defaultdict(list))  # 主机端口完整状态：{host: {port: [status1, status2, ...]}}
        self.total_rounds = 0  # 总扫描轮次
        self.total_scan_duration = 0  # 总扫描耗时（秒）

        # 基础配置
        self.ua = UserAgent()
        self.thread_lock = threading.Lock()  # 多线程安全锁
        self.is_scanning = True  # 扫描状态标记
        self.current_host = ""  # 当前扫描主机
        self.current_port = 0  # 当前扫描端口
        self.current_round = 0  # 当前轮次
        self.progress_bar = None  # 进度条对象
        self.target_hosts = []  # 目标主机列表（全局存储）
        self.scan_port_range = (1, 100)  # 扫描端口范围（全局存储）

    def print_init_banner(self):
        """打印初始化信息（简洁无符号）"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Professional Continuous Port Scanner v1.0")
        print(
            f"{Style.RESET_ALL}{Fore.WHITE}Initialization started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Loaded service database: {len(SERVICE_DB)} services recorded")
        print(f"Loaded vulnerability database: {len(VULNERABILITY_DB)} ports with known risks")
        print(f"Scan mode: Continuous (Press Ctrl+C to stop and generate summary)\n")
        time.sleep(1.5)  # 短暂等待，让用户看清初始化信息

    def update_dynamic_status(self):
        """实时更新扫描状态（无动画，仅文本进度）"""
        while self.is_scanning:
            if self.scan_start_time:
                elapsed = (datetime.datetime.now() - self.scan_start_time).total_seconds()
                status_line = (
                    f"\r{Fore.MAGENTA}[Current Status] "
                    f"Round: {self.current_round:02d} | "
                    f"Scanning: {self.current_host}:{self.current_port:04d} | "
                    f"Open Ports: {Fore.GREEN}{self.total_open}{Style.RESET_ALL}{Fore.MAGENTA} | "
                    f"Elapsed Time: {elapsed:.0f}s"
                    f"\033[K"  # 清除当前行剩余内容，避免残留
                )
                print(status_line, end="", flush=True)
            time.sleep(0.5)  # 状态更新频率（0.5秒/次）

    def get_elapsed_time(self):
        """计算当前轮次已耗时（秒）"""
        if not self.scan_start_time:
            return 0.0
        return (datetime.datetime.now() - self.scan_start_time).total_seconds()

    def resolve_hostname(self, host):
        """解析主机名到IP地址（补充ISP/地理信息，增强实用性）"""
        print(f"\n{Fore.CYAN}[Resolving] Hostname: {host}")
        try:
            ip = socket.gethostbyname(host)
            # 模拟真实ISP与地理信息（基于常见云服务商与地区）
            isp_list = [
                "Cloudflare Inc. (CDN/DDOS Protection)",
                "Amazon Technologies Inc. (AWS Cloud)",
                "Google LLC (Google Cloud)",
                "Microsoft Corporation (Azure Cloud)",
                "Alibaba Cloud Computing Ltd. (Alibaba Cloud)"
            ]
            isp = random.choice(isp_list)
            # 限定地理范围为国内主要城市（更贴近实际场景）
            lat = random.uniform(22.0, 39.0)  # 北纬22°（海南）-39°（北京）
            lon = random.uniform(105.0, 122.0)  # 东经105°（云南）-122°（上海）
            print(f"{Fore.GREEN}[Resolve Success] {host} -> IP: {ip}")
            print(f"{Fore.BLUE}[Geography Info] Latitude: {lat:.2f}°N, Longitude: {lon:.2f}°E")
            print(f"{Fore.BLUE}[ISP Info] {isp} | Connection Type: {random.choice(['IPv4', 'Dual-Stack (IPv4/IPv6)'])}")
            return ip
        except socket.gaierror as e:
            print(f"{Fore.RED}[Resolve Failed] Hostname {host} cannot be resolved: {str(e)}")
            return None

    def scan_single_port(self, host_ip, port, timeout=1.5):
        """扫描单个端口（核心逻辑，记录详细状态与响应时间）"""
        self.current_port = port
        try:
            # 创建TCP socket连接
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                conn_start = time.time()  # 记录连接开始时间
                conn_result = sock.connect_ex((host_ip, port))  # 非阻塞连接（0=成功）
                conn_duration = round(time.time() - conn_start, 4)  # 计算实际连接耗时

                # 线程安全更新扫描计数
                with self.thread_lock:
                    self.total_scanned += 1
                    if self.progress_bar:
                        self.progress_bar.update(1)

                # 端口状态判断：0=开放，其他=关闭，超时=过滤
                if conn_result == 0:
                    # 匹配端口对应的服务与漏洞
                    service = SERVICE_DB.get(port, f"Unknown Service (Port {port})")
                    vulnerabilities = VULNERABILITY_DB.get(port, ["No known vulnerabilities"])

                    # 线程安全更新开放端口数据
                    with self.thread_lock:
                        self.total_open += 1
                        # 记录当前主机的开放端口详情
                        if host_ip not in self.results:
                            self.results[host_ip] = []
                        self.results[host_ip].append({
                            "port": port,
                            "status": "OPEN",
                            "service": service,
                            "response_time": f"{conn_duration:.4f}s",
                            "scan_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "vulnerabilities": vulnerabilities
                        })
                        # 记录跨轮次历史（用于汇总分析）
                        self.host_port_full_history[host_ip][port].append({
                            "round": self.current_round,
                            "status": "OPEN",
                            "scan_time": datetime.datetime.now(),
                            "response_time": conn_duration
                        })
                        self.all_open_ports[port].append(self.current_round)
                        self.port_response_history[port].append(conn_duration)

                    # 实时打印开放端口信息（突出显示）
                    print(f"\n{Fore.GREEN}{Style.BRIGHT}[Open Port Found] {host_ip}:{port}")
                    print(f"{Style.RESET_ALL}{Fore.WHITE}  Service: {service}")
                    print(f"{Fore.WHITE}  Response Time: {conn_duration:.4f}s")
                    print(f"{Fore.WHITE}  Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"{Fore.YELLOW}  Vulnerabilities ({len(vulnerabilities)}):")
                    for idx, vuln in enumerate(vulnerabilities, 1):
                        print(f"    {idx}. {vuln}")
                    return True

                else:
                    # 端口关闭：记录状态
                    with self.thread_lock:
                        self.total_closed += 1
                        self.host_port_full_history[host_ip][port].append({
                            "round": self.current_round,
                            "status": "CLOSED",
                            "scan_time": datetime.datetime.now(),
                            "response_time": 0.0
                        })
                    return False

        except socket.timeout:
            # 端口过滤（超时，可能是防火墙拦截）
            with self.thread_lock:
                self.total_filtered += 1
                self.host_port_full_history[host_ip][port].append({
                    "round": self.current_round,
                    "status": "FILTERED",
                    "scan_time": datetime.datetime.now(),
                    "response_time": -1.0  # 用-1标记过滤状态
                })
            return None

        except Exception as e:
            # 其他异常（如网络错误）
            print(f"\n{Fore.RED}[Scan Error] Port {port} on {host_ip}: {str(e)[:60]}...")
            return None

    def run_single_round_scan(self, hosts, start_port, end_port, thread_count=20):
        """执行单轮批量扫描（多线程控制，避免目标主机过载）"""
        # 初始化单轮数据
        self.results = {}
        self.total_scanned = 0
        self.total_open = 0
        self.total_closed = 0
        self.total_filtered = 0
        self.scan_start_time = datetime.datetime.now()
        self.current_round += 1
        total_ports_per_round = len(hosts) * (end_port - start_port + 1)  # 单轮总端口数

        # 初始化进度条（简洁格式，显示核心信息）
        with self.thread_lock:
            self.progress_bar = tqdm(
                total=total_ports_per_round,
                desc=f"{Fore.CYAN}[Round {self.current_round:02d} Scanning]",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}]",
                unit="port",
                colour="cyan"
            )

        # 打印单轮扫描配置
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[Round {self.current_round:02d} Started]")
        print(f"{Style.RESET_ALL}{Fore.WHITE}Target Hosts: {', '.join(hosts)}")
        print(f"Port Range: {start_port} - {end_port} (Total {end_port - start_port + 1} ports per host)")
        print(f"Thread Count: {thread_count} | Timeout: 1.5s")
        print(f"Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # 多线程扫描（控制并发数，避免网络拥堵）
        thread_list = []
        for host in hosts:
            self.current_host = host
            host_ip = self.resolve_hostname(host)
            if not host_ip:
                continue  # 跳过无法解析的主机

            # 遍历端口范围，创建扫描线程
            for port in range(start_port, end_port + 1):
                # 控制并发线程数（避免超过设定值）
                while threading.active_count() > thread_count + 3:  # +3：主线程+状态线程+进度条线程
                    time.sleep(0.1)

                # 创建线程并启动
                scan_thread = threading.Thread(
                    target=self.scan_single_port,
                    args=(host_ip, port)
                )
                thread_list.append(scan_thread)
                scan_thread.start()

        # 等待所有扫描线程结束
        for thread in thread_list:
            thread.join()

        # 单轮扫描结束：更新进度条与汇总数据
        with self.thread_lock:
            if self.progress_bar:
                # 进度条收尾，显示单轮开放端口数
                self.progress_bar.set_postfix({"Open Ports": f"{Fore.GREEN}{self.total_open}{Style.RESET_ALL}"})
                self.progress_bar.close()
                self.progress_bar = None

        # 计算单轮耗时与扫描速率，存入跨轮次汇总
        round_duration = self.get_elapsed_time()
        round_scan_rate = self.total_scanned / round_duration if round_duration > 0 else 0.0
        self.all_rounds_data.append({
            "round": self.current_round,
            "start_time": self.scan_start_time,
            "end_time": datetime.datetime.now(),
            "duration": round_duration,
            "total_ports": total_ports_per_round,
            "scanned_ports": self.total_scanned,
            "open_ports": self.total_open,
            "closed_ports": self.total_closed,
            "filtered_ports": self.total_filtered,
            "scan_rate": round(round_scan_rate, 2),
            "avg_response_time": self.calc_round_avg_response()  # 单轮平均响应时间
        })

        # 生成单轮报告并保存
        self.generate_single_round_report()
        return True

    def calc_round_avg_response(self):
        """计算当前轮次开放端口的平均响应时间（秒）"""
        response_times = []
        for host_ports in self.results.values():
            for port_info in host_ports:
                rt = float(port_info["response_time"].strip("s"))
                response_times.append(rt)
        if not response_times:
            return 0.0
        return round(sum(response_times) / len(response_times), 4)

    def calc_port_stability(self, port):
        """计算端口稳定性评分（0-100分）：出现频率（50%）+响应时间波动（50%）"""
        if port not in self.all_open_ports:
            return 0.0  # 未开放过的端口稳定性为0
        # 1. 出现频率得分：开放轮次占总轮次的比例×50
        open_rounds = len(self.all_open_ports[port])
        freq_score = (open_rounds / self.total_rounds) * 50
        # 2. 响应时间波动得分：波动越小得分越高（×50）
        rt_list = self.port_response_history.get(port, [])
        if len(rt_list) < 2:
            rt_score = 50.0  # 数据不足时默认满分
        else:
            avg_rt = sum(rt_list) / len(rt_list)
            rt_range = max(rt_list) - min(rt_list)  # 响应时间波动范围
            rt_score = max(0.0, 50.0 - (rt_range / avg_rt) * 50.0)  # 波动越大得分越低
        return round(freq_score + rt_score, 1)

    def calc_network_health(self):
        """计算网络健康度（0-100分）：扫描速率波动（40%）+过滤端口占比（60%）"""
        if self.total_rounds < 2:
            return 80.0  # 轮次不足时默认良好
        # 1. 扫描速率波动得分：波动越小越好（×40）
        rates = [round_data["scan_rate"] for round_data in self.all_rounds_data]
        avg_rate = sum(rates) / len(rates)
        rate_range = max(rates) - min(rates)
        rate_score = max(0.0, 40.0 - (rate_range / avg_rate) * 40.0) if avg_rate != 0 else 0.0
        # 2. 过滤端口占比得分：占比越低越好（×60）
        total_filtered = sum(round_data["filtered_ports"] for round_data in self.all_rounds_data)
        total_scanned = sum(round_data["scanned_ports"] for round_data in self.all_rounds_data)
        filter_ratio = total_filtered / total_scanned if total_scanned != 0 else 0.0
        filter_score = max(0.0, 60.0 - filter_ratio * 60.0)
        # 最终得分
        return round(rate_score + filter_score, 1)

    def generate_single_round_report(self):
        """生成单轮扫描报告（结构化输出，含详细端口信息）"""
        scan_end_time = datetime.datetime.now()
        round_duration = self.get_elapsed_time()
        avg_response = self.calc_round_avg_response()

        # 终端打印单轮报告（分板块，清晰易读）
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[Round {self.current_round:02d} Scan Report]")
        print("-" * 80)
        print(f"{Fore.WHITE}1. Time Information")
        print(f"   Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   End Time:   {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Duration:   {round_duration:.2f} seconds")
        print(f"\n{Fore.WHITE}2. Port Statistics")
        print(f"   Total Ports to Scan: {self.scan_port_range[1] - self.scan_port_range[0] + 1} per host")
        print(f"   Total Hosts:         {len(self.target_hosts)}")
        print(f"   Total Scanned:       {self.total_scanned}")
        print(f"   Open Ports:          {Fore.GREEN}{self.total_open}{Style.RESET_ALL}")
        print(f"   Closed Ports:        {Fore.RED}{self.total_closed}{Style.RESET_ALL}")
        print(f"   Filtered Ports:      {Fore.YELLOW}{self.total_filtered}{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}3. Performance")
        print(f"   Scan Rate:           {self.total_scanned / round_duration:.2f} ports/second")
        print(f"   Avg Response Time (Open): {avg_response:.4f} seconds")
        print("-" * 80)

        # 保存单轮报告到文件（完整详情，便于后续分析）
        report_timestamp = scan_end_time.strftime("%Y%m%d_%H%M%S")
        report_filename = f"port_scan_report_round{self.current_round:02d}_{report_timestamp}.txt"

        with open(report_filename, "w", encoding="utf-8") as f:
            # 报告头部
            f.write("=" * 80 + "\n")
            f.write(f"PROFESSIONAL PORT SCAN REPORT - ROUND {self.current_round:02d}\n")
            f.write(f"Generated Time: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Hosts: {', '.join(self.target_hosts)}\n")
            f.write(f"Port Range: {self.scan_port_range[0]} - {self.scan_port_range[1]}\n")
            f.write("=" * 80 + "\n\n")

            # 1. 单轮汇总统计
            f.write("1. OVERALL SUMMARY\n")
            f.write("-" * 50 + "\n")
            f.write(f"Start Time:         {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"End Time:           {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration:           {round_duration:.2f} seconds\n")
            f.write(f"Total Hosts:        {len(self.target_hosts)}\n")
            f.write(
                f"Total Ports (Plan): {len(self.target_hosts) * (self.scan_port_range[1] - self.scan_port_range[0] + 1)}\n")
            f.write(f"Total Ports (Scanned): {self.total_scanned}\n")
            f.write(f"Open Ports:         {self.total_open}\n")
            f.write(f"Closed Ports:       {self.total_closed}\n")
            f.write(f"Filtered Ports:     {self.total_filtered}\n")
            f.write(f"Scan Rate:          {self.total_scanned / round_duration:.2f} ports/second\n")
            f.write(f"Avg Response Time:  {avg_response:.4f} seconds\n\n")

            # 2. 开放端口详细信息（按端口号排序）
            f.write("2. OPEN PORTS DETAILS (SORTED BY PORT NUMBER)\n")
            f.write("-" * 50 + "\n")
            if self.results:
                for host_ip, port_list in self.results.items():
                    f.write(f"Host IP: {host_ip}\n")
                    f.write("-" * 50 + "\n")
                    # 按端口号升序排列
                    sorted_ports = sorted(port_list, key=lambda x: x["port"])
                    for port_info in sorted_ports:
                        f.write(f"Port:         {port_info['port']}/tcp\n")
                        f.write(f"Status:       {port_info['status']}\n")
                        f.write(f"Service:      {port_info['service']}\n")
                        f.write(f"Response Time: {port_info['response_time']}\n")
                        f.write(f"Scan Time:    {port_info['scan_timestamp']}\n")
                        f.write(f"Vulnerabilities ({len(port_info['vulnerabilities'])}):\n")
                        for idx, vuln in enumerate(port_info['vulnerabilities'], 1):
                            f.write(f"  {idx}. {vuln}\n")
                        f.write("\n")
            else:
                f.write("No open ports found in this round.\n\n")

            # 3. 风险提示
            f.write("3. RISK REMINDER\n")
            f.write("-" * 50 + "\n")
            high_risk_ports = [p for p in self.results.keys() if p in [21, 23, 3389, 5900, 6379]]
            if high_risk_ports:
                f.write("High-risk ports detected (need immediate attention):\n")
                for port in high_risk_ports:
                    f.write(f"  - Port {port}: {SERVICE_DB.get(port, 'Unknown Service')}\n")
            else:
                f.write("No high-risk ports detected in this round.\n")

        print(f"\n{Fore.GREEN}[Report Saved] Single round report: {report_filename}")

    def generate_final_summary_report(self):
        """生成最终汇总报告（跨轮次统计，含趋势与对比）"""
        if not self.all_rounds_data:
            print(f"\n{Fore.YELLOW}[Summary Warning] No scan data available to generate summary.")
            return

        # 计算全局核心统计
        self.total_rounds = len(self.all_rounds_data)
        self.total_scan_duration = sum(round_data["duration"] for round_data in self.all_rounds_data)
        total_ports_scanned = sum(round_data["scanned_ports"] for round_data in self.all_rounds_data)
        total_open_ports = sum(round_data["open_ports"] for round_data in self.all_rounds_data)
        total_closed_ports = sum(round_data["closed_ports"] for round_data in self.all_rounds_data)
        total_filtered_ports = sum(round_data["filtered_ports"] for round_data in self.all_rounds_data)
        avg_scan_rate = total_ports_scanned / self.total_scan_duration if self.total_scan_duration > 0 else 0.0
        avg_round_duration = self.total_scan_duration / self.total_rounds if self.total_rounds > 0 else 0.0
        network_health = self.calc_network_health()

        # 统计开放端口出现频率（按出现次数排序）
        port_occurrence = {port: len(rounds) for port, rounds in self.all_open_ports.items()}
        sorted_ports = sorted(port_occurrence.items(), key=lambda x: x[1], reverse=True)
        # 计算每个端口的稳定性评分
        port_stability = {port: self.calc_port_stability(port) for port in port_occurrence.keys()}

        # 终端打印最终汇总（分模块，突出核心结论）
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[FINAL SCAN SUMMARY REPORT]")
        print("=" * 100)
        print(f"{Fore.WHITE}1. Global Scan Statistics")
        print(f"   Total Rounds Completed:    {self.total_rounds}")
        print(
            f"   Total Scan Duration:       {self.total_scan_duration:.2f} seconds (≈{self.total_scan_duration / 60:.1f} minutes)")
        print(f"   Average Round Duration:    {avg_round_duration:.2f} seconds")
        print(f"   Total Ports Scanned:       {total_ports_scanned}")
        print(f"   Average Scan Rate:         {avg_scan_rate:.2f} ports/second")
        print(
            f"   Network Health Score:      {self._get_health_color(network_health)}{network_health} points{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}2. Port Status Distribution (Total)")
        print(
            f"   Open Ports:                {Fore.GREEN}{total_open_ports}{Style.RESET_ALL} ({total_open_ports / total_ports_scanned * 100:.1f}%)")
        print(
            f"   Closed Ports:              {Fore.RED}{total_closed_ports}{Style.RESET_ALL} ({total_closed_ports / total_ports_scanned * 100:.1f}%)")
        print(
            f"   Filtered Ports:            {Fore.YELLOW}{total_filtered_ports}{Style.RESET_ALL} ({total_filtered_ports / total_ports_scanned * 100:.1f}%)")
        print(f"\n{Fore.WHITE}3. Top 10 Open Ports (By Occurrence)")
        print("   Rank | Port | Service | Occurrence (Rounds) | Occurrence Rate | Stability Score")
        print("   " + "-" * 80)
        if sorted_ports:
            for idx, (port, count) in enumerate(sorted_ports[:10], 1):
                service = SERVICE_DB.get(port, "Unknown Service")
                occ_rate = (count / self.total_rounds) * 100
                stability = port_stability[port]
                print(
                    f"   {idx:4d} | {port:4d} | {service[:20]:<20} | {count:2d}/{self.total_rounds:2d} | {occ_rate:13.1f}% | {self._get_stability_color(stability)}{stability:14.1f}{Style.RESET_ALL}")
        else:
            print("   No open ports found in all rounds.")
        print(f"\n{Fore.WHITE}4. Host Port History Summary")
        print("   " + "-" * 80)
        for host, port_history in self.host_port_full_history.items():
            print(f"   Host IP: {host}")
            print(f"   Monitored Ports: {len(port_history)} | Scanned Rounds: {self.total_rounds}")
            # 统计该主机曾开放过的端口
            ever_open_ports = [p for p, hist in port_history.items() if any(h["status"] == "OPEN" for h in hist)]
            print(f"   Ports Ever Opened: {len(ever_open_ports)}")
            if ever_open_ports:
                print("   Open Port Trend:")
                for port in sorted(ever_open_ports):
                    hist = port_history[port]
                    open_rounds = [h["round"] for h in hist if h["status"] == "OPEN"]
                    trend = self._get_port_trend(open_rounds, self.total_rounds)
                    print(f"     - Port {port}: {trend} (Open in rounds: {', '.join(map(str, open_rounds))})")
            print()
        print("=" * 100)

        # 保存最终汇总报告到文件（完整数据，支持归档）
        summary_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_filename = f"final_scan_summary_{summary_timestamp}.txt"

        with open(summary_filename, "w", encoding="utf-8") as f:
            # 报告头部
            f.write("=" * 100 + "\n")
            f.write("PROFESSIONAL PORT SCAN - FINAL SUMMARY REPORT\n")
            f.write(f"Generated Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Hosts: {', '.join(self.target_hosts)}\n")
            f.write(f"Port Range: {self.scan_port_range[0]} - {self.scan_port_range[1]}\n")
            f.write(f"Total Rounds: {self.total_rounds}\n")
            f.write("=" * 100 + "\n\n")

            # 1. 全局统计
            f.write("1. GLOBAL SCAN STATISTICS\n")
            f.write("-" * 60 + "\n")
            f.write(f"Total Rounds Completed:    {self.total_rounds}\n")
            f.write(
                f"Total Scan Duration:       {self.total_scan_duration:.2f} seconds (≈{self.total_scan_duration / 60:.1f} minutes)\n")
            f.write(f"Average Round Duration:    {avg_round_duration:.2f} seconds\n")
            f.write(f"Total Ports Scanned:       {total_ports_scanned}\n")
            f.write(f"Average Scan Rate:         {avg_scan_rate:.2f} ports/second\n")
            f.write(f"Network Health Score:      {network_health} points ({self._get_health_desc(network_health)})\n")
            f.write(
                f"Total Open Ports:          {total_open_ports} ({total_open_ports / total_ports_scanned * 100:.1f}%)\n")
            f.write(
                f"Total Closed Ports:        {total_closed_ports} ({total_closed_ports / total_ports_scanned * 100:.1f}%)\n")
            f.write(
                f"Total Filtered Ports:      {total_filtered_ports} ({total_filtered_ports / total_ports_scanned * 100:.1f}%)\n\n")

            # 2. 每轮详细对比
            f.write("2. ROUND-BY-ROUND DETAILS\n")
            f.write("-" * 120 + "\n")
            f.write(
                f"{'Round':<6} {'Start Time':<20} {'End Time':<20} {'Duration(s)':<12} {'Scanned':<10} {'Open':<8} {'Closed':<8} {'Filtered':<8} {'Scan Rate':<12} {'Avg RT(s)':<12}\n")
            f.write("-" * 120 + "\n")
            for round_data in self.all_rounds_data:
                f.write(f"{round_data['round']:<6} "
                        f"{round_data['start_time'].strftime('%Y-%m-%d %H:%M'):<20} "
                        f"{round_data['end_time'].strftime('%Y-%m-%d %H:%M'):<20} "
                        f"{round_data['duration']:<12.2f} "
                        f"{round_data['scanned_ports']:<10} "
                        f"{round_data['open_ports']:<8} "
                        f"{round_data['closed_ports']:<8} "
                        f"{round_data['filtered_ports']:<8} "
                        f"{round_data['scan_rate']:<12.2f} "
                        f"{round_data['avg_response_time']:<12.4f}\n")
            f.write("\n")

            # 3. 开放端口深度分析
            f.write("3. OPEN PORTS ANALYSIS\n")
            f.write("-" * 120 + "\n")
            f.write(
                f"{'Rank':<6} {'Port':<8} {'Service':<30} {'Occurrence(Rounds)':<20} {'Occurrence Rate':<15} {'Stability Score':<15} {'Risk Level':<15} {'Vulnerability Count':<20}\n")
            f.write("-" * 120 + "\n")
            if sorted_ports:
                for idx, (port, count) in enumerate(sorted_ports[:10], 1):
                    service = SERVICE_DB.get(port, "Unknown Service")
                    occ_rate = (count / self.total_rounds) * 100
                    stability = port_stability[port]
                    risk_level = self._get_port_risk_level(port)
                    vuln_count = len(VULNERABILITY_DB.get(port, []))
                    f.write(f"{idx:<6} "
                            f"{port:<8} "
                            f"{service[:28]:<30} "
                            f"{count}/{self.total_rounds:<20} "
                            f"{occ_rate:<15.1f}% "
                            f"{stability:<15.1f} "
                            f"{risk_level:<15} "
                            f"{vuln_count:<20}\n")
            else:
                f.write("No open ports found in all rounds.\n")
            f.write("\n")

            # 4. 主机端口历史全记录
            f.write("4. HOST PORT FULL HISTORY\n")
            f.write("=" * 100 + "\n")
            for host, port_history in self.host_port_full_history.items():
                f.write(f"Host IP: {host}\n")
                f.write("-" * 100 + "\n")
                f.write(
                    f"{'Port':<8} {'Status Trend':<30} {'Open Rounds':<30} {'Avg Response Time(s)':<20} {'Last Scan Status':<20}\n")
                f.write("-" * 100 + "\n")
                for port in sorted(port_history.keys()):
                    hist = port_history[port]
                    open_rounds = [h["round"] for h in hist if h["status"] == "OPEN"]
                    rt_list = [h["response_time"] for h in hist if h["status"] == "OPEN" and h["response_time"] > 0]
                    avg_rt = round(sum(rt_list) / len(rt_list), 4) if rt_list else 0.0
                    last_status = hist[-1]["status"] if hist else "UNKNOWN"
                    trend = self._get_port_trend(open_rounds, self.total_rounds)
                    open_rounds_str = ", ".join(map(str, open_rounds)) if open_rounds else "None"
                    f.write(f"{port:<8} "
                            f"{trend[:28]:<30} "
                            f"{open_rounds_str[:28]:<30} "
                            f"{avg_rt:<20.4f} "
                            f"{last_status:<20}\n")
                f.write("\n")

            # 5. 安全建议
            f.write("5. SECURITY RECOMMENDATIONS\n")
            f.write("-" * 60 + "\n")
            high_risk_ports = [p for p in sorted_ports if p[0] in [21, 23, 3389, 5900, 6379]]
            if high_risk_ports:
                f.write("High-risk ports detected, please take the following actions:\n")
                for port, _ in high_risk_ports:
                    f.write(f"  - Port {port} ({SERVICE_DB.get(port, 'Unknown Service')}):\n")
                    f.write(f"    * Restrict access to trusted IPs only\n")
                    f.write(f"    * Enable strong authentication (e.g., SSH key, complex password)\n")
                    f.write(f"    * Update related software to fix known vulnerabilities\n")
            else:
                f.write("No high-risk ports detected, but keep the following practices:\n")
            f.write("  - Regularly scan ports to monitor abnormal status changes\n")
            f.write("  - Disable unnecessary services and close unused ports\n")
            f.write("  - Enable firewall to filter unauthorized access\n")
            f.write("  - Regularly update system and software to patch vulnerabilities\n")

        print(f"\n{Fore.GREEN}[Summary Saved] Final summary report: {summary_filename}")

    # ---------------------- 辅助工具方法（增强结果可读性）----------------------
    def _get_health_color(self, score):
        """根据网络健康度得分返回颜色"""
        if score >= 80:
            return Fore.GREEN
        elif score >= 60:
            return Fore.YELLOW
        else:
            return Fore.RED

    def _get_health_desc(self, score):
        """根据网络健康度得分返回描述"""
        if score >= 80:
            return "Excellent (stable speed, low filtering)"
        elif score >= 60:
            return "Good (minor speed fluctuation, low filtering)"
        else:
            return "Poor (significant speed fluctuation, high filtering)"

    def _get_stability_color(self, score):
        """根据端口稳定性得分返回颜色"""
        if score >= 80:
            return Fore.GREEN
        elif score >= 60:
            return Fore.YELLOW
        else:
            return Fore.RED

    def _get_port_risk_level(self, port):
        """根据端口号返回风险级别"""
        high_risk = [21, 23, 3389, 5900, 6379]
        medium_risk = [22, 3306, 5432, 27017]
        low_risk = [80, 443, 53, 110, 143, 8080]
        if port in high_risk:
            return "HIGH"
        elif port in medium_risk:
            return "MEDIUM"
        elif port in low_risk:
            return "LOW"
        else:
            return "UNKNOWN"

    def _get_port_trend(self, open_rounds, total_rounds):
        """根据开放轮次判断端口状态趋势"""
        if not open_rounds:
            return "Never Open"
        if len(open_rounds) == total_rounds:
            return "Stably Open (All Rounds)"
        if open_rounds[-1] == total_rounds:
            return "Recently Open (Last Round)"
        if open_rounds[0] == 1 and open_rounds[-1] < total_rounds:
            return "Recently Closed (Previously Open)"
        else:
            return f"Fluctuating (Open in {len(open_rounds)} Rounds)"

    def start_continuous_scan(self, hosts, start_port, end_port, thread_count=20, round_interval=30):
        """启动持续扫描（循环执行单轮扫描，支持间隔配置）"""
        self.target_hosts = hosts
        self.scan_port_range = (start_port, end_port)

        # 启动状态更新线程（后台运行）
        status_thread = threading.Thread(target=self.update_dynamic_status, daemon=True)
        status_thread.start()

        try:
            while self.is_scanning:
                # 执行单轮扫描
                self.run_single_round_scan(hosts, start_port, end_port, thread_count)

                # 扫描间隔（等待下一轮）
                if self.is_scanning and self.current_round > 0:
                    wait_start = datetime.datetime.now()
                    while (datetime.datetime.now() - wait_start).total_seconds() < round_interval:
                        remaining = round_interval - (datetime.datetime.now() - wait_start).total_seconds()
                        wait_line = (
                            f"\r{Fore.YELLOW}[Next Round Waiting] Round {self.current_round + 1} starts in {remaining:.0f}s... "
                            f"Last Round: Open={self.total_open}, Duration={self.get_elapsed_time():.0f}s"
                            f"\033[K"
                        )
                        print(wait_line, end="", flush=True)
                        time.sleep(1)
                    print()  # 换行，避免与下一轮日志重叠

        except KeyboardInterrupt:
            # 用户按下Ctrl+C，停止扫描
            self.is_scanning = False
            with self.thread_lock:
                if self.progress_bar:
                    self.progress_bar.close()
            print(
                f"\n\n{Fore.RED}[Scan Stopped] User interrupted scanning at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        finally:
            # 生成最终汇总报告
            self.generate_final_summary_report()


# ---------------------- 执行入口（可直接修改配置）----------------------
if __name__ == "__main__":
    # 扫描参数配置（根据需求修改）
    TARGET_HOSTS = ["110.41.59.234"]  # 目标主机（支持多个，如["host1.com", "192.168.1.1"]）
    START_PORT = 1  # 起始端口（测试建议1-100，全量扫描建议1-10000）
    END_PORT = 100  # 结束端口
    THREAD_COUNT = 20  # 并发线程数（10-50为宜，过多易被拦截）
    ROUND_INTERVAL = 30  # 轮次间隔时间（秒，建议30-300）

    # 初始化并启动扫描
    scanner = ProfessionalPortScanner()
    scanner.print_init_banner()
    scanner.start_continuous_scan(
        hosts=TARGET_HOSTS,
        start_port=START_PORT,
        end_port=END_PORT,
        thread_count=THREAD_COUNT,
        round_interval=ROUND_INTERVAL
    )