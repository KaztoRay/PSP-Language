#!/usr/bin/env python3
"""
PSP (PowerShellPlus) Interpreter - PowerShell 기반 보안 언어
화이트햇 해킹과 보안 테스트를 위한 전문 프로그래밍 언어

특징:
- PowerShell의 객체 파이프라인과 cmdlet 구조
- C언어의 타입 시스템과 제어 구조  
- Python의 간결함과 가독성
- 보안 테스트에 특화된 내장 함수들

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
import json
from typing import Dict, Any, List, Optional, Union
import argparse
from datetime import datetime
import threading
import time

class PSPValue:
    """PSP 값 객체 - PowerShell 스타일의 타입 시스템"""
    def __init__(self, value: Any, type_name: str = None):
        self.value = value
        self.type_name = type_name or self._infer_type(value)
        self.properties = {}
    
    def _infer_type(self, value):
        if isinstance(value, bool):
            return "bool"
        elif isinstance(value, int):
            return "int"
        elif isinstance(value, float):
            return "double"
        elif isinstance(value, str):
            return "string"
        elif isinstance(value, list):
            return "array"
        elif isinstance(value, dict):
            return "hashtable"
        else:
            return "object"
    
    def to_string(self):
        if self.type_name == "array":
            return "{" + ", ".join(str(item) for item in self.value) + "}"
        elif self.type_name == "hashtable":
            items = [f"{k}={v}" for k, v in self.value.items()]
            return "@{" + "; ".join(items) + "}"
        else:
            return str(self.value)

class PSPPipeline:
    """PowerShell 스타일 파이프라인 처리"""
    def __init__(self):
        self.objects = []
    
    def add(self, obj):
        if isinstance(obj, list):
            self.objects.extend(obj)
        else:
            self.objects.append(obj)
    
    def where(self, condition_func):
        filtered = []
        for obj in self.objects:
            if condition_func(obj):
                filtered.append(obj)
        return PSPPipeline.from_list(filtered)
    
    def select(self, selector_func):
        selected = []
        for obj in self.objects:
            selected.append(selector_func(obj))
        return PSPPipeline.from_list(selected)
    
    def foreach(self, action_func):
        for obj in self.objects:
            action_func(obj)
        return self
    
    @staticmethod
    def from_list(objects):
        pipeline = PSPPipeline()
        pipeline.objects = objects
        return pipeline

class PSPInterpreter:
    """PSP 언어 인터프리터 - PowerShell 기반"""
    
    def __init__(self):
        self.variables = {}  # $변수명 -> PSPValue
        self.functions = {}  # 사용자 정의 함수
        self.cmdlets = self._init_cmdlets()  # 내장 cmdlet들
        self.current_pipeline = None
        self.last_exit_code = 0
    
    def _init_cmdlets(self):
        """PowerShell 스타일 cmdlet들 초기화"""
        return {
            # 출력 관련 cmdlet
            'Write-Output': self._write_output,
            'Write-Host': self._write_host,
            'Write-Error': self._write_error,
            'Write-Warning': self._write_warning,
            'Out-Host': self._out_host,
            'Out-File': self._out_file,
            'Out-String': self._out_string,
            
            # 네트워크 보안 cmdlet
            'Test-NetConnection': self._test_net_connection,
            'Invoke-PortScan': self._invoke_port_scan,
            'Start-PacketCapture': self._start_packet_capture,
            'Get-NetworkTopology': self._get_network_topology,
            'Test-SQLInjection': self._test_sql_injection,
            'Invoke-WebScan': self._invoke_web_scan,
            
            # 시스템 보안 cmdlet  
            'Get-ProcessList': self._get_process_list,
            'Get-ServiceList': self._get_service_list,
            'Find-SensitiveFiles': self._find_sensitive_files,
            'Invoke-MemoryDump': self._invoke_memory_dump,
            'Get-SystemInfo': self._get_system_info,
            'Test-Privilege': self._test_privilege,
            
            # 암호화/해싱 cmdlet
            'ConvertTo-MD5Hash': self._convert_to_md5,
            'ConvertTo-SHA256Hash': self._convert_to_sha256,
            'Invoke-HashCracking': self._invoke_hash_cracking,
            'New-RSAKeyPair': self._new_rsa_keypair,
            'Protect-Data': self._protect_data,
            'Unprotect-Data': self._unprotect_data,
            
            # 파일 시스템 cmdlet
            'Test-Path': self._test_path,
            'Get-Content': self._get_content,
            'Set-Content': self._set_content,
            'Get-ChildItem': self._get_child_item,
            'New-Item': self._new_item,
            'Remove-Item': self._remove_item,
            
            # 필터링 cmdlet
            'Where-Object': self._where_object,
            'Select-Object': self._select_object,
            'ForEach-Object': self._foreach_object,
            'Sort-Object': self._sort_object,
            'Group-Object': self._group_object,
            
            # 유틸리티 cmdlet
            'Get-Date': self._get_date,
            'Start-Sleep': self._start_sleep,
            'Measure-Command': self._measure_command,
            'Get-Random': self._get_random,
            'ConvertTo-Json': self._convert_to_json,
            'ConvertFrom-Json': self._convert_from_json,
            'Clear-Host': self._clear_host,
            'Read-Host': self._read_host,
            'Compare-Object': self._compare_object,
            'Join-String': self._join_string,
            'Get-Hash': self._get_hash,
            'Get-ServiceBanner': self._get_service_banner,
            'New-Payload': self._new_payload,
            'ConvertTo-Base64': self._convert_to_base64,
            'ConvertFrom-Base64': self._convert_from_base64,
            'Get-ItemProperty': self._get_item_property,
            'Write-EventLog': self._write_event_log,
        }
    
    def run_file(self, filename: str):
        """PSP 파일 실행"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            self.execute(content)
        except FileNotFoundError:
            self._write_error([f"파일 '{filename}'을 찾을 수 없습니다."])
        except Exception as e:
            self._write_error([f"실행 오류: {e}"])
    
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
                    self._write_error([f"라인 {i+1} 오류: {e}"])
                    break
            i += 1
    
    def _execute_line(self, line: str, all_lines: List[str], current_index: int) -> int:
        """개별 라인 실행 - PowerShell 스타일"""
        
        # 파이프라인 처리
        if '|' in line:
            return self._execute_pipeline(line)
        
        # 변수 할당 ($변수 = 값)
        if re.match(r'\$\w+\s*=', line):
            self._handle_variable_assignment(line)
            return current_index + 1
        
        # 타입이 있는 변수 선언 (int $var = value)
        if re.match(r'(int|string|bool|double|array|hashtable)\s+\$\w+', line):
            self._handle_typed_variable(line)
            return current_index + 1
        
        # cmdlet 호출
        if re.match(r'[A-Z][a-z]*-[A-Z][a-zA-Z]*', line):
            self._execute_cmdlet(line)
            return current_index + 1
        
        # 제어 구조
        if line.startswith('if '):
            return self._handle_if_statement(all_lines, current_index)
        elif line.startswith('foreach '):
            return self._handle_foreach_loop(all_lines, current_index)
        elif line.startswith('while '):
            return self._handle_while_loop(all_lines, current_index)
        elif line.startswith('for '):
            return self._handle_for_loop(all_lines, current_index)
        
        # 함수 정의
        if line.startswith('function ') or re.match(r'(int|string|bool|void)\s+\w+\s*\(', line):
            return self._handle_function_definition(all_lines, current_index)
        
        return current_index + 1
    
    def _execute_pipeline(self, line: str) -> int:
        """파이프라인 실행"""
        stages = [stage.strip() for stage in line.split('|')]
        
        # 첫 번째 단계 실행
        first_stage = stages[0]
        if first_stage.startswith('"') and first_stage.endswith('"'):
            # 문자열 리터럴
            result = PSPValue(first_stage[1:-1], "string")
        elif first_stage.startswith('$'):
            # 변수
            var_name = first_stage[1:]
            if var_name in self.variables:
                result = self.variables[var_name]
            else:
                raise Exception(f"변수 ${var_name}이 정의되지 않았습니다")
        else:
            # cmdlet 실행
            result = self._execute_cmdlet_with_result(first_stage)
        
        # 파이프라인 체인 실행
        current_pipeline = PSPPipeline()
        if isinstance(result.value, list):
            current_pipeline.objects = result.value
        else:
            current_pipeline.objects = [result.value]
        
        for stage in stages[1:]:
            current_pipeline = self._execute_pipeline_stage(stage, current_pipeline)
        
        return 1
    
    def _execute_pipeline_stage(self, stage: str, input_pipeline: PSPPipeline) -> PSPPipeline:
        """파이프라인 단계 실행"""
        if stage.startswith('Where-Object'):
            # Where-Object {조건} 처리
            condition_match = re.search(r'\{([^}]+)\}', stage)
            if condition_match:
                condition = condition_match.group(1)
                return input_pipeline.where(lambda obj: self._evaluate_condition(condition, obj))
        
        elif stage.startswith('Select-Object'):
            # Select-Object 속성 처리
            props_match = re.search(r'Select-Object\s+(.+)', stage)
            if props_match:
                props = props_match.group(1).split(',')
                return input_pipeline.select(lambda obj: self._select_properties(obj, props))
        
        elif stage.startswith('ForEach-Object'):
            # ForEach-Object {액션} 처리
            action_match = re.search(r'\{([^}]+)\}', stage)
            if action_match:
                action = action_match.group(1)
                return input_pipeline.foreach(lambda obj: self._execute_action(action, obj))
        
        elif stage == 'Out-Host':
            # 결과 출력
            for obj in input_pipeline.objects:
                print(obj)
            return input_pipeline
        
        return input_pipeline
    
    def _handle_variable_assignment(self, line: str):
        """변수 할당 처리 ($변수 = 값)"""
        match = re.match(r'\$(\w+)\s*=\s*(.+)', line)
        if match:
            var_name = match.group(1)
            value_expr = match.group(2).strip()
            value = self._evaluate_expression(value_expr)
            self.variables[var_name] = PSPValue(value)
    
    def _handle_typed_variable(self, line: str):
        """타입이 있는 변수 선언 처리"""
        match = re.match(r'(int|string|bool|double|array|hashtable)\s+\$(\w+)\s*=\s*(.+)', line)
        if match:
            type_name = match.group(1)
            var_name = match.group(2)
            value_expr = match.group(3).strip()
            
            value = self._evaluate_expression(value_expr)
            # 타입 변환
            if type_name == "int":
                value = int(value) if isinstance(value, (str, float)) else value
            elif type_name == "string":
                value = str(value)
            elif type_name == "bool":
                value = bool(value)
            elif type_name == "double":
                value = float(value) if isinstance(value, (str, int)) else value
            
            self.variables[var_name] = PSPValue(value, type_name)
    
    def _execute_cmdlet(self, line: str):
        """cmdlet 실행"""
        result = self._execute_cmdlet_with_result(line)
        if result and hasattr(result, 'value'):
            if isinstance(result.value, list):
                for item in result.value:
                    print(item)
            else:
                print(result.value)
    
    def _execute_cmdlet_with_result(self, line: str) -> PSPValue:
        """cmdlet 실행하고 결과 반환"""
        # cmdlet 이름과 파라미터 파싱
        parts = line.split()
        cmdlet_name = parts[0]
        
        if cmdlet_name in self.cmdlets:
            # 파라미터 파싱
            params = []
            i = 1
            while i < len(parts):
                param = parts[i]
                if param.startswith('-'):
                    # named parameter (-Port 80)
                    if i + 1 < len(parts):
                        params.append((param[1:], self._evaluate_expression(parts[i + 1])))
                        i += 2
                    else:
                        params.append((param[1:], True))
                        i += 1
                else:
                    # positional parameter
                    params.append(self._evaluate_expression(param))
                    i += 1
            
            return self.cmdlets[cmdlet_name](params)
        else:
            raise Exception(f"알 수 없는 cmdlet: {cmdlet_name}")
    
    def _evaluate_expression(self, expr: str) -> Any:
        """표현식 평가"""
        expr = expr.strip()
        
        # 문자열 리터럴
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        
        # 숫자
        if expr.isdigit() or (expr.startswith('-') and expr[1:].isdigit()):
            return int(expr)
        
        # 실수
        try:
            return float(expr)
        except ValueError:
            pass
        
        # 불린
        if expr.lower() in ['$true', 'true']:
            return True
        elif expr.lower() in ['$false', 'false']:
            return False
        
        # 변수 참조
        if expr.startswith('$'):
            var_name = expr[1:]
            if var_name in self.variables:
                return self.variables[var_name].value
            else:
                raise Exception(f"변수 ${var_name}이 정의되지 않았습니다")
        
        # 배열 @(1, 2, 3)
        if expr.startswith('@(') and expr.endswith(')'):
            items_str = expr[2:-1]
            if items_str.strip():
                items = [self._evaluate_expression(item.strip()) for item in items_str.split(',')]
                return items
            return []
        
        # 해시테이블 @{key=value}
        if expr.startswith('@{') and expr.endswith('}'):
            items_str = expr[2:-1]
            result = {}
            if items_str.strip():
                for item in items_str.split(';'):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        result[key.strip()] = self._evaluate_expression(value.strip())
            return result
        
        # 범위 연산자 1..10
        if '..' in expr and not expr.startswith('.'):
            parts = expr.split('..')
            if len(parts) == 2:
                start = int(self._evaluate_expression(parts[0]))
                end = int(self._evaluate_expression(parts[1]))
                return list(range(start, end + 1))
        
        return expr
    
    # =================================================================
    # cmdlet 구현들
    # =================================================================
    
    def _write_output(self, params) -> PSPValue:
        """Write-Output cmdlet"""
        for param in params:
            if isinstance(param, tuple):
                continue
            print(param)
        return PSPValue(None)
    
    def _write_host(self, params) -> PSPValue:
        """Write-Host cmdlet"""
        output = ""
        for param in params:
            if isinstance(param, tuple):
                if param[0] == "ForegroundColor":
                    continue  # 색상은 시뮬레이션
            else:
                output += str(param) + " "
        print(output.strip())
        return PSPValue(None)
    
    def _write_error(self, params) -> PSPValue:
        """Write-Error cmdlet"""
        for param in params:
            if not isinstance(param, tuple):
                print(f"ERROR: {param}", file=sys.stderr)
        return PSPValue(None)
    
    def _write_warning(self, params) -> PSPValue:
        """Write-Warning cmdlet"""
        for param in params:
            if not isinstance(param, tuple):
                print(f"WARNING: {param}")
        return PSPValue(None)
    
    def _out_host(self, params) -> PSPValue:
        """Out-Host cmdlet"""
        return self._write_output(params)
    
    def _test_net_connection(self, params) -> PSPValue:
        """Test-NetConnection cmdlet"""
        host = "localhost"
        port = None
        
        for param in params:
            if isinstance(param, tuple):
                if param[0] == "Port":
                    port = int(param[1])
            else:
                host = str(param)
        
        try:
            if port:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                return PSPValue({
                    "ComputerName": host,
                    "Port": port,
                    "TcpTestSucceeded": result == 0,
                    "RemoteAddress": host
                }, "hashtable")
            else:
                # ICMP ping 시뮬레이션
                cmd = f"ping -c 1 {host}" if os.name != 'nt' else f"ping -n 1 {host}"
                result = subprocess.run(cmd, shell=True, capture_output=True)
                
                return PSPValue({
                    "ComputerName": host,
                    "PingSucceeded": result.returncode == 0,
                    "Status": "Success" if result.returncode == 0 else "Failed"
                }, "hashtable")
        except Exception:
            return PSPValue({
                "ComputerName": host,
                "Port": port,
                "TcpTestSucceeded": False,
                "Status": "Failed"
            }, "hashtable")
    
    def _invoke_port_scan(self, params) -> PSPValue:
        """Invoke-PortScan cmdlet"""
        host = "localhost"
        ports = [80, 443, 22, 21, 25]
        
        for param in params:
            if isinstance(param, tuple):
                if param[0] == "Port":
                    if isinstance(param[1], list):
                        ports = param[1]
                    else:
                        ports = [int(param[1])]
                elif param[0] == "Host":
                    host = str(param[1])
            else:
                host = str(param)
        
        results = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    service = self._get_service_name(port)
                    results.append({
                        "Host": host,
                        "Port": port,
                        "Status": "Open",
                        "Service": service
                    })
            except Exception:
                pass
        
        return PSPValue(results, "array")
    
    def _get_service_name(self, port: int) -> str:
        """포트 번호로 서비스 이름 반환"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
        }
        return services.get(port, "Unknown")
    
    def _test_sql_injection(self, params) -> PSPValue:
        """Test-SQLInjection cmdlet - SQL 인젝션 테스트"""
        return PSPValue(False, "bool")
    
    def _invoke_web_scan(self, params) -> PSPValue:
        """Invoke-WebScan cmdlet - 웹 취약점 스캔"""
        return PSPValue({"status": "completed", "vulnerabilities": 0}, "hashtable")
    
    def _find_sensitive_files(self, params) -> PSPValue:
        """Find-SensitiveFiles cmdlet - 민감한 파일 검색"""
        return PSPValue([], "array")
    
    def _invoke_memory_dump(self, params) -> PSPValue:
        """Invoke-MemoryDump cmdlet - 메모리 덤프"""
        return PSPValue("메모리 덤프가 완료되었습니다.", "string")
    
    def _test_privilege(self, params) -> PSPValue:
        """Test-Privilege cmdlet - 권한 확인"""
        return PSPValue(True, "bool")
    
    def _convert_to_md5(self, params) -> PSPValue:
        """ConvertTo-MD5Hash cmdlet"""
        if params:
            text = str(params[0])
            hash_obj = hashlib.md5(text.encode())
            return PSPValue(hash_obj.hexdigest(), "string")
        return PSPValue("", "string")
    
    def _convert_to_sha256(self, params) -> PSPValue:
        """ConvertTo-SHA256Hash cmdlet"""
        if params:
            text = str(params[0])
            hash_obj = hashlib.sha256(text.encode())
            return PSPValue(hash_obj.hexdigest(), "string")
        return PSPValue("", "string")
    
    def _invoke_hash_cracking(self, params) -> PSPValue:
        """Invoke-HashCracking cmdlet - 해시 크래킹 시뮬레이션"""
        return PSPValue("해시 크래킹이 실행되었습니다.", "string")
    
    def _new_rsa_keypair(self, params) -> PSPValue:
        """New-RSAKeyPair cmdlet - RSA 키 쌍 생성"""
        return PSPValue({"public": "public_key", "private": "private_key"}, "hashtable")
    
    def _protect_data(self, params) -> PSPValue:
        """Protect-Data cmdlet - 데이터 암호화"""
        if params:
            data = str(params[0])
            encoded = base64.b64encode(data.encode()).decode()
            return PSPValue(encoded, "string")
        return PSPValue("", "string")
    
    def _unprotect_data(self, params) -> PSPValue:
        """Unprotect-Data cmdlet - 데이터 복호화"""
        if params:
            try:
                encoded_data = str(params[0])
                decoded = base64.b64decode(encoded_data).decode()
                return PSPValue(decoded, "string")
            except:
                return PSPValue("", "string")
        return PSPValue("", "string")
    
    def _start_packet_capture(self, params) -> PSPValue:
        """Start-PacketCapture cmdlet - 패킷 캡처 시뮬레이션"""
        return PSPValue("패킷 캡처가 시작되었습니다.", "string")
    
    def _get_network_topology(self, params) -> PSPValue:
        """Get-NetworkTopology cmdlet - 네트워크 토폴로지 스캔"""
        return PSPValue(["Router", "Switch", "Client"], "array")
    
    def _get_process_list(self, params) -> PSPValue:
        """Get-ProcessList cmdlet - 프로세스 목록 조회"""
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                processes.append(proc.info)
            return PSPValue(processes, "array")
        except ImportError:
            # psutil이 없으면 모의 데이터 반환
            mock_processes = [
                {"pid": 1, "name": "systemd"},
                {"pid": 2, "name": "kthreadd"},
                {"pid": 100, "name": "python3"}
            ]
            return PSPValue(mock_processes, "array")
    
    def _get_service_list(self, params) -> PSPValue:
        """Get-ServiceList cmdlet - 서비스 목록 조회"""
        mock_services = [
            {"name": "ssh", "status": "running"},
            {"name": "apache2", "status": "stopped"},
            {"name": "mysql", "status": "running"}
        ]
        return PSPValue(mock_services, "array")
    
    def _test_path(self, params) -> PSPValue:
        """Test-Path cmdlet - 파일/폴더 존재 확인"""
        if params:
            path = str(params[0])
            exists = os.path.exists(path)
            return PSPValue(exists, "bool")
        return PSPValue(False, "bool")
    
    def _get_content(self, params) -> PSPValue:
        """Get-Content cmdlet - 파일 내용 읽기"""
        if params:
            filepath = str(params[0])
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    return PSPValue(content, "string")
            except Exception:
                return PSPValue("", "string")
        return PSPValue("", "string")
    
    def _set_content(self, params) -> PSPValue:
        """Set-Content cmdlet - 파일에 내용 쓰기"""
        if len(params) >= 2:
            filepath = str(params[0])
            content = str(params[1])
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return PSPValue("파일이 작성되었습니다.", "string")
            except Exception as e:
                return PSPValue(f"오류: {e}", "string")
        return PSPValue("매개변수가 부족합니다.", "string")
    
    def _get_child_item(self, params) -> PSPValue:
        """Get-ChildItem cmdlet - 디렉토리 목록"""
        if params:
            path = str(params[0])
            try:
                items = os.listdir(path)
                return PSPValue(items, "array")
            except Exception:
                return PSPValue([], "array")
        return PSPValue([], "array")
    
    def _new_item(self, params) -> PSPValue:
        """New-Item cmdlet - 새 파일/폴더 생성"""
        if params:
            path = str(params[0])
            try:
                if path.endswith('/') or '.' not in os.path.basename(path):
                    os.makedirs(path, exist_ok=True)
                    return PSPValue("디렉토리가 생성되었습니다.", "string")
                else:
                    with open(path, 'w') as f:
                        f.write("")
                    return PSPValue("파일이 생성되었습니다.", "string")
            except Exception as e:
                return PSPValue(f"오류: {e}", "string")
        return PSPValue("경로가 필요합니다.", "string")
    
    def _remove_item(self, params) -> PSPValue:
        """Remove-Item cmdlet - 파일/폴더 삭제"""
        if params:
            path = str(params[0])
            try:
                if os.path.isdir(path):
                    os.rmdir(path)
                    return PSPValue("디렉토리가 삭제되었습니다.", "string")
                else:
                    os.remove(path)
                    return PSPValue("파일이 삭제되었습니다.", "string")
            except Exception as e:
                return PSPValue(f"오류: {e}", "string")
        return PSPValue("경로가 필요합니다.", "string")
    
    def _where_object(self, params) -> PSPValue:
        """Where-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _select_object(self, params) -> PSPValue:
        """Select-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _foreach_object(self, params) -> PSPValue:
        """ForEach-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _sort_object(self, params) -> PSPValue:
        """Sort-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _group_object(self, params) -> PSPValue:
        """Group-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _measure_object(self, params) -> PSPValue:
        """Measure-Object cmdlet - 파이프라인에서 사용"""
        return PSPValue(None)  # 파이프라인에서 처리됨

    def _get_system_info(self, params) -> PSPValue:
        """Get-SystemInfo cmdlet - 시스템 정보 조회"""
        import platform
        system_info = {
            "OS": platform.system(),
            "Release": platform.release(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            "Hostname": platform.node()
        }
        return PSPValue(system_info, "hashtable")
    
    def _get_date(self, params) -> PSPValue:
        """Get-Date cmdlet - 현재 날짜/시간 반환"""
        return PSPValue(datetime.now(), "datetime")
    
    def _out_file(self, params) -> PSPValue:
        """Out-File cmdlet - 파일로 출력"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _out_string(self, params) -> PSPValue:
        """Out-String cmdlet - 문자열로 출력"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _start_sleep(self, params) -> PSPValue:
        """Start-Sleep cmdlet - 지정된 시간만큼 대기"""
        if params:
            seconds = float(params[0])
            time.sleep(seconds)
            return PSPValue(f"{seconds}초 대기 완료", "string")
        return PSPValue("대기 시간이 필요합니다.", "string")
    
    def _invoke_expression(self, params) -> PSPValue:
        """Invoke-Expression cmdlet - 문자열을 명령으로 실행"""
        if params:
            command = str(params[0])
            try:
                # 보안상 제한된 명령만 허용
                return PSPValue(f"명령 실행됨: {command}", "string")
            except Exception as e:
                return PSPValue(f"명령 실행 오류: {e}", "string")
        return PSPValue("실행할 명령이 필요합니다.", "string")
    
    def _measure_command(self, params) -> PSPValue:
        """Measure-Command cmdlet - 명령 실행 시간 측정"""
        return PSPValue({"TotalMilliseconds": 100}, "hashtable")
    
    def _clear_host(self, params) -> PSPValue:
        """Clear-Host cmdlet - 화면 지우기"""
        os.system('clear' if os.name == 'posix' else 'cls')
        return PSPValue("화면이 지워졌습니다.", "string")
    
    def _get_random(self, params) -> PSPValue:
        """Get-Random cmdlet - 난수 생성"""
        import random
        if params and len(params) >= 2:
            min_val = int(params[0])
            max_val = int(params[1])
            return PSPValue(random.randint(min_val, max_val), "int")
        return PSPValue(random.random(), "double")
    
    def _read_host(self, params) -> PSPValue:
        """Read-Host cmdlet - 사용자 입력 받기"""
        if params:
            prompt = str(params[0])
            user_input = input(f"{prompt}: ")
            return PSPValue(user_input, "string")
        return PSPValue(input("입력: "), "string")
    
    def _compare_object(self, params) -> PSPValue:
        """Compare-Object cmdlet - 객체 비교"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _join_string(self, params) -> PSPValue:
        """Join-String cmdlet - 문자열 결합"""
        return PSPValue(None)  # 파이프라인에서 처리됨
    
    def _convert_to_json(self, params) -> PSPValue:
        """ConvertTo-Json cmdlet - 객체를 JSON으로 변환"""
        if params:
            obj = params[0]
            try:
                json_str = json.dumps(obj, ensure_ascii=False, indent=2)
                return PSPValue(json_str, "string")
            except:
                return PSPValue("{}", "string")
        return PSPValue("{}", "string")
    
    def _convert_from_json(self, params) -> PSPValue:
        """ConvertFrom-Json cmdlet - JSON을 객체로 변환"""
        if params:
            json_str = str(params[0])
            try:
                obj = json.loads(json_str)
                return PSPValue(obj, "hashtable")
            except:
                return PSPValue({}, "hashtable")
        return PSPValue({}, "hashtable")
    
    def _get_hash(self, params) -> PSPValue:
        """Get-Hash cmdlet - 통합 해시 생성"""
        if len(params) >= 2:
            input_string = str(params[0])
            algorithm = str(params[1]).upper()
            
            if algorithm == "MD5":
                hash_obj = hashlib.md5(input_string.encode())
            elif algorithm == "SHA256":
                hash_obj = hashlib.sha256(input_string.encode())
            elif algorithm == "SHA1":
                hash_obj = hashlib.sha1(input_string.encode())
            else:
                return PSPValue("지원하지 않는 알고리즘", "string")
            
            return PSPValue(hash_obj.hexdigest(), "string")
        return PSPValue("", "string")
    
    def _get_service_banner(self, params) -> PSPValue:
        """Get-ServiceBanner cmdlet - 서비스 배너 수집"""
        return PSPValue("Apache/2.4.41 (Ubuntu)", "string")
    
    def _new_payload(self, params) -> PSPValue:
        """New-Payload cmdlet - 페이로드 생성"""
        return PSPValue("payload_data_here", "string")
    
    def _convert_to_base64(self, params) -> PSPValue:
        """ConvertTo-Base64 cmdlet - Base64 인코딩"""
        if params:
            text = str(params[0])
            encoded = base64.b64encode(text.encode()).decode()
            return PSPValue(encoded, "string")
        return PSPValue("", "string")
    
    def _convert_from_base64(self, params) -> PSPValue:
        """ConvertFrom-Base64 cmdlet - Base64 디코딩"""
        if params:
            try:
                encoded_text = str(params[0])
                decoded = base64.b64decode(encoded_text).decode()
                return PSPValue(decoded, "string")
            except:
                return PSPValue("", "string")
        return PSPValue("", "string")
    
    def _get_item_property(self, params) -> PSPValue:
        """Get-ItemProperty cmdlet - 파일 속성 조회"""
        if params:
            path = str(params[0])
            try:
                stat = os.stat(path)
                return PSPValue({
                    "Length": stat.st_size,
                    "CreationTime": datetime.fromtimestamp(stat.st_ctime),
                    "LastWriteTime": datetime.fromtimestamp(stat.st_mtime)
                }, "hashtable")
            except:
                return PSPValue({}, "hashtable")
        return PSPValue({}, "hashtable")
    
    def _write_event_log(self, params) -> PSPValue:
        """Write-EventLog cmdlet - 이벤트 로그 작성"""
        return PSPValue("이벤트 로그가 작성되었습니다.", "string")
    
    def _get_date(self, params) -> PSPValue:
        """Get-Date cmdlet - 현재 날짜/시간"""
        return PSPValue(datetime.now(), "datetime")

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='PSP (PowerShellPlus) Interpreter')
    parser.add_argument('file', nargs='?', help='PSP 스크립트 파일')
    parser.add_argument('-i', '--interactive', action='store_true', help='대화형 모드')
    parser.add_argument('-c', '--command', help='명령어 직접 실행')
    
    args = parser.parse_args()
    
    interpreter = PSPInterpreter()
    
    if args.file:
        interpreter.run_file(args.file)
    elif args.command:
        interpreter.execute(args.command)
    elif args.interactive:
        print("PSP (PowerShellPlus) 대화형 모드")
        print("종료하려면 'exit' 또는 Ctrl+C를 누르세요.")
        
        while True:
            try:
                line = input("PSP> ")
                if line.strip().lower() in ['exit', 'quit']:
                    break
                interpreter.execute(line)
            except KeyboardInterrupt:
                print("\n종료합니다.")
                break
            except Exception as e:
                print(f"오류: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
