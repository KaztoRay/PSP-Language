# PSP (PowerShellPlus) 완전 문법 가이드

## 1. 기본 구조

### 1.1 Hello World
```psp
# hello_world.pspp
print("Hello, World!")
print("안녕하세요, PSP 세계!")
```

### 1.2 주석 (Comments)
```psp
# 한줄 주석

/* 
   여러줄 주석
   블록 주석
*/

/* 
 * 문서화 주석
 * @author: PSP Developer
 * @version: 1.0
 */
```

### 1.3 파일 구조
```psp
#!/usr/bin/env psp
# -*- coding: utf-8 -*-

/**
 * 파일 설명: 네트워크 스캔 도구
 * 작성자: 화이트해커
 * 날짜: 2024-10-25
 */

# 모듈 임포트
import "network_utils"
import "crypto_tools" as crypto

# 전역 변수
global target_ip = "192.168.1.1"
global scan_timeout = 5

# 메인 함수
function main() {
    print("PSP 프로그램 시작")
    // 프로그램 로직
}

# 프로그램 시작점
if __name__ == "__main__" {
    main()
}
```

## 2. 데이터 타입 (Data Types)

### 2.1 기본 타입
```psp
# 정수 (Integer)
age = 25
port = 80
negative = -10
hex_value = 0xFF
binary_value = 0b1010
octal_value = 0o755

# 실수 (Float)
pi = 3.14159
timeout = 2.5
scientific = 1.23e-4

# 문자열 (String)
name = "PSP Language"
path = 'C:\\Windows\\System32'
multiline = """
여러줄
문자열
지원
"""

# 불린 (Boolean)
is_running = true
is_secure = false
is_null = null

# 특수 값
undefined_var = undefined
```

### 2.2 문자열 처리
```psp
# 문자열 보간
name = "해커"
message = "안녕하세요, ${name}님!"  # "안녕하세요, 해커님!"

# 원시 문자열 (Raw String)
regex_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
windows_path = r"C:\Program Files\Tools"

# 이스케이프 시퀀스
escaped = "줄바꿈: \n탭: \t백슬래시: \\"

# 문자열 연산
full_name = "Power" + "Shell" + "Plus"
repeated = "A" * 10  # "AAAAAAAAAA"
```

### 2.3 배열 (Arrays)
```psp
# 배열 생성
ports = [21, 22, 23, 80, 443]
services = ["ftp", "ssh", "telnet", "http", "https"]
mixed = [1, "hello", true, 3.14]
empty = []

# 다차원 배열
matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
scan_results = [
    ["192.168.1.1", 80, "open"],
    ["192.168.1.2", 22, "closed"],
    ["192.168.1.3", 443, "filtered"]
]

# 배열 접근
first_port = ports[0]      # 21
last_port = ports[-1]      # 443
subset = ports[1:3]        # [22, 23]

# 배열 메서드
ports.append(8080)         # 추가
ports.insert(1, 25)        # 삽입
removed = ports.pop()      # 제거 및 반환
ports.remove(23)           # 값으로 제거
length = len(ports)        # 길이
```

### 2.4 딕셔너리 (Dictionaries)
```psp
# 딕셔너리 생성
server_info = {
    "ip": "192.168.1.100",
    "port": 80,
    "service": "http",
    "banner": "Apache/2.4.41"
}

# 중첩 딕셔너리
scan_results = {
    "target": "example.com",
    "ports": {
        "open": [80, 443],
        "closed": [21, 22],
        "filtered": [25]
    },
    "vulnerabilities": [
        {"type": "XSS", "severity": "medium"},
        {"type": "SQLi", "severity": "high"}
    ]
}

# 딕셔너리 접근
ip_address = server_info["ip"]
port_number = server_info.port  # 점 표기법도 지원
server_info["os"] = "Windows"   # 추가
del server_info["banner"]       # 삭제

# 딕셔너리 메서드
keys = server_info.keys()
values = server_info.values()
items = server_info.items()
```

### 2.5 타입 변환
```psp
# 명시적 변환
str_num = "123"
int_num = int(str_num)      # 123
float_num = float(str_num)  # 123.0
bool_val = bool(int_num)    # true

# 문자열 변환
num_str = str(123)          # "123"
list_str = str([1, 2, 3])   # "[1, 2, 3]"

# 타입 확인
type_name = typeof(123)     # "int"
is_string = isinstance("hello", str)  # true
```

## 3. 변수와 상수 (Variables and Constants)

### 3.1 변수 선언
```psp
# 기본 변수
target = "192.168.1.1"
port = 80

# 타입 힌트 (선택사항)
target: string = "192.168.1.1"
port: int = 80
timeout: float = 2.5
is_running: bool = true

# 다중 할당
ip, port, service = "192.168.1.1", 80, "http"
a, b = b, a  # 값 교환
```

### 3.2 상수
```psp
# 상수 선언 (대문자 권장)
const DEFAULT_TIMEOUT = 10
const MAX_PORTS = 65535
const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

# 읽기 전용 (런타임에 결정)
readonly current_time = get_current_time()
readonly system_info = get_system_info()
```

### 3.3 스코프와 접근 제어
```psp
# 전역 변수
global debug_mode = true
global log_file = "scan.log"

# 지역 변수
function scan_port(host, port) {
    local timeout = 5  # 함수 스코프
    # ...
}

# 정적 변수 (함수 간 상태 유지)
function get_next_id() {
    static counter = 0
    counter = counter + 1
    return counter
}
```

## 4. 연산자 (Operators)

### 4.1 산술 연산자
```psp
a = 10
b = 3

sum = a + b        # 13 (덧셈)
diff = a - b       # 7  (뺄셈)
product = a * b    # 30 (곱셈)
quotient = a / b   # 3.333... (나눗셈)
remainder = a % b  # 1  (나머지)
power = a ** b     # 1000 (거듭제곱)
int_div = a // b   # 3  (정수 나눗셈)

# 복합 할당 연산자
a += 5    # a = a + 5
a -= 3    # a = a - 3
a *= 2    # a = a * 2
a /= 4    # a = a / 4
a %= 3    # a = a % 3
a **= 2   # a = a ** 2

# 증감 연산자
counter = 0
counter++    # 후위 증가 (counter = 1)
++counter    # 전위 증가 (counter = 2)
counter--    # 후위 감소 (counter = 1)
--counter    # 전위 감소 (counter = 0)
```

### 4.2 비교 연산자
```psp
a = 10
b = 5

equal = (a == b)      # false (같음)
not_equal = (a != b)  # true  (다름)
greater = (a > b)     # true  (초과)
less = (a < b)        # false (미만)
gte = (a >= b)        # true  (이상)
lte = (a <= b)        # false (이하)

# 문자열 비교
str1 = "apple"
str2 = "banana"
lexical = (str1 < str2)  # true (사전순)

# 객체 비교
identity = (obj1 is obj2)      # 동일 객체
not_identity = (obj1 is not obj2)  # 다른 객체
```

### 4.3 논리 연산자
```psp
a = true
b = false

and_result = a && b    # false (AND)
or_result = a || b     # true  (OR)
not_result = !a        # false (NOT)

# 단축 평가
result = a && expensive_function()  # a가 false면 함수 호출 안함

# 비트 연산자
x = 0b1010  # 10
y = 0b1100  # 12

bit_and = x & y        # 0b1000 (8)
bit_or = x | y         # 0b1110 (14)
bit_xor = x ^ y        # 0b0110 (6)
bit_not = ~x           # ...11110101
left_shift = x << 2    # 0b101000 (40)
right_shift = x >> 1   # 0b101 (5)
```

### 4.4 문자열 연산자
```psp
str1 = "Hello"
str2 = "World"

# 연결
greeting = str1 + " " + str2  # "Hello World"

# 반복
dashes = "-" * 10  # "----------"

# 포함 확인
contains = "ell" in str1      # true
not_contains = "xyz" not in str1  # true

# 패턴 매칭
matches = "192.168.1.1" =~ r"\d+\.\d+\.\d+\.\d+"  # true
not_matches = "invalid" !~ r"\d+\.\d+\.\d+\.\d+"  # true
```

### 4.5 삼항 연산자
```psp
# 조건부 표현식
age = 20
status = (age >= 18) ? "성인" : "미성년자"

# null 병합 연산자
config_value = user_setting ?? default_value

# 안전한 접근 연산자
banner = response?.body?.banner ?? "Unknown"
```

## 5. 제어 구조 (Control Flow)

### 5.1 조건문 (Conditional Statements)

#### if 문
```psp
port = 80

if port == 80 {
    print("HTTP 포트")
} else if port == 443 {
    print("HTTPS 포트")
} else if port == 22 {
    print("SSH 포트")
} else {
    print("알 수 없는 포트")
}

# 한줄 if
if debug_mode { print("디버그 모드 활성화") }

# unless (if not의 줄임)
unless is_secure {
    print("보안 경고!")
}
```

#### switch 문
```psp
service_type = get_service_type(port)

switch service_type {
    case "http":
        print("웹 서버 스캔 시작")
        scan_web_server(target)
        break
    
    case "ssh":
        print("SSH 서비스 발견")
        check_ssh_version(target)
        break
    
    case "ftp":
        print("FTP 서비스 발견")
        check_anonymous_ftp(target)
        break
    
    default:
        print("알 수 없는 서비스")
}

# 표현식 형태의 switch
result = switch port {
    80, 8080 => "HTTP"
    443, 8443 => "HTTPS"
    22 => "SSH"
    21 => "FTP"
    default => "Unknown"
}
```

### 5.2 반복문 (Loops)

#### for 루프
```psp
# 기본 for 루프
for i in range(1, 11) {
    print("포트 ${i} 스캔 중...")
}

# 배열 순회
ports = [80, 443, 22, 21]
for port in ports {
    if scan_port(target, port) {
        print("포트 ${port}: 열림")
    }
}

# 딕셔너리 순회
server_info = {"ip": "192.168.1.1", "port": 80, "service": "http"}

for key in server_info {
    print("${key}: ${server_info[key]}")
}

for key, value in server_info.items() {
    print("${key} = ${value}")
}

# 인덱스와 함께 순회
for index, port in enumerate(ports) {
    print("${index}: ${port}")
}

# C 스타일 for 루프
for (i = 0; i < 10; i++) {
    print("반복 ${i}")
}
```

#### while 루프
```psp
# 기본 while
counter = 0
while counter < 5 {
    print("카운터: ${counter}")
    counter++
}

# 조건부 while
while scan_port(target, port) {
    print("포트가 여전히 열려있음")
    sleep(1)
}

# do-while (최소 1회 실행)
do {
    result = perform_scan()
    print("스캔 결과: ${result}")
} while result != "complete"
```

#### 반복 제어
```psp
for port in range(1, 1001) {
    if port == 100 {
        continue  # 다음 반복으로
    }
    
    if port > 500 {
        break     # 반복 종료
    }
    
    scan_port(target, port)
}

# 레이블을 사용한 다중 루프 제어
outer: for host in hosts {
    inner: for port in ports {
        if critical_error_occurred() {
            break outer  # 외부 루프까지 종료
        }
        
        if minor_error_occurred() {
            continue inner  # 내부 루프의 다음 반복
        }
    }
}
```

### 5.3 예외 처리 (Exception Handling)
```psp
# 기본 try-catch
try {
    result = risky_operation()
    print("성공: ${result}")
} catch NetworkError as e {
    print("네트워크 오류: ${e.message}")
} catch TimeoutError as e {
    print("타임아웃 오류: ${e.message}")
} catch Error as e {
    print("일반 오류: ${e.message}")
} finally {
    cleanup_resources()
}

# 간단한 형태
try {
    connect(target, port)
} catch {
    print("연결 실패")
}

# 오류 던지기
function validate_ip(ip) {
    if !is_valid_ip(ip) {
        throw new ValidationError("유효하지 않은 IP 주소: ${ip}")
    }
}

# 사용자 정의 오류
class CustomScanError extends Error {
    constructor(message, error_code) {
        super(message)
        this.error_code = error_code
    }
}
```

## 6. 함수 (Functions)

### 6.1 함수 정의
```psp
# 기본 함수
function greet(name) {
    return "안녕하세요, ${name}님!"
}

# 타입 힌트가 있는 함수
function scan_port(host: string, port: int, timeout: float = 5.0): bool {
    # 함수 본문
    return connect(host, port, timeout)
}

# 가변 인수 함수
function scan_multiple_ports(host: string, ...ports: int[]): dict {
    results = {}
    for port in ports {
        results[port] = scan_port(host, port)
    }
    return results
}

# 키워드 인수 함수
function advanced_scan(host: string, **options: dict): dict {
    timeout = options.get("timeout", 5.0)
    threads = options.get("threads", 10)
    stealth = options.get("stealth", false)
    
    # 스캔 로직
    return scan_results
}
```

### 6.2 함수 호출
```psp
# 기본 호출
message = greet("해커")

# 위치 인수
result = scan_port("192.168.1.1", 80)

# 키워드 인수
result = scan_port(host="192.168.1.1", port=80, timeout=10.0)

# 가변 인수
results = scan_multiple_ports("192.168.1.1", 80, 443, 22, 21)

# 키워드 인수 딕셔너리
scan_options = {
    "timeout": 10.0,
    "threads": 20,
    "stealth": true
}
results = advanced_scan("192.168.1.1", **scan_options)
```

### 6.3 람다 함수
```psp
# 기본 람다
square = (x) => x * x
add = (a, b) => a + b

# 배열 처리에 사용
numbers = [1, 2, 3, 4, 5]
squared = numbers.map((x) => x * x)      # [1, 4, 9, 16, 25]
evens = numbers.filter((x) => x % 2 == 0)  # [2, 4]

# 포트 스캔에 적용
open_ports = ports.filter((port) => scan_port(target, port))
```

### 6.4 고차 함수
```psp
# 함수를 인수로 받기
function retry(operation, max_attempts = 3) {
    for attempt in range(1, max_attempts + 1) {
        try {
            return operation()
        } catch {
            if attempt == max_attempts {
                throw
            }
            sleep(attempt)  # 지수 백오프
        }
    }
}

# 사용 예
result = retry(() => scan_port("192.168.1.1", 80))

# 함수 반환
function create_scanner(default_timeout) {
    return (host, port) => scan_port(host, port, default_timeout)
}

fast_scan = create_scanner(1.0)
slow_scan = create_scanner(10.0)
```

### 6.5 함수 데코레이터
```psp
# 데코레이터 정의
function timing(func) {
    return function(...args) {
        start_time = time()
        result = func(...args)
        end_time = time()
        print("함수 ${func.name} 실행 시간: ${end_time - start_time}초")
        return result
    }
}

function retry_on_failure(max_attempts = 3) {
    return function(func) {
        return function(...args) {
            for attempt in range(1, max_attempts + 1) {
                try {
                    return func(...args)
                } catch {
                    if attempt == max_attempts {
                        throw
                    }
                }
            }
        }
    }
}

# 데코레이터 사용
@timing
@retry_on_failure(3)
function complex_scan(target) {
    # 복잡한 스캔 로직
    return scan_results
}
```

## 7. 클래스와 객체 지향 프로그래밍

### 7.1 클래스 정의
```psp
# 기본 클래스
class Scanner {
    # 클래스 변수
    static default_timeout = 5.0
    static scan_count = 0
    
    # 생성자
    constructor(target_host, options = {}) {
        this.host = target_host
        this.timeout = options.timeout ?? Scanner.default_timeout
        this.threads = options.threads ?? 10
        this.results = {}
        Scanner.scan_count++
    }
    
    # 인스턴스 메서드
    function scan_port(port) {
        try {
            is_open = connect(this.host, port, this.timeout)
            this.results[port] = is_open ? "open" : "closed"
            return is_open
        } catch TimeoutError {
            this.results[port] = "timeout"
            return false
        }
    }
    
    function scan_range(start_port, end_port) {
        open_ports = []
        for port in range(start_port, end_port + 1) {
            if this.scan_port(port) {
                open_ports.append(port)
            }
        }
        return open_ports
    }
    
    # 게터/세터
    get host() {
        return this._host
    }
    
    set host(value) {
        if !is_valid_ip(value) {
            throw new ValidationError("유효하지 않은 IP: ${value}")
        }
        this._host = value
    }
    
    # 정적 메서드
    static function get_total_scans() {
        return Scanner.scan_count
    }
    
    # 프라이빗 메서드
    private function _validate_port(port) {
        return port >= 1 && port <= 65535
    }
    
    # 문자열 표현
    function toString() {
        return "Scanner(host=${this.host}, timeout=${this.timeout})"
    }
}
```

### 7.2 상속
```psp
# 부모 클래스
class NetworkTool {
    constructor(name) {
        this.name = name
        this.created_at = current_time()
    }
    
    function log(message) {
        print("[${this.name}] ${message}")
    }
}

# 자식 클래스
class AdvancedScanner extends NetworkTool {
    constructor(target_host, scan_type = "tcp") {
        super("AdvancedScanner")  # 부모 생성자 호출
        this.host = target_host
        this.scan_type = scan_type
        this.vulnerabilities = []
    }
    
    # 메서드 오버라이드
    function log(message) {
        super.log("[${this.scan_type.upper()}] ${message}")
    }
    
    # 새로운 메서드
    function vulnerability_scan() {
        this.log("취약점 스캔 시작")
        
        # 공통 취약점 확인
        if this.scan_port(21) {
            this.check_ftp_anonymous()
        }
        
        if this.scan_port(22) {
            this.check_ssh_version()
        }
        
        return this.vulnerabilities
    }
    
    private function check_ftp_anonymous() {
        # FTP 익명 로그인 체크
        if ftp_anonymous_login(this.host) {
            this.vulnerabilities.append({
                "type": "FTP Anonymous Login",
                "severity": "medium",
                "port": 21
            })
        }
    }
}
```

### 7.3 인터페이스와 추상 클래스
```psp
# 인터페이스 정의
interface IScannable {
    function scan(): dict
    function get_results(): dict
}

# 추상 클래스
abstract class BaseTool {
    constructor(name) {
        this.name = name
    }
    
    # 추상 메서드 (구현 필요)
    abstract function execute(): dict
    
    # 구체 메서드
    function log_execution() {
        print("도구 ${this.name} 실행 중...")
    }
}

# 인터페이스 구현
class PortScanner implements IScannable {
    constructor(host) {
        this.host = host
        this.scan_results = {}
    }
    
    function scan() {
        # IScannable 인터페이스 구현
        for port in [21, 22, 80, 443] {
            this.scan_results[port] = scan_port(this.host, port)
        }
        return this.scan_results
    }
    
    function get_results() {
        return this.scan_results
    }
}
```

### 7.4 믹스인 (Mixins)
```psp
# 믹스인 정의
mixin Loggable {
    function debug(message) {
        if this.debug_mode {
            print("[DEBUG] ${message}")
        }
    }
    
    function info(message) {
        print("[INFO] ${message}")
    }
    
    function error(message) {
        print("[ERROR] ${message}")
    }
}

mixin Configurable {
    function load_config(config_file) {
        this.config = load_json(config_file)
    }
    
    function get_config(key, default_value = null) {
        return this.config.get(key, default_value)
    }
}

# 믹스인 사용
class WebScanner with Loggable, Configurable {
    constructor(target_url) {
        this.target_url = target_url
        this.debug_mode = true
        this.config = {}
    }
    
    function scan_vulnerabilities() {
        this.info("웹 취약점 스캔 시작")
        this.debug("타겟 URL: ${this.target_url}")
        
        # 스캔 로직
        results = this.perform_scan()
        
        this.info("스캔 완료")
        return results
    }
}
```

## 8. 모듈 시스템

### 8.1 모듈 정의
```psp
# network_utils.pspp
/**
 * 네트워크 유틸리티 모듈
 * @author PSP Team
 * @version 1.0
 */

# 모듈 메타데이터
__module_name__ = "network_utils"
__version__ = "1.0.0"
__author__ = "PSP Team"

# 내보낼 함수들
export function advanced_port_scan(host, ports, options = {}) {
    timeout = options.timeout ?? 5.0
    threads = options.threads ?? 10
    
    results = {}
    
    # 멀티스레드 스캔 구현
    for port in ports {
        results[port] = {
            "status": scan_port(host, port, timeout),
            "banner": get_banner(host, port)
        }
    }
    
    return results
}

export function subnet_scan(network_range) {
    active_hosts = []
    
    for ip in generate_ip_range(network_range) {
        if ping_host(ip) {
            active_hosts.append(ip)
        }
    }
    
    return active_hosts
}

export function service_detection(host, port) {
    banner = get_banner(host, port)
    
    # 서비스 시그니처 매칭
    if "Apache" in banner {
        return {"service": "Apache HTTP", "version": extract_version(banner)}
    } else if "nginx" in banner {
        return {"service": "Nginx", "version": extract_version(banner)}
    } else if "OpenSSH" in banner {
        return {"service": "OpenSSH", "version": extract_version(banner)}
    }
    
    return {"service": "unknown", "banner": banner}
}

# 프라이빗 함수 (모듈 내부에서만 사용)
function extract_version(banner) {
    # 버전 추출 로직
    version_match = banner.match(r"(\d+\.\d+(?:\.\d+)?)")
    return version_match ? version_match[1] : "unknown"
}

# 모듈 초기화
function __init__() {
    print("네트워크 유틸리티 모듈 로드됨")
}
```

### 8.2 모듈 사용
```psp
# main.pspp

# 전체 모듈 임포트
import "network_utils"
import "crypto_tools"
import "web_scanner"

# 별칭 사용
import "network_utils" as net
import "crypto_tools" as crypto

# 특정 함수만 임포트
from "network_utils" import advanced_port_scan, subnet_scan
from "crypto_tools" import hash_password, encrypt_data

# 와일드카드 임포트 (권장하지 않음)
from "network_utils" import *

# 모듈 사용
function main() {
    # 전체 모듈 경로
    results = network_utils.advanced_port_scan("192.168.1.1", [80, 443])
    
    # 별칭 사용
    hash_value = crypto.sha256("password")
    
    # 직접 임포트된 함수
    scan_results = advanced_port_scan("192.168.1.1", [21, 22, 80])
}
```

### 8.3 패키지 구조
```
psp_security_tools/
├── __init__.pspp           # 패키지 초기화
├── network/
│   ├── __init__.pspp
│   ├── scanner.pspp        # 포트 스캐너
│   ├── sniffer.pspp        # 패킷 스니퍼
│   └── analyzer.pspp       # 트래픽 분석
├── crypto/
│   ├── __init__.pspp
│   ├── hash.pspp           # 해시 함수들
│   ├── encryption.pspp     # 암호화 도구
│   └── cracking.pspp       # 크래킹 도구
└── web/
    ├── __init__.pspp
    ├── scanner.pspp        # 웹 취약점 스캐너
    ├── payloads.pspp       # 웹 공격 페이로드
    └── crawler.pspp        # 웹 크롤러
```

```psp
# 패키지 사용
import "psp_security_tools.network.scanner" as port_scanner
import "psp_security_tools.crypto.hash" as hash_utils
from "psp_security_tools.web.payloads" import sql_injection_payloads
```

## 9. 오류 처리와 디버깅

### 9.1 사용자 정의 오류
```psp
# 기본 오류 클래스
class PSPError extends Error {
    constructor(message, error_code = null) {
        super(message)
        this.error_code = error_code
        this.timestamp = current_time()
    }
}

class NetworkError extends PSPError {
    constructor(message, host = null, port = null) {
        super(message, "NET_ERROR")
        this.host = host
        this.port = port
    }
}

class ScanTimeoutError extends NetworkError {
    constructor(host, port, timeout) {
        super("스캔 타임아웃: ${host}:${port} (${timeout}초)", host, port)
        this.timeout = timeout
    }
}

class ValidationError extends PSPError {
    constructor(message, field = null) {
        super(message, "VALIDATION_ERROR")
        this.field = field
    }
}
```

### 9.2 어서션과 디버깅
```psp
# 어서션
function scan_port(host, port) {
    assert host != null, "호스트가 null일 수 없습니다"
    assert port > 0 && port <= 65535, "포트 범위가 잘못되었습니다: ${port}"
    
    # 스캔 로직
    return connect(host, port)
}

# 디버깅 정보
function debug_scan(host, port) {
    debug_print("스캔 시작: ${host}:${port}")
    
    start_time = time()
    result = scan_port(host, port)
    end_time = time()
    
    debug_print("스캔 완료: ${result} (${end_time - start_time}초)")
    
    return result
}

# 조건부 디버깅
DEBUG_MODE = true

function conditional_debug(message) {
    if DEBUG_MODE {
        print("[DEBUG ${current_time()}] ${message}")
    }
}
```

### 9.3 로깅
```psp
# 로깅 시스템
class Logger {
    static levels = {
        "DEBUG": 0,
        "INFO": 1,
        "WARNING": 2,
        "ERROR": 3,
        "CRITICAL": 4
    }
    
    constructor(name, level = "INFO") {
        this.name = name
        this.level = Logger.levels[level]
        this.handlers = []
    }
    
    function add_handler(handler) {
        this.handlers.append(handler)
    }
    
    function log(level, message) {
        if Logger.levels[level] >= this.level {
            log_entry = {
                "timestamp": current_time(),
                "logger": this.name,
                "level": level,
                "message": message
            }
            
            for handler in this.handlers {
                handler.emit(log_entry)
            }
        }
    }
    
    function debug(message) { this.log("DEBUG", message) }
    function info(message) { this.log("INFO", message) }
    function warning(message) { this.log("WARNING", message) }
    function error(message) { this.log("ERROR", message) }
    function critical(message) { this.log("CRITICAL", message) }
}

# 파일 핸들러
class FileHandler {
    constructor(filename) {
        this.filename = filename
    }
    
    function emit(log_entry) {
        formatted = "${log_entry.timestamp} [${log_entry.level}] ${log_entry.logger}: ${log_entry.message}"
        file_append(this.filename, formatted + "\n")
    }
}

# 사용 예
logger = new Logger("ScanTool", "DEBUG")
logger.add_handler(new FileHandler("scan.log"))

logger.info("포트 스캔 시작")
logger.debug("타겟: 192.168.1.1")
logger.error("연결 실패")
```

## 10. 고급 기능

### 10.1 제네릭과 타입 시스템
```psp
# 제네릭 함수
function create_list<T>(): Array<T> {
    return []
}

function find<T>(array: Array<T>, predicate: (T) => bool): T? {
    for item in array {
        if predicate(item) {
            return item
        }
    }
    return null
}

# 제네릭 클래스
class Result<T, E> {
    constructor(value: T? = null, error: E? = null) {
        this.value = value
        this.error = error
        this.is_success = error == null
    }
    
    function unwrap(): T {
        if this.is_success {
            return this.value
        } else {
            throw this.error
        }
    }
    
    function map<U>(func: (T) => U): Result<U, E> {
        if this.is_success {
            return new Result<U, E>(func(this.value))
        } else {
            return new Result<U, E>(null, this.error)
        }
    }
}

# 사용 예
function safe_scan_port(host: string, port: int): Result<bool, NetworkError> {
    try {
        result = scan_port(host, port)
        return new Result<bool, NetworkError>(result)
    } catch NetworkError as e {
        return new Result<bool, NetworkError>(null, e)
    }
}

scan_result = safe_scan_port("192.168.1.1", 80)
if scan_result.is_success {
    print("스캔 성공: ${scan_result.value}")
} else {
    print("스캔 실패: ${scan_result.error.message}")
}
```

### 10.2 비동기 프로그래밍
```psp
# 비동기 함수
async function async_scan_port(host: string, port: int): Promise<bool> {
    return await connect_async(host, port)
}

async function scan_multiple_hosts(hosts: string[], port: int): Promise<dict> {
    results = {}
    
    # 병렬 실행
    tasks = []
    for host in hosts {
        tasks.append(async_scan_port(host, port))
    }
    
    # 모든 작업 완료 대기
    scan_results = await Promise.all(tasks)
    
    for i, host in enumerate(hosts) {
        results[host] = scan_results[i]
    }
    
    return results
}

# async/await 사용
async function main() {
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    results = await scan_multiple_hosts(hosts, 80)
    
    for host, is_open in results.items() {
        status = is_open ? "열림" : "닫힘"
        print("${host}:80 - ${status}")
    }
}

# 프로미스 체이닝
scan_port_async("192.168.1.1", 80)
    .then((result) => {
        print("스캔 결과: ${result}")
        return get_banner_async("192.168.1.1", 80)
    })
    .then((banner) => {
        print("배너: ${banner}")
    })
    .catch((error) => {
        print("오류 발생: ${error}")
    })
```

### 10.3 메타프로그래밍
```psp
# 리플렉션
class ScanTool {
    function tcp_scan(host, port) { /* ... */ }
    function udp_scan(host, port) { /* ... */ }
    function stealth_scan(host, port) { /* ... */ }
}

# 클래스 정보 조회
tool = new ScanTool()
class_info = reflect(tool)

print("클래스 이름: ${class_info.name}")
print("메서드 목록:")
for method in class_info.methods {
    print("  ${method.name}(${method.parameters.join(', ')})")
}

# 동적 메서드 호출
method_name = "tcp_scan"
if class_info.has_method(method_name) {
    result = tool.call_method(method_name, "192.168.1.1", 80)
}

# 애트리뷰트 조작
tool.set_attribute("timeout", 10.0)
timeout = tool.get_attribute("timeout")

# 데코레이터 팩토리
function create_retry_decorator(max_attempts) {
    return function(target, property_name, descriptor) {
        original_method = descriptor.value
        
        descriptor.value = function(...args) {
            for attempt in range(1, max_attempts + 1) {
                try {
                    return original_method.apply(this, args)
                } catch {
                    if attempt == max_attempts {
                        throw
                    }
                    sleep(attempt)
                }
            }
        }
        
        return descriptor
    }
}

# 사용
class NetworkScanner {
    @create_retry_decorator(3)
    function unreliable_scan(host, port) {
        # 불안정할 수 있는 스캔 로직
        return scan_port(host, port)
    }
}
```

### 10.4 매크로 시스템
```psp
# 매크로 정의
macro repeat(count, body) {
    for __i in range(${count}) {
        ${body}
    }
}

macro benchmark(name, body) {
    __start = time()
    ${body}
    __end = time()
    print("${name} 실행 시간: ${__end - __start}초")
}

# 매크로 사용
repeat(5) {
    print("반복 중...")
}

benchmark("포트 스캔") {
    scan_port("192.168.1.1", 80)
}

# 조건부 컴파일
macro debug_only(body) {
    #if DEBUG_MODE
        ${body}
    #endif
}

debug_only {
    print("디버그 모드에서만 실행됩니다")
}
```

이 완전한 문법 가이드로 PSP 언어의 모든 기능을 다룰 수 있습니다. 다음으로 GitHub과 VS Code 지원을 위한 파일들을 생성하겠습니다.
