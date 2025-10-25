# PSP (PowerShellPlus) 언어 문법 정의

## 기본 구조

### 변수 선언 및 할당
```
변수명 = 값
target = "192.168.1.1"
port = 80
```

### 데이터 타입
- 문자열: "hello", 'world'
- 정수: 42, -10
- 실수: 3.14, -2.5
- 불린: true, false
- 배열: [1, 2, 3, "test"]
- 딕셔너리: {"key": "value", "port": 80}

### 주석
```
# 한줄 주석
/* 
   여러줄 주석
   블록 주석
*/
```

## 제어 구조

### 조건문
```
if 조건 {
    # 실행할 코드
} else if 다른조건 {
    # 다른 코드
} else {
    # 기본 코드
}
```

### 반복문
```
# for 루프
for i in range(1, 10) {
    print(i)
}

for item in array {
    print(item)
}

# while 루프
while 조건 {
    # 반복할 코드
}
```

### 함수 정의
```
function 함수명(매개변수1, 매개변수2) {
    # 함수 본문
    return 반환값
}

# 예제
function calculate_hash(data, algorithm) {
    if algorithm == "md5" {
        return md5(data)
    } else if algorithm == "sha256" {
        return sha256(data)
    }
    return ""
}
```

## 내장 함수들

### 네트워크 함수
- `connect(host, port)` - TCP 연결 테스트
- `send(host, port, data)` - 데이터 전송
- `recv(host, port, size)` - 데이터 수신
- `scan_port(host, port)` - 포트 스캔
- `scan_range(host, start_port, end_port)` - 포트 범위 스캔

### 암호화/해시 함수
- `md5(data)` - MD5 해시
- `sha1(data)` - SHA1 해시
- `sha256(data)` - SHA256 해시
- `base64_encode(data)` - Base64 인코딩
- `base64_decode(data)` - Base64 디코딩

### 페이로드/익스플로잇 함수
- `create_payload(type, target, options)` - 페이로드 생성
- `buffer_overflow(size, pattern)` - 버퍼 오버플로우 패턴
- `shellcode(arch)` - 셸코드 생성

### 윈도우 시스템 함수
- `enum_processes()` - 프로세스 열거
- `enum_services()` - 서비스 열거
- `registry_read(key, value)` - 레지스트리 읽기
- `registry_write(key, value, data, type)` - 레지스트리 쓰기

### 파일 시스템 함수
- `file_read(path)` - 파일 읽기
- `file_write(path, content)` - 파일 쓰기
- `file_exists(path)` - 파일 존재 확인
- `dir_list(path)` - 디렉터리 목록

### 출력 함수
- `print(message)` - 기본 출력
- `printf(format, args...)` - 포맷 출력
- `log(message, level)` - 로그 출력

## 연산자

### 산술 연산자
- `+` - 덧셈
- `-` - 뺄셈
- `*` - 곱셈
- `/` - 나눗셈
- `%` - 나머지
- `**` - 거듭제곱

### 비교 연산자
- `==` - 같음
- `!=` - 다름
- `>` - 초과
- `<` - 미만
- `>=` - 이상
- `<=` - 이하

### 논리 연산자
- `&&` - AND
- `||` - OR
- `!` - NOT

### 문자열 연산자
- `+` - 문자열 연결
- `in` - 포함 여부 확인

## 특수 기능

### 파이프라인
```
scan_range("192.168.1.1", 1, 1000) | filter_open() | save_results("scan.txt")
```

### 병렬 처리
```
parallel {
    scan_port("192.168.1.1", 80)
    scan_port("192.168.1.1", 443)
    scan_port("192.168.1.1", 22)
}
```

### 예외 처리
```
try {
    # 위험한 코드
    connect(target, port)
} catch error {
    log("연결 실패: " + error, "ERROR")
} finally {
    # 정리 코드
    cleanup()
}
```

## 모듈 시스템

### 모듈 임포트
```
import "network_utils"
import "crypto_tools" as crypto
```

### 모듈 정의
```
# network_utils.pspp
export function advanced_scan(target, ports) {
    results = []
    for port in ports {
        if scan_port(target, port) {
            results.append(port)
        }
    }
    return results
}
```
