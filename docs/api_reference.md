# PSP API Reference

## 네트워크 함수 (Network Functions)

### connect(host, port)
TCP 연결을 테스트합니다.

**매개변수:**
- `host` (string): 대상 호스트 IP 또는 도메인
- `port` (int): 대상 포트 번호

**반환값:** `bool` - 연결 성공 시 true, 실패 시 false

**예제:**
```psp
if connect("192.168.1.1", 80) {
    print("웹 서버가 실행 중입니다.")
}
```

### send(host, port, data)
TCP를 통해 데이터를 전송합니다.

**매개변수:**
- `host` (string): 대상 호스트
- `port` (int): 대상 포트
- `data` (string): 전송할 데이터

**반환값:** `bool` - 전송 성공 시 true

### recv(host, port, size)
TCP를 통해 데이터를 수신합니다.

**매개변수:**
- `host` (string): 대상 호스트
- `port` (int): 대상 포트
- `size` (int): 수신할 바이트 수 (기본값: 1024)

**반환값:** `string` - 수신된 데이터

### scan_port(host, port)
단일 포트를 스캔합니다.

**매개변수:**
- `host` (string): 스캔할 호스트
- `port` (int): 스캔할 포트

**반환값:** `bool` - 포트가 열려있으면 true

### scan_range(host, start_port, end_port)
포트 범위를 스캔합니다.

**매개변수:**
- `host` (string): 스캔할 호스트
- `start_port` (int): 시작 포트
- `end_port` (int): 끝 포트

**반환값:** `array` - 열린 포트 번호들의 배열

## 암호화 함수 (Cryptography Functions)

### md5(data)
MD5 해시를 계산합니다.

**매개변수:**
- `data` (string): 해시할 데이터

**반환값:** `string` - MD5 해시 값 (32자리 16진수)

### sha1(data)
SHA1 해시를 계산합니다.

**매개변수:**
- `data` (string): 해시할 데이터

**반환값:** `string` - SHA1 해시 값 (40자리 16진수)

### sha256(data)
SHA256 해시를 계산합니다.

**매개변수:**
- `data` (string): 해시할 데이터

**반환값:** `string` - SHA256 해시 값 (64자리 16진수)

### base64_encode(data)
Base64로 인코딩합니다.

**매개변수:**
- `data` (string): 인코딩할 데이터

**반환값:** `string` - Base64 인코딩된 문자열

### base64_decode(data)
Base64를 디코딩합니다.

**매개변수:**
- `data` (string): 디코딩할 Base64 문자열

**반환값:** `string` - 디코딩된 원본 데이터

## 익스플로잇 함수 (Exploit Functions)

### create_payload(type, target, options)
공격 페이로드를 생성합니다.

**매개변수:**
- `type` (string): 페이로드 타입 ("reverse_shell", "bind_shell", "download_exec")
- `target` (string): 타겟 주소 (옵션)
- `options` (string): 추가 옵션 (옵션)

**반환값:** `string` - 생성된 페이로드

**지원되는 페이로드 타입:**
- `reverse_shell`: 리버스 셸 페이로드
- `bind_shell`: 바인드 셸 페이로드
- `download_exec`: 다운로드 & 실행 페이로드

### buffer_overflow(size, pattern)
버퍼 오버플로우 패턴을 생성합니다.

**매개변수:**
- `size` (int): 패턴 크기
- `pattern` (string): 반복할 문자 (기본값: "A")

**반환값:** `string` - 생성된 패턴

### shellcode(arch)
셸코드를 생성합니다.

**매개변수:**
- `arch` (string): 아키텍처 ("x64" 또는 "x86", 기본값: "x64")

**반환값:** `string` - 셸코드

## 윈도우 시스템 함수 (Windows System Functions)

### enum_processes()
실행 중인 프로세스를 열거합니다.

**반환값:** `array` - 프로세스 목록

### enum_services()
윈도우 서비스를 열거합니다.

**반환값:** `array` - 서비스 목록

### registry_read(key, value)
레지스트리 값을 읽습니다.

**매개변수:**
- `key` (string): 레지스트리 키 경로
- `value` (string): 값 이름 (옵션)

**반환값:** `string` - 레지스트리 값

### registry_write(key, value, data, type)
레지스트리 값을 씁니다.

**매개변수:**
- `key` (string): 레지스트리 키 경로
- `value` (string): 값 이름
- `data` (string): 쓸 데이터
- `type` (string): 레지스트리 타입 (기본값: "REG_SZ")

**반환값:** `bool` - 성공 시 true

## 파일 시스템 함수 (File System Functions)

### file_read(path)
파일을 읽습니다.

**매개변수:**
- `path` (string): 파일 경로

**반환값:** `string` - 파일 내용

### file_write(path, content)
파일을 씁니다.

**매개변수:**
- `path` (string): 파일 경로
- `content` (string): 쓸 내용

**반환값:** `bool` - 성공 시 true

### file_exists(path)
파일 존재 여부를 확인합니다.

**매개변수:**
- `path` (string): 파일 경로

**반환값:** `bool` - 존재하면 true

### dir_list(path)
디렉터리 내용을 나열합니다.

**매개변수:**
- `path` (string): 디렉터리 경로 (기본값: ".")

**반환값:** `array` - 파일 및 디렉터리 목록

## 출력 함수 (Output Functions)

### print(message)
메시지를 출력합니다.

**매개변수:**
- `message` (any): 출력할 메시지

### printf(format, args...)
포맷된 메시지를 출력합니다.

**매개변수:**
- `format` (string): 포맷 문자열
- `args` (any): 포맷 인수들

### log(message, level)
로그 메시지를 출력합니다.

**매개변수:**
- `message` (string): 로그 메시지
- `level` (string): 로그 레벨 (기본값: "INFO")

**지원되는 로그 레벨:**
- `INFO`: 정보
- `WARNING`: 경고
- `ERROR`: 오류
- `SUCCESS`: 성공
