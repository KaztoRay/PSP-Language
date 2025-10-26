# PSP (PowerShell Plus) 프로그래밍 언어

<div align="center">

![PSP Logo](https://img.shields.io/badge/PSP-Programming%20Language-0078d4?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**보안 테스트와 시스템 관리를 위한 전문 프로그래밍 언어**

[📖 문서](#-문서) •
[🚀 시작하기](#-시작하기) •
[💻 예제](#-예제) •
[🔧 설치](#-설치) •
[🤝 기여](#-기여)

</div>

## 📋 개요

PSP는 **PowerShell, C언어, Python**의 장점을 결합한 혁신적인 프로그래밍 언어입니다. 사이버 보안 전문가, 시스템 관리자, 그리고 보안 연구원을 위해 특별히 설계되었습니다.

### ✨ 주요 특징

- 🛡️ **보안 특화**: 네트워크 스캔, 취약점 테스트, 포렌식 도구 내장
- 🔧 **PowerShell 스타일 cmdlet**: 직관적이고 강력한 명령어 시스템
- 📘 **C언어 스타일 타입**: 명시적 타입 선언으로 안전성 향상
- 🐍 **Python 스타일 간결함**: 읽기 쉽고 작성하기 쉬운 문법
- 🔄 **객체 파이프라인**: PowerShell과 같은 강력한 데이터 처리
- 🌐 **크로스플랫폼**: Windows, Linux, macOS 지원

## 🚀 시작하기

### Hello World

```psp
# PSP Hello World
Write-Output "안녕하세요, PSP 언어에 오신 것을 환영합니다!"
Write-Host "PSP는 보안 테스트 전문 언어입니다." -ForegroundColor Green

# 변수 선언 (타입 명시)
String $language = "PSP"
Int32 $version = 1
Boolean $isSecure = $true

# 변수 출력
Write-Output "언어: $language"
Write-Output "버전: $version"
Write-Output "보안 특화: $isSecure"
```

### 네트워크 보안 스캔 예제

```psp
# 네트워크 보안 스캔
String $target = "192.168.1.1"
Array[Int32] $ports = @(80, 443, 22, 21, 25, 53)

Write-Output "스캔 대상: $target"

# 포트 스캔 실행
foreach ($port in $ports) {
    $result = Test-NetConnection -ComputerName $target -Port $port
    if ($result.TcpTestSucceeded) {
        Write-Host "포트 $port : OPEN" -ForegroundColor Green
        $banner = Get-ServiceBanner -Target $target -Port $port
        Write-Output "  서비스: $banner"
    } else {
        Write-Host "포트 $port : CLOSED" -ForegroundColor Red
    }
}
```

## 💻 예제

### 기본 문법

```psp
# 변수와 타입
String $name = "김철수"
Int32 $age = 25
Array[String] $skills = @("PSP", "PowerShell", "Python")
Hashtable $config = @{
    Host = "localhost"
    Port = 8080
    SSL = $true
}

# 조건문
if ($age -ge 18) {
    Write-Output "성인입니다"
} else {
    Write-Output "미성년자입니다"
}

# 반복문
foreach ($skill in $skills) {
    Write-Output "기술: $skill"
}
```

### 보안 테스트

```psp
# SQL 인젝션 테스트
$url = "http://example.com/login"
$payload = "' OR '1'='1"
$result = Test-SQLInjection -Url $url -Payload $payload

if ($result.Vulnerable) {
    Write-Warning "SQL 인젝션 취약점 발견!"
}

# 암호화/해싱
$password = "admin123"
$md5Hash = Get-Hash -InputString $password -Algorithm MD5
$sha256Hash = Get-Hash -InputString $password -Algorithm SHA256

Write-Output "MD5: $md5Hash"
Write-Output "SHA256: $sha256Hash"
```

### 파이프라인 처리

```psp
# 프로세스 분석
Get-ProcessList | 
    Where-Object { $_.CPU -gt 50 } | 
    Sort-Object CPU -Descending |
    Select-Object Name, CPU, Memory |
    Export-Csv "high_cpu_processes.csv"
```

## 🔧 설치

### 필요 조건

- Python 3.8 이상
- Windows 10/11, Linux, 또는 macOS

### 설치 방법

1. **저장소 클론**
```bash
git clone https://github.com/psp-team/PSP-Language.git
cd PSP-Language
```

2. **의존성 설치**
```bash
pip install -r requirements.txt
```

3. **PSP 스크립트 실행**
```bash
# 파일 실행
python3 src/psp_interpreter.py examples/hello_world.pspp

# 명령어 직접 실행
python3 src/psp_interpreter.py -c 'Write-Output "Hello PSP!"'

# 대화형 모드
python3 src/psp_interpreter.py -i
```

### VS Code 확장프로그램

PSP 언어를 더 편리하게 사용하려면 VS Code 확장프로그램을 설치하세요:

1. VS Code 열기
2. 확장프로그램 마켓플레이스에서 "PSP Language Support" 검색
3. 설치 및 활성화

## 📖 문서

- [📚 완전 가이드](docs/PSP_COMPLETE_GUIDE.md) - PSP 언어의 모든 문법과 기능
- [🏗️ 언어 설계](docs/NEW_LANGUAGE_DESIGN.md) - PSP 언어의 설계 철학과 목표
- [📝 문법 가이드](docs/powershell_based_grammar.md) - 상세한 문법 설명

### 예제 파일

- [👋 Hello World](examples/hello_world.pspp) - 기본 문법 소개
- [📖 기본 문법](examples/basic_syntax.pspp) - 변수, 타입, 제어구조
- [🔧 함수](examples/functions.pspp) - 함수 정의 및 사용
- [🔄 파이프라인](examples/pipelines.pspp) - 객체 파이프라인 처리
- [🏗️ 클래스](examples/classes.pspp) - 객체 지향 프로그래밍
- [🌐 네트워크 스캔](examples/network_scan.pspp) - 네트워크 보안 스캔
- [🔒 보안 테스트](examples/web_security_test.pspp) - 웹 보안 테스트

## 🛠️ 내장 cmdlet

### 출력 cmdlet
- `Write-Output` - 일반 출력
- `Write-Host` - 콘솔 출력 (색상 지원)
- `Write-Error` - 오류 메시지
- `Write-Warning` - 경고 메시지

### 네트워크 보안 cmdlet
- `Test-NetConnection` - 네트워크 연결 테스트
- `Invoke-PortScan` - 포트 스캔
- `Get-ServiceBanner` - 서비스 배너 수집
- `Start-PacketCapture` - 패킷 캡처

### 웹 보안 cmdlet
- `Test-SQLInjection` - SQL 인젝션 테스트
- `Test-XSS` - XSS 취약점 테스트
- `Invoke-WebScan` - 웹 취약점 스캔

### 암호화/해싱 cmdlet
- `Get-Hash` - 해시 생성 (MD5, SHA1, SHA256)
- `ConvertTo-Base64` - Base64 인코딩
- `ConvertFrom-Base64` - Base64 디코딩
- `Protect-Data` - 데이터 암호화
- `Unprotect-Data` - 데이터 복호화

### 시스템 정보 cmdlet
- `Get-SystemInfo` - 시스템 정보 조회
- `Get-ProcessList` - 프로세스 목록
- `Get-ServiceList` - 서비스 목록
- `Find-SensitiveFiles` - 민감한 파일 검색

## 🎯 사용 사례

### 보안 테스트
- 네트워크 취약점 스캔
- 웹 애플리케이션 보안 테스트
- 패스워드 크래킹
- 포렌식 분석

### 시스템 관리
- 서버 모니터링
- 로그 분석
- 자동화 스크립트
- 백업 및 복구

### 보안 연구
- 취약점 연구
- 익스플로잇 개발
- 보안 도구 개발
- 침투 테스트

## 📄 라이선스

이 프로젝트는 [MIT 라이선스](LICENSE) 하에 배포됩니다.
