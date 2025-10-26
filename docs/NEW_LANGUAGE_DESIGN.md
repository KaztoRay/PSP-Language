# PSP (PowerShellPlus) 언어 설계 문서

## 언어 핵심 철학
- **PowerShell 기반**: PowerShell의 객체 파이프라인과 cmdlet 구조를 기본으로 함
- **C언어 문법**: 타입 시스템과 제어 구조는 C언어 스타일
- **Python 편의성**: Python의 간결함과 가독성을 도입
- **보안 특화**: 화이트햇 해킹과 보안 테스트에 최적화

## 핵심 문법 구조

### 1. PowerShell 기반 요소
```psp
# Cmdlet 스타일 함수 (동사-명사 패턴)
Get-ProcessList | Where-Object {$_.Name -like "*svchost*"} | Select-Object Name, PID

# 파이프라인 연산자
"192.168.1.1" | Test-NetConnection -Port 80 | Out-Host

# 변수 ($변수명)
$target = "192.168.1.100"
$ports = @(80, 443, 22)

# 해시테이블 (@{key=value})
$config = @{
    Host = "target.com"
    Port = 443
    SSL = $true
}
```

### 2. C언어 스타일 요소
```psp
# 타입 선언
int $port = 80;
string $hostname = "example.com";
bool $isSecure = true;
char $grade = 'A';

# 포인터와 참조 (PowerShell 적응)
ref $target = Get-Reference $hostname;
ptr $buffer = New-Buffer 1024;

# 구조체 정의
struct NetworkTarget {
    string $Host;
    int $Port;
    bool $IsAlive;
};

# 함수 정의 (반환 타입 명시)
int Scan-Port(string $host, int $port) {
    if (Test-NetConnection $host -Port $port) {
        return 1;
    }
    return 0;
}
```

### 3. Python 스타일 요소
```psp
# 리스트 컴프리헨션
$openPorts = @(foreach ($port in 1..1000) { 
    if (Test-Port $target $port) { $port } 
});

# 딕셔너리 스타일
$results = @{}
$results["target"] = $hostname
$results["status"] = "alive"

# 간단한 문법
if ($port -eq 80):
    Write-Output "HTTP port detected"
elif ($port -eq 443):
    Write-Output "HTTPS port detected"
else:
    Write-Output "Unknown service on port $port"
```

## 보안 특화 Cmdlet

### 네트워크 보안
- `Invoke-PortScan`
- `Test-SQLInjection`
- `Start-PacketCapture`
- `Get-NetworkTopology`

### 시스템 보안
- `Get-ProcessHollowing`
- `Find-Privilege Escalation`
- `Search-SensitiveFiles`
- `Invoke-MemoryDump`

### 웹 보안
- `Test-WebVulnerabilities`
- `Invoke-DirectoryBruteforce`
- `Get-WebTechnologies`
- `Test-XSSPayload`

### 암호화/해싱
- `ConvertTo-MD5Hash`
- `Invoke-HashCracking`
- `New-RSAKeyPair`
- `Protect-Data`

## 파일 확장자
- `.pspp` - PowerShellPlus 스크립트 파일
- `.pspx` - PowerShellPlus 실행 파일
- `.pspm` - PowerShellPlus 모듈 파일
