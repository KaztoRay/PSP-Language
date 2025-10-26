# PSP (PowerShellPlus) 완전 문법 가이드 v2.0
## PowerShell 기반 보안 특화 프로그래밍 언어

### 언어 철학
PSP는 PowerShell의 강력한 객체 파이프라인과 cmdlet 구조를 기반으로 하되, C언어의 타입 시스템과 Python의 간결함을 결합한 하이브리드 언어입니다.

---

## 1. 기본 문법 구조

### 1.1 Hello World
```psp
# PSP Hello World
Write-Host "안녕하세요, PSP 세계!" -ForegroundColor Green
Write-Output "PowerShell + C언어 + Python = PSP"
```

### 1.2 주석 (Comments)
```psp
# 한줄 주석 (PowerShell 스타일)

<#
여러줄 주석
PowerShell 스타일 블록 주석
#>

/* 
 * C언어 스타일 블록 주석도 지원
 * 혼합 사용 가능
 */
```

---

## 2. 변수와 데이터 타입

### 2.1 PowerShell 스타일 변수 ($변수명)
```psp
# 기본 변수 선언
$name = "PSP Language"
$version = 1.0
$isSecure = $true

# 변수 출력
Write-Output "언어: $name"
Write-Output "버전: $version"
```

### 2.2 C언어 스타일 타입 선언
```psp
# 강타입 변수 선언
int $port = 80
string $hostname = "example.com"
bool $isAlive = $false
double $score = 95.5
char $grade = 'A'

# 배열 선언
array $ports = @(80, 443, 22, 21)
hashtable $config = @{
    Host = "target.com"
    Port = 443
    SSL = $true
}
```

### 2.3 특수 변수들
```psp
# PowerShell 특수 변수
$_ = "현재 파이프라인 객체"
$? = $true  # 마지막 명령 성공 여부
$LastExitCode = 0  # 마지막 종료 코드
$Error = @()  # 오류 배열
```

---

## 3. 연산자

### 3.1 산술 연산자
```psp
int $a = 10
int $b = 3

$sum = $a + $b      # 덧셈
$diff = $a - $b     # 뺄셈
$mult = $a * $b     # 곱셈
$div = $a / $b      # 나눗셈
$mod = $a % $b      # 나머지
```

### 3.2 비교 연산자 (PowerShell 스타일)
```psp
# 대소문자 구분하지 않는 비교
$a -eq $b    # 같음
$a -ne $b    # 다름
$a -lt $b    # 작음
$a -le $b    # 작거나 같음
$a -gt $b    # 큼
$a -ge $b    # 크거나 같음

# 대소문자 구분하는 비교
$a -ceq $b   # 대소문자 구분 같음
$a -cne $b   # 대소문자 구분 다름

# 패턴 매칭
$text -like "*pattern*"      # 와일드카드 매칭
$text -match "regex"         # 정규식 매칭
$text -contains "substring"  # 포함 여부
```

### 3.3 논리 연산자
```psp
$condition1 -and $condition2   # AND
$condition1 -or $condition2    # OR
-not $condition                # NOT
!$condition                    # NOT (단축형)
```

---

## 4. 제어 구조

### 4.1 조건문
```psp
# if-elseif-else (PowerShell + C언어 혼합)
if ($port -eq 80) {
    Write-Output "HTTP 포트"
} elseif ($port -eq 443) {
    Write-Output "HTTPS 포트"
} else {
    Write-Output "기타 포트: $port"
}

# Python 스타일도 지원
if ($status -eq "success"):
    Write-Host "성공!" -ForegroundColor Green
elif ($status -eq "warning"):
    Write-Host "경고!" -ForegroundColor Yellow
else:
    Write-Host "실패!" -ForegroundColor Red
```

### 4.2 switch 문 (PowerShell 스타일)
```psp
switch ($port) {
    80 { Write-Output "HTTP 서비스" }
    443 { Write-Output "HTTPS 서비스" }
    22 { Write-Output "SSH 서비스" }
    21 { Write-Output "FTP 서비스" }
    default { Write-Output "알 수 없는 서비스" }
}
```

### 4.3 반복문

#### foreach 루프 (PowerShell 스타일)
```psp
# 배열 순회
array $servers = @("web1", "web2", "db1")
foreach ($server in $servers) {
    Write-Output "서버 확인: $server"
    Test-NetConnection $server
}

# 범위 순회
foreach ($i in 1..10) {
    Write-Output "카운트: $i"
}
```

#### for 루프 (C언어 스타일)
```psp
for (int $i = 1; $i -le 10; $i++) {
    Write-Output "반복: $i"
}
```

#### while 루프
```psp
int $counter = 0
while ($counter -lt 5) {
    Write-Output "카운터: $counter"
    $counter++
}
```

#### do-while 루프
```psp
int $attempts = 0
do {
    Write-Output "시도: $($attempts + 1)"
    $attempts++
} while ($attempts -lt 3)
```

---

## 5. 함수와 cmdlet

### 5.1 PowerShell 스타일 cmdlet
```psp
# 기본 cmdlet 호출
Get-ProcessList
Test-NetConnection "google.com" -Port 80
Write-Host "메시지" -ForegroundColor Red

# 파라미터가 있는 cmdlet
Invoke-PortScan "192.168.1.1" -Port @(80, 443, 22)
ConvertTo-MD5Hash "password123"
```

### 5.2 C언어 스타일 함수 정의
```psp
# 반환 타입이 있는 함수
int Calculate-Sum(int $a, int $b) {
    return $a + $b
}

# void 함수
void Print-Banner(string $message) {
    Write-Host "=" * 50
    Write-Host $message -ForegroundColor Cyan
    Write-Host "=" * 50
}

# 복합 타입 반환
hashtable Get-ServerInfo(string $hostname) {
    hashtable $info = @{
        Name = $hostname
        Status = "Online"
        LastCheck = Get-Date
    }
    return $info
}
```

### 5.3 고급 함수 기능
```psp
# 기본값이 있는 매개변수
string Test-Connection(string $host = "localhost", int $port = 80) {
    # 함수 구현
    return "Connected to $host:$port"
}

# 가변 매개변수
void Log-Messages(params string[] $messages) {
    foreach ($msg in $messages) {
        Write-Output "[$(Get-Date)] $msg"
    }
}

# 호출 예시
Log-Messages "시작", "진행중", "완료"
```

---

## 6. 파이프라인 (PowerShell의 핵심 기능)

### 6.1 기본 파이프라인
```psp
# 객체 파이프라인
Get-ProcessList | Where-Object { $_.Name -like "*chrome*" } | Select-Object Name, PID

# 문자열 파이프라인
"192.168.1.1" | Test-NetConnection -Port 80 | Out-Host

# 배열 파이프라인
@(80, 443, 22) | ForEach-Object { Test-NetConnection "google.com" -Port $_ }
```

### 6.2 파이프라인 필터링
```psp
# Where-Object로 필터링
Get-ProcessList | Where-Object { $_.CPU -gt 50 }

# Select-Object로 속성 선택
Get-ServiceList | Select-Object Name, Status, StartType

# Sort-Object로 정렬
Get-ProcessList | Sort-Object CPU -Descending

# Group-Object로 그룹화
Get-ProcessList | Group-Object Status
```

### 6.3 고급 파이프라인 연산
```psp
# 체이닝된 파이프라인
Get-ProcessList | 
    Where-Object { $_.Name -notlike "*system*" } |
    Sort-Object CPU -Descending |
    Select-Object -First 10 |
    ForEach-Object { 
        Write-Host "$($_.Name): $($_.CPU)%" -ForegroundColor Yellow 
    }
```

---

## 7. 객체 지향 프로그래밍

### 7.1 구조체 정의 (C언어 스타일)
```psp
struct NetworkTarget {
    string $Host;
    int $Port;
    bool $IsAlive;
    hashtable $Services;
    
    # 메서드 정의
    void Test-Connectivity() {
        $this.IsAlive = Test-NetConnection $this.Host -Port $this.Port
    }
}
```

### 7.2 클래스 정의 (PowerShell + C언어 혼합)
```psp
class SecurityScanner {
    # 멤버 변수
    private string $target
    private array $ports
    protected hashtable $results
    
    # 생성자
    SecurityScanner(string $hostname) {
        $this.target = $hostname
        $this.ports = @(80, 443, 22, 21)
        $this.results = @{}
    }
    
    # 공개 메서드
    public hashtable Start-Scan() {
        Write-Host "스캔 시작: $($this.target)"
        
        foreach ($port in $this.ports) {
            $this.results[$port] = $this.Test-Port($port)
        }
        
        return $this.results
    }
    
    # 비공개 메서드
    private bool Test-Port(int $port) {
        hashtable $result = Test-NetConnection $this.target -Port $port
        return $result.TcpTestSucceeded
    }
    
    # 정적 메서드
    static bool Is-ValidIP(string $ip) {
        return $ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    }
}
```

### 7.3 상속
```psp
class AdvancedScanner : SecurityScanner {
    private bool $verboseMode
    
    # 부모 생성자 호출
    AdvancedScanner(string $hostname, bool $verbose) : base($hostname) {
        $this.verboseMode = $verbose
    }
    
    # 메서드 오버라이드
    override public hashtable Start-Scan() {
        if ($this.verboseMode) {
            Write-Host "고급 스캔 모드 활성화"
        }
        
        # 부모 메서드 호출
        hashtable $baseResults = base.Start-Scan()
        
        # 추가 기능
        $this.Perform-VulnerabilityCheck()
        
        return $baseResults
    }
    
    private void Perform-VulnerabilityCheck() {
        Write-Host "취약점 검사 수행 중..."
    }
}
```

---

## 8. 예외 처리

### 8.1 try-catch-finally (PowerShell 스타일)
```psp
try {
    hashtable $result = Test-NetConnection "invalid-host.com"
    Write-Output "연결 성공"
} catch [System.Net.NetworkException] {
    Write-Error "네트워크 오류: $($_.Exception.Message)"
} catch {
    Write-Error "알 수 없는 오류: $($_.Exception.Message)"
} finally {
    Write-Output "정리 작업 수행"
}
```

### 8.2 사용자 정의 예외
```psp
class SecurityException : Exception {
    string $SecurityCode
    
    SecurityException(string $message, string $code) : base($message) {
        $this.SecurityCode = $code
    }
}

# 예외 던지기
if ($port -eq 0) {
    throw [SecurityException]::new("잘못된 포트", "SEC001")
}
```

---

## 9. 모듈과 네임스페이스

### 9.1 모듈 정의
```psp
# NetworkUtils.pspm 모듈 파일
module NetworkUtils {
    
    export function Test-MultipleHosts(array $hosts) {
        foreach ($host in $hosts) {
            Test-NetConnection $host
        }
    }
    
    export class PortScanner {
        # 클래스 구현
    }
    
    # 비공개 함수 (export하지 않음)
    function Internal-Helper() {
        # 내부 구현
    }
}
```

### 9.2 모듈 사용
```psp
# 모듈 임포트
Import-Module "./NetworkUtils.pspm"
using module NetworkUtils

# 네임스페이스 사용
NetworkUtils.Test-MultipleHosts @("google.com", "github.com")

# 클래스 사용
$scanner = [NetworkUtils.PortScanner]::new("192.168.1.1")
```

---

## 10. 보안 특화 기능

### 10.1 내장 보안 cmdlet
```psp
# 네트워크 보안
Invoke-PortScan "target.com" -Port @(80, 443, 22)
Test-SQLInjection -Url "http://target.com/search" -Parameter "q"
Start-PacketCapture -Interface "eth0" -Duration 60

# 암호화/해싱
ConvertTo-MD5Hash "password123"
ConvertTo-SHA256Hash "sensitive_data"
New-RSAKeyPair -KeySize 2048
Protect-Data "secret" -Key "encryption_key"

# 시스템 보안
Get-ProcessList | Where-Object { $_.Name -like "*malware*" }
Find-SensitiveFiles -Path "C:\" -Pattern "*.config"
Invoke-MemoryDump -ProcessId 1234

# 웹 보안
Test-WebVulnerabilities "http://target.com"
Invoke-DirectoryBruteforce "http://target.com" -Wordlist @("admin", "backup")
```

### 10.2 보안 파이프라인 예제
```psp
# 종합 보안 스캔 파이프라인
"192.168.1.0/24" | 
    Discover-Hosts |
    Where-Object { $_.IsAlive } |
    ForEach-Object { 
        Invoke-PortScan $_.IP -Port @(80, 443, 22, 21) 
    } |
    Where-Object { $_.OpenPorts.Count -gt 0 } |
    ForEach-Object {
        Test-ServiceVulnerabilities $_.IP $_.OpenPorts
    } |
    Export-SecurityReport -Format "JSON"
```

---

## 11. 고급 기능

### 11.1 비동기 프로그래밍 (PowerShell Jobs)
```psp
# 백그라운드 작업
$job = Start-Job -ScriptBlock {
    Invoke-PortScan "192.168.1.1" -Port @(1..1000)
}

# 작업 상태 확인
Get-Job $job

# 결과 수신
$results = Receive-Job $job -Wait
```

### 11.2 정규식 연산자
```psp
# 정규식 매칭
string $text = "IP: 192.168.1.100"
if ($text -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
    Write-Output "IP 주소 발견: $($Matches[0])"
}

# 정규식 치환
string $cleaned = $text -replace "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "XXX.XXX.XXX.XXX"
```

### 11.3 문자열 보간 및 여기 문자열
```psp
# 문자열 보간
string $host = "example.com"
int $port = 80
string $message = "연결 대상: ${host}:${port}"

# 여기 문자열 (Here-String)
string $report = @"
보안 스캔 보고서
================
대상: $host
포트: $port
시간: $(Get-Date)
"@
```

---

## 12. 실제 사용 예제

### 12.1 종합 네트워크 스캔
```psp
# 대상 네트워크 정의
string $network = "192.168.1.0/24"
array $ports = @(21, 22, 23, 25, 53, 80, 135, 139, 443, 445)

# 호스트 발견
Write-Host "호스트 발견 중..." -ForegroundColor Yellow
array $aliveHosts = Discover-Hosts $network

# 포트 스캔
Write-Host "포트 스캔 중..." -ForegroundColor Yellow
hashtable $scanResults = @{}

foreach ($host in $aliveHosts) {
    $scanResults[$host] = Invoke-PortScan $host -Port $ports
}

# 취약점 테스트
Write-Host "취약점 테스트 중..." -ForegroundColor Yellow
foreach ($host in $scanResults.Keys) {
    array $openPorts = $scanResults[$host] | Where-Object { $_.Status -eq "Open" }
    
    foreach ($portInfo in $openPorts) {
        switch ($portInfo.Port) {
            80 { 
                Test-WebVulnerabilities "http://${host}"
            }
            22 { 
                Test-SSHConfiguration $host
            }
            21 { 
                Test-FTPAnonymous $host
            }
        }
    }
}
```

### 12.2 웹 애플리케이션 보안 테스트
```psp
# 웹 애플리케이션 스캔 클래스
class WebSecurityScanner {
    private string $baseUrl
    private array $vulnerabilities
    
    WebSecurityScanner(string $url) {
        $this.baseUrl = $url
        $this.vulnerabilities = @()
    }
    
    public hashtable Start-FullScan() {
        $this.Test-SQLInjection()
        $this.Test-XSS()
        $this.Test-DirectoryTraversal()
        $this.Check-SecurityHeaders()
        
        return @{
            Target = $this.baseUrl
            Vulnerabilities = $this.vulnerabilities
            Score = $this.Calculate-SecurityScore()
        }
    }
    
    private void Test-SQLInjection() {
        array $payloads = @("'", "' OR 1=1 --", "'; DROP TABLE users; --")
        
        foreach ($payload in $payloads) {
            hashtable $result = Test-SQLInjection -Url "$($this.baseUrl)/search" -Parameter "q" -Payload $payload
            
            if ($result.Vulnerable) {
                $this.vulnerabilities += @{
                    Type = "SQL Injection"
                    Severity = "High"
                    Payload = $payload
                    URL = "$($this.baseUrl)/search"
                }
            }
        }
    }
    
    private int Calculate-SecurityScore() {
        int $baseScore = 100
        foreach ($vuln in $this.vulnerabilities) {
            switch ($vuln.Severity) {
                "Critical" { $baseScore -= 30 }
                "High" { $baseScore -= 20 }
                "Medium" { $baseScore -= 10 }
                "Low" { $baseScore -= 5 }
            }
        }
        return [Math]::Max(0, $baseScore)
    }
}

# 스캐너 사용
$scanner = [WebSecurityScanner]::new("http://testphp.vulnweb.com")
hashtable $report = $scanner.Start-FullScan()

Write-Output "보안 점수: $($report.Score)/100"
Write-Output "발견된 취약점: $($report.Vulnerabilities.Count)개"
```

---

이 문법 가이드는 PSP (PowerShellPlus) 언어의 모든 핵심 기능을 다루며, PowerShell의 강력함과 C언어의 정확성, Python의 간결함을 결합한 혁신적인 보안 프로그래밍 언어의 완전한 사용법을 제공합니다.
