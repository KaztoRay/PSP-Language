# PSP (PowerShell Plus) 프로그래밍 언어 완전 가이드

## 개요

PSP는 PowerShell, C언어, Python의 장점을 결합한 보안 테스트 및 시스템 관리 전용 프로그래밍 언어입니다.

## 언어 특징

- **PowerShell 스타일 cmdlet**: 직관적이고 강력한 명령어 시스템
- **C언어 스타일 타입**: 명시적 타입 선언으로 안전성 향상
- **Python 스타일 간결함**: 읽기 쉽고 작성하기 쉬운 문법
- **보안 특화**: 네트워크 스캔, 취약점 테스트, 포렌식 도구 내장

## 1. 기본 문법

### 1.1 주석
```psp
# 한 줄 주석
/* 
   여러 줄 주석
   블록 주석
*/
```

### 1.2 변수 선언 및 타입
```psp
# 기본 타입
String $name = "PSP Language"
Int32 $port = 80
Int64 $bigNumber = 9223372036854775807
Double $pi = 3.14159
Boolean $isSecure = $true
Byte $value = 255

# 배열
Array[String] $targets = @("192.168.1.1", "192.168.1.2")
Array[Int32] $ports = @(80, 443, 22, 21)

# 해시테이블 (딕셔너리)
Hashtable $config = @{
    Host = "localhost"
    Port = 8080
    SSL = $true
}
```

### 1.3 변수 참조
```psp
# PowerShell 스타일 변수 참조
Write-Output "대상: $target"
Write-Output "포트: $($config.Port)"

# 배열 접근
$firstTarget = $targets[0]
$lastPort = $ports[-1]

# 해시테이블 접근
$hostName = $config.Host
$sslEnabled = $config["SSL"]
```

## 2. 제어 구조

### 2.1 조건문
```psp
# if-else (C언어 스타일)
if ($port -eq 80) {
    Write-Output "HTTP 포트입니다"
} elseif ($port -eq 443) {
    Write-Output "HTTPS 포트입니다"
} else {
    Write-Output "기타 포트입니다"
}

# 비교 연산자
# -eq (같음), -ne (다름), -lt (작음), -le (작거나 같음)
# -gt (큼), -ge (크거나 같음), -like (패턴 매칭), -match (정규식)
```

### 2.2 반복문
```psp
# for 루프
for ($i = 0; $i -lt $ports.Length; $i++) {
    Write-Output "포트: $($ports[$i])"
}

# foreach 루프
foreach ($target in $targets) {
    Test-NetConnection -ComputerName $target
}

# while 루프
while ($running -eq $true) {
    $result = Get-UserInput
    if ($result -eq "exit") {
        $running = $false
    }
}
```

### 2.3 예외 처리
```psp
try {
    Test-NetConnection -ComputerName $target -Port $port
} catch [System.Net.NetworkException] {
    Write-Error "네트워크 연결 실패: $($_.Exception.Message)"
} catch {
    Write-Error "알 수 없는 오류: $($_.Exception.Message)"
} finally {
    Write-Output "연결 테스트 완료"
}
```

## 3. 함수 및 cmdlet

### 3.1 함수 정의
```psp
function Scan-Port {
    param(
        [String] $Target,
        [Int32] $Port,
        [Int32] $Timeout = 1000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $result = $tcpClient.ConnectAsync($Target, $Port).Wait($Timeout)
        $tcpClient.Close()
        return $result
    } catch {
        return $false
    }
}
```

### 3.2 고급 함수 (cmdlet 스타일)
```psp
[CmdletBinding()]
function Invoke-NetworkScan {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Target,
        
        [Parameter()]
        [Int32[]] $Ports = @(80, 443, 22, 21, 25, 53),
        
        [Parameter()]
        [Switch] $Verbose
    )
    
    begin {
        Write-Verbose "스캔 시작: $Target"
        $results = @()
    }
    
    process {
        foreach ($port in $Ports) {
            $isOpen = Scan-Port -Target $Target -Port $port
            $results += [PSCustomObject]@{
                Port = $port
                Status = if ($isOpen) { "Open" } else { "Closed" }
                Service = Get-ServiceName -Port $port
            }
        }
    }
    
    end {
        return $results
    }
}
```

## 4. 파이프라인

### 4.1 기본 파이프라인
```psp
# 객체 파이프라인 (PowerShell 스타일)
Get-Process | Where-Object { $_.CPU -gt 50 } | Sort-Object CPU -Descending

# 데이터 변환
$openPorts | Where-Object { $_.Status -eq "Open" } | Select-Object Port, Service

# 그룹화 및 집계
Get-EventLog | Group-Object Level | Sort-Object Count -Descending
```

### 4.2 고급 파이프라인
```psp
# 복합 파이프라인
Get-ChildItem "C:\Windows\System32\*.exe" |
    Where-Object { $_.Length -gt 1MB } |
    Sort-Object Length -Descending |
    Select-Object Name, Length, CreationTime |
    Export-Csv "large_files.csv"
```

## 5. 내장 cmdlet

### 5.1 출력 cmdlet
```psp
Write-Output "일반 출력"
Write-Host "콘솔 출력" -ForegroundColor Green
Write-Error "오류 메시지"
Write-Warning "경고 메시지"
Write-Verbose "상세 정보" -Verbose
Write-Debug "디버그 정보" -Debug
```

### 5.2 네트워크 보안 cmdlet
```psp
# 네트워크 연결 테스트
Test-NetConnection -ComputerName "google.com" -Port 80

# 포트 스캔
Invoke-PortScan -Target "192.168.1.1" -StartPort 1 -EndPort 1000

# 서비스 배너 그래빙
Get-ServiceBanner -Target "192.168.1.1" -Port 80

# 네트워크 토폴로지 발견
Get-NetworkTopology -Subnet "192.168.1.0/24"

# 패킷 캡처
Start-PacketCapture -Interface "eth0" -Filter "tcp port 80"
```

### 5.3 웹 보안 cmdlet
```psp
# SQL 인젝션 테스트
Test-SQLInjection -Url "http://example.com/login" -Parameter "username"

# XSS 테스트
Test-XSS -Url "http://example.com/search" -Parameter "query"

# 웹 취약점 스캔
Invoke-WebScan -Target "http://example.com" -ScanType "Full"

# 디렉토리 부르트포스
Invoke-DirBuster -Target "http://example.com" -Wordlist "common.txt"
```

### 5.4 암호화/해싱 cmdlet
```psp
# 해시 생성
Get-Hash -InputString "password123" -Algorithm SHA256
ConvertTo-MD5Hash "data"
ConvertTo-SHA1Hash "data"

# 암호화/복호화
$encrypted = Protect-Data -PlainText "secret" -Key "mykey"
$decrypted = Unprotect-Data -EncryptedData $encrypted -Key "mykey"

# Base64 인코딩/디코딩
$encoded = ConvertTo-Base64 -InputString "hello world"
$decoded = ConvertFrom-Base64 -EncodedString $encoded

# 패스워드 생성
New-Password -Length 16 -IncludeSymbols
```

### 5.5 시스템 정보 cmdlet
```psp
# 프로세스 정보
Get-ProcessList | Where-Object { $_.Name -like "*chrome*" }

# 서비스 정보
Get-ServiceList | Where-Object { $_.Status -eq "Running" }

# 시스템 정보
Get-SystemInfo
Get-ComputerInfo

# 사용자 정보
Get-LocalUsers
Get-LoggedOnUsers

# 네트워크 정보
Get-NetworkAdapters
Get-NetworkConnections
```

### 5.6 파일 시스템 cmdlet
```psp
# 파일/폴더 작업
Test-Path "C:\Windows\System32\cmd.exe"
Get-Content "config.txt"
Set-Content "output.txt" -Value "Hello PSP"

# 디렉토리 탐색
Get-ChildItem "C:\Windows" -Recurse -Filter "*.exe"
Find-Files -Path "C:\" -Pattern "*.log" -Modified (Get-Date).AddDays(-7)

# 민감한 파일 찾기
Find-SensitiveFiles -Path "C:\Users" -FileTypes @("*.txt", "*.doc", "*.pdf")
```

## 6. 클래스 및 객체

### 6.1 클래스 정의
```psp
class NetworkScanner {
    [String] $Target
    [Array] $OpenPorts
    [Hashtable] $Results
    
    # 생성자
    NetworkScanner([String] $target) {
        $this.Target = $target
        $this.OpenPorts = @()
        $this.Results = @{}
    }
    
    # 메서드
    [Array] ScanPorts([Array] $ports) {
        foreach ($port in $ports) {
            if (Test-Port -Target $this.Target -Port $port) {
                $this.OpenPorts += $port
            }
        }
        return $this.OpenPorts
    }
    
    [String] GenerateReport() {
        $report = "스캔 대상: $($this.Target)`n"
        $report += "열린 포트: $($this.OpenPorts -join ', ')`n"
        return $report
    }
}
```

### 6.2 클래스 사용
```psp
# 객체 생성
$scanner = [NetworkScanner]::new("192.168.1.1")

# 메서드 호출
$openPorts = $scanner.ScanPorts(@(80, 443, 22, 21))
$report = $scanner.GenerateReport()

Write-Output $report
```

## 7. 모듈 및 라이브러리

### 7.1 모듈 정의
```psp
# SecurityTools.psm1
Export-ModuleMember -Function @(
    'Invoke-NetworkScan',
    'Test-SQLInjection',
    'Get-Hash'
)

function Invoke-NetworkScan {
    # 구현...
}

function Test-SQLInjection {
    # 구현...
}
```

### 7.2 모듈 사용
```psp
# 모듈 임포트
Import-Module SecurityTools

# 모듈 함수 사용
$results = Invoke-NetworkScan -Target "192.168.1.1"
```

## 8. 고급 기능

### 8.1 비동기 프로그래밍
```psp
# 비동기 작업
$job = Start-Job -ScriptBlock {
    Invoke-PortScan -Target "192.168.1.1" -StartPort 1 -EndPort 65535
}

# 진행 상황 확인
while ($job.State -eq "Running") {
    Write-Progress -Activity "포트 스캔 중..." -PercentComplete 50
    Start-Sleep 1
}

# 결과 수집
$results = Receive-Job $job
Remove-Job $job
```

### 8.2 이벤트 처리
```psp
# 이벤트 핸들러 등록
Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action {
    $path = $Event.SourceEventArgs.FullPath
    Write-Host "새 파일 생성: $path"
}
```

### 8.3 정규식
```psp
# 정규식 매칭
if ($email -match '^\w+@\w+\.\w+$') {
    Write-Output "유효한 이메일 주소"
}

# 정규식 캡처
$ip -match '(\d+)\.(\d+)\.(\d+)\.(\d+)'
$octets = $matches[1..4]
```

## 9. 보안 프로그래밍 패턴

### 9.1 안전한 네트워크 스캔
```psp
function Safe-NetworkScan {
    param(
        [String] $Target,
        [Int32] $MaxThreads = 10,
        [Int32] $Timeout = 1000
    )
    
    # 입력 검증
    if (-not ($Target -match '^\d+\.\d+\.\d+\.\d+$')) {
        throw "잘못된 IP 주소 형식"
    }
    
    # 스캔 실행
    # ...
}
```

### 9.2 로깅 및 감사
```psp
function Write-AuditLog {
    param(
        [String] $Action,
        [String] $Target,
        [String] $Result
    )
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        User = $env:USERNAME
        Action = $Action
        Target = $Target
        Result = $Result
    }
    
    $logEntry | ConvertTo-Json | Add-Content "audit.log"
}
```

## 10. 예제 및 실전 활용

### 10.1 네트워크 정찰
```psp
# 서브넷 스캔
$subnet = "192.168.1.0/24"
$liveHosts = Invoke-HostDiscovery -Subnet $subnet

foreach ($host in $liveHosts) {
    $openPorts = Invoke-PortScan -Target $host -Ports @(80, 443, 22, 21)
    Write-Output "호스트: $host, 열린 포트: $($openPorts -join ', ')"
}
```

### 10.2 웹 애플리케이션 테스트
```psp
# 종합 웹 보안 테스트
$target = "http://example.com"

# 1. 정보 수집
$serverInfo = Get-WebServerInfo -Url $target
$directories = Invoke-DirBuster -Target $target

# 2. 취약점 테스트
$sqlResults = Test-SQLInjection -Url $target
$xssResults = Test-XSS -Url $target
$csrfResults = Test-CSRF -Url $target

# 3. 보고서 생성
$report = Generate-SecurityReport -Target $target -Results @{
    ServerInfo = $serverInfo
    Directories = $directories
    SQLInjection = $sqlResults
    XSS = $xssResults
    CSRF = $csrfResults
}

Export-Report -Report $report -Format "HTML" -Path "security_report.html"
```

## 11. 디버깅 및 개발 도구

### 11.1 디버깅
```psp
# 중단점 설정
Set-PSBreakpoint -Line 10 -Script "script.pspp"

# 변수 감시
Watch-Variable -Name "target" -Action { Write-Host "target 변경됨: $target" }

# 스택 추적
Get-PSCallStack
```

### 11.2 성능 측정
```psp
# 실행 시간 측정
$time = Measure-Command {
    Invoke-PortScan -Target "192.168.1.1" -StartPort 1 -EndPort 1000
}
Write-Output "스캔 시간: $($time.TotalSeconds)초"
```

이 가이드는 PSP 언어의 모든 문법과 기능을 포괄적으로 다루고 있습니다. 다음 단계에서는 VS Code 확장프로그램과 GitHub 언어 인식을 위한 설정을 진행하겠습니다.
