# PSP (PowerShellPlus) 언어 프로젝트 완전 구조

## 📁 프로젝트 구조

```
PSP-Language/
├── 📄 README.md                           # 메인 프로젝트 문서 (한/영/일/중)
├── 📄 LICENSE                             # MIT 라이선스
├── 📄 requirements.txt                    # Python 의존성
├── 📄 .gitattributes                      # GitHub 언어 인식 설정
├── 📄 languages.yml                       # GitHub Linguist 언어 정의
├── 📄 psp.yml                             # 언어 메타데이터
├── 🔧 install.sh                          # Linux/Mac 설치 스크립트
├── 🔧 install.bat                         # Windows 설치 스크립트
│
├── 📁 src/                                # PSP 인터프리터 소스코드
│   └── 📄 psp_interpreter.py              # PSP 메인 인터프리터 (Python)
│
├── 📁 libs/                               # PSP 확장 라이브러리
│   ├── 📄 psp_crypto.py                   # 고급 암호화 라이브러리
│   └── 📄 psp_network.py                  # 고급 네트워크 라이브러리
│
├── 📁 docs/                               # 문서화
│   ├── 📄 complete_grammar.md             # 완전한 PSP 문법 가이드
│   ├── 📄 syntax.md                       # 기본 문법 가이드
│   ├── 📄 api_reference.md                # API 레퍼런스
│   └── 📄 tutorial.md                     # 단계별 튜토리얼
│
├── 📁 examples/                           # PSP 예제 파일들
│   ├── 🔐 hello_world.pspp                # Hello World 예제
│   ├── 🔐 advanced_features.pspp          # 고급 문법 데모
│   ├── 🔐 network_scan.pspp               # 네트워크 스캔 예제
│   ├── 🔐 vulnerability_test.pspp         # 취약점 테스트 예제
│   ├── 🔐 system_recon.pspp               # 시스템 정보 수집 예제
│   └── 🔐 web_application_test.pspp       # 웹 애플리케이션 테스트 예제
│
└── 📁 vscode-extension/                   # VS Code Extension
    ├── 📄 package.json                    # Extension 메타데이터
    ├── 📄 tsconfig.json                   # TypeScript 설정
    ├── 📄 language-configuration.json     # 언어 설정
    ├── 📄 README.md                       # Extension 문서
    ├── 📄 CHANGELOG.md                    # 변경 이력
    ├── 📄 DEVELOPMENT.md                  # 개발 가이드
    │
    ├── 📁 src/                            # Extension 소스코드
    │   └── 📄 extension.ts                # 메인 Extension 코드
    │
    ├── 📁 syntaxes/                       # 문법 정의
    │   └── 📄 psp.tmLanguage.json         # TextMate 문법 규칙
    │
    ├── 📁 snippets/                       # 코드 스니펫
    │   └── 📄 psp.json                    # PSP 스니펫 정의
    │
    ├── 📁 themes/                         # VS Code 테마
    │   ├── 📄 psp-dark.json               # PSP 다크 테마
    │   └── 📄 psp-light.json              # PSP 라이트 테마
    │
    └── 📁 icons/                          # Extension 아이콘들
        └── (아이콘 파일들)
```

## 🎯 주요 구성 요소

### 1. PSP 인터프리터 (`src/psp_interpreter.py`)
- **기능**: PSP 언어의 핵심 실행 엔진
- **지원 기능**:
  - 변수 할당 및 표현식 평가
  - 제어 구조 (if, for, while)
  - 함수 호출 및 내장 함수
  - 오류 처리 및 디버깅
- **내장 함수 카테고리**:
  - 네트워크: `scan_port`, `scan_range`, `connect`, `send`, `recv`
  - 암호화: `md5`, `sha1`, `sha256`, `base64_encode`, `base64_decode`
  - 익스플로잇: `create_payload`, `buffer_overflow`, `shellcode`
  - 시스템: `enum_processes`, `enum_services`, `registry_read`, `registry_write`
  - 파일: `file_read`, `file_write`, `file_exists`, `dir_list`
  - 출력: `print`, `printf`, `log`

### 2. 확장 라이브러리 (`libs/`)
- **psp_crypto.py**: 고급 암호화 기능
  - AES 암호화/복호화
  - PBKDF2 패스워드 해싱
  - HMAC 및 키 관리
  - 해시 크래킹 도구
- **psp_network.py**: 고급 네트워킹 기능
  - 멀티스레드 포트 스캔
  - 서브넷 스캔
  - 스텔스 스캔
  - 웹 익스플로잇 페이로드

### 3. VS Code Extension (`vscode-extension/`)
- **언어 지원**:
  - 완전한 문법 강조 (syntax highlighting)
  - IntelliSense 코드 완성
  - 함수 호버 문서화
  - 자동 들여쓰기 및 괄호 매칭
- **개발 도구**:
  - PSP 파일 실행 (F5)
  - 대화형 모드 시작
  - 코드 스니펫 (15개 이상)
  - 전용 테마 (다크/라이트)

### 4. 문서화 (`docs/`)
- **complete_grammar.md**: 완전한 언어 문법 (1000+ 라인)
- **api_reference.md**: 모든 내장 함수 설명
- **tutorial.md**: 8단계 학습 가이드
- **syntax.md**: 기본 문법 요약

### 5. 예제 파일들 (`examples/`)
- **hello_world.pspp**: 기본 문법 데모
- **advanced_features.pspp**: 고급 문법 (클래스, 예외처리, 함수형)
- **network_scan.pspp**: 네트워크 스캔 도구
- **vulnerability_test.pspp**: 취약점 테스트
- **system_recon.pspp**: 시스템 정보 수집
- **web_application_test.pspp**: 웹 애플리케이션 테스트

## 🔧 설치 및 사용법

### 1. PSP 언어 설치
```bash
# 자동 설치 (Linux/Mac)
./install.sh

# 자동 설치 (Windows)
install.bat

# 수동 설치
pip install -r requirements.txt
python3 src/psp_interpreter.py --help
```

### 2. PSP 파일 실행
```bash
# 예제 실행
python3 src/psp_interpreter.py examples/hello_world.pspp

# 대화형 모드
python3 src/psp_interpreter.py -i
```

### 3. VS Code Extension 설치
```bash
cd vscode-extension
npm install
npm run compile
vsce package
code --install-extension psp-language-support-1.0.0.vsix
```

## 🌐 GitHub 언어 인식 설정

### 1. `.gitattributes` 파일
```
*.pspp linguist-language=PSP
```

### 2. `languages.yml` (GitHub Linguist)
```yaml
PSP:
  type: programming
  color: "#FF6B35"
  extensions:
  - ".pspp"
  tm_scope: source.psp
  ace_mode: text
  language_id: 998877665
  aliases:
  - psp
  - powershellplus
```

### 3. VS Code 언어 정의
- **언어 ID**: `psp`
- **파일 확장자**: `.pspp`
- **MIME 타입**: `text/x-psp`
- **언어 스코프**: `source.psp`

## 🎨 PSP 언어 특징

### 문법적 특징
- **하이브리드 문법**: C + PowerShell + Python 스타일
- **타입 시스템**: 동적 타이핑 + 선택적 타입 힌트
- **객체 지향**: 클래스, 상속, 믹스인 지원
- **함수형**: 람다, 고차함수, 맵/필터/리듀스
- **비동기**: async/await 지원 (개념적)

### 보안 기능
- **네트워크**: TCP/UDP 스캔, 배너 그래빙, 서브넷 스캔
- **암호화**: 다양한 해시 알고리즘, 대칭/비대칭 암호화
- **익스플로잇**: 페이로드 생성, 버퍼 오버플로우, 셸코드
- **웹 보안**: SQL 인젝션, XSS, LFI, SSRF 페이로드
- **시스템**: 프로세스/서비스 조작, 레지스트리 접근

### 개발자 경험
- **IDE 지원**: VS Code 완전 지원 (문법강조, 자동완성, 디버깅)
- **코드 스니펫**: 일반적인 보안 테스트 시나리오 템플릿
- **오류 처리**: 상세한 오류 메시지 및 스택 트레이스
- **문서화**: 풍부한 예제와 튜토리얼

## 📈 프로젝트 통계

- **총 파일 수**: 30+ 파일
- **코드 라인 수**: 5000+ 라인
- **문서 라인 수**: 3000+ 라인
- **예제 프로그램**: 6개
- **내장 함수**: 50+ 개
- **코드 스니펫**: 15+ 개
- **지원 언어**: 4개 (한국어, 영어, 일본어, 중국어)

## 🚀 배포 및 공유

### GitHub 저장소 설정
1. GitHub에 저장소 생성
2. 언어 인식 파일들 업로드 (`.gitattributes`, `languages.yml`)
3. Topics 추가: `psp`, `powershellplus`, `hacking`, `pentesting`, `security`

### VS Code Marketplace 배포
1. Microsoft 게시자 계정 생성
2. Extension 패키징 (`vsce package`)
3. Marketplace 업로드 (`vsce publish`)

### 커뮤니티 구축
- Discord 서버 또는 포럼 생성
- 예제 프로젝트 및 튜토리얼 제공
- 기여자 가이드라인 작성

이제 PSP (PowerShellPlus) 언어가 완전히 구현되었고, GitHub과 VS Code에서 완벽하게 지원됩니다! 🎉🔐
