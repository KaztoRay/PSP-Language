# PSP VS Code Extension 설치 가이드

## 개발 환경 설정

### 1. 필요한 도구 설치
```bash
# Node.js와 npm 설치 확인
node --version
npm --version

# VS Code Extension 개발 도구 설치
npm install -g vsce
npm install -g yo generator-code
```

### 2. Extension 의존성 설치
```bash
cd vscode-extension
npm install
```

### 3. Extension 컴파일
```bash
# TypeScript 컴파일
npm run compile

# 또는 watch 모드로 개발
npm run watch
```

## Extension 패키징 및 설치

### 1. VSIX 파일 생성
```bash
cd vscode-extension
vsce package
```

### 2. VS Code에 설치
```bash
# 명령어로 설치
code --install-extension psp-language-support-1.0.0.vsix

# 또는 VS Code에서
# Ctrl+Shift+P -> "Extensions: Install from VSIX..."
```

### 3. Extension 개발 모드 테스트
```bash
# VS Code Extension 개발 창 열기
# F5 키를 누르거나 "Run Extension" 디버그 구성 실행
```

## VS Code Marketplace 배포

### 1. 게시자 등록
```bash
# Microsoft 계정으로 Azure DevOps에 로그인
vsce login <publisher-name>
```

### 2. Extension 게시
```bash
vsce publish
```

### 3. 버전 업데이트
```bash
# 패치 버전 증가
vsce publish patch

# 마이너 버전 증가  
vsce publish minor

# 메이저 버전 증가
vsce publish major

# 특정 버전으로 게시
vsce publish 1.1.0
```

## 로컬 개발 및 테스트

### 1. Extension 개발 환경 실행
1. VS Code에서 `vscode-extension` 폴더 열기
2. F5 키 또는 "Run Extension" 디버그 구성 실행
3. 새로운 VS Code 창(Extension Development Host)이 열림
4. 새 창에서 .pspp 파일을 열어 테스트

### 2. 기능 테스트
- `.pspp` 파일 생성 및 syntax highlighting 확인
- 코드 완성 기능 테스트 (Ctrl+Space)
- 스니펫 기능 테스트 (예: `hello` + Tab)
- 명령어 실행 테스트 (F5로 PSP 파일 실행)
- 테마 적용 테스트

### 3. 디버깅
- `src/extension.ts`에 breakpoint 설정
- Extension Development Host에서 PSP 관련 작업 수행
- 디버그 콘솔에서 로그 확인

## 트러블슈팅

### 1. 컴파일 오류
```bash
# 의존성 재설치
rm -rf node_modules package-lock.json
npm install

# TypeScript 컴파일 확인
npx tsc --noEmit
```

### 2. Extension 로딩 실패
- `package.json`의 `activationEvents` 확인
- `contributes` 섹션의 언어 설정 확인
- 문법 파일 경로 확인

### 3. 문법 강조 문제
- `syntaxes/psp.tmLanguage.json` 문법 규칙 확인
- TextMate grammar 테스트 도구 사용
- VS Code Developer Tools로 토큰 분석

## Extension 구조

```
vscode-extension/
├── package.json              # Extension 메타데이터
├── tsconfig.json             # TypeScript 설정
├── src/
│   └── extension.ts          # Extension 메인 코드
├── syntaxes/
│   └── psp.tmLanguage.json   # 문법 정의
├── snippets/
│   └── psp.json              # 코드 스니펫
├── themes/
│   ├── psp-dark.json         # 다크 테마
│   └── psp-light.json        # 라이트 테마
├── icons/                    # 아이콘 파일들
├── language-configuration.json # 언어 설정
├── README.md                 # Extension 문서
└── CHANGELOG.md              # 변경 이력
```

## 개발 팁

### 1. 실시간 문법 테스트
- [TextMate Grammar Test](https://microsoft.github.io/monaco-editor/monarch.html) 사용
- VS Code의 "Developer: Inspect Editor Tokens and Scopes" 명령어 활용

### 2. 스니펫 개발
- [Snippet Generator](https://snippet-generator.app/) 도구 사용
- 탭 정렬과 placeholder 적극 활용

### 3. 테마 개발
- VS Code의 "Developer: Generate Color Theme From Current Settings" 사용
- 색상 접근성 고려 (대비비 확인)

### 4. 성능 최적화
- 큰 파일에서의 문법 강조 성능 확인
- 정규식 패턴 최적화
- 불필요한 activation events 제거
