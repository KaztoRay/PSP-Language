import * as vscode from 'vscode';
import * as path from 'path';
import { spawn } from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    console.log('PSP Language Support extension is now active!');

    // PSP 파일 실행 명령어
    const runFileDisposable = vscode.commands.registerCommand('psp.runFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.languageId === 'psp') {
            runPSPFile(editor.document.fileName);
        } else {
            vscode.window.showErrorMessage('Active file is not a PSP file (.pspp)');
        }
    });

    // PSP 대화형 모드 시작 명령어
    const runInteractiveDisposable = vscode.commands.registerCommand('psp.runInteractive', () => {
        startPSPInteractiveMode();
    });

    // 상태 표시줄 아이템
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = "$(play) PSP";
    statusBarItem.tooltip = "Run PSP File";
    statusBarItem.command = 'psp.runFile';
    
    // PSP 파일이 활성화되었을 때만 상태 표시줄 아이템 표시
    const updateStatusBar = () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.languageId === 'psp') {
            statusBarItem.show();
        } else {
            statusBarItem.hide();
        }
    };

    // 이벤트 리스너 등록
    vscode.window.onDidChangeActiveTextEditor(updateStatusBar);
    updateStatusBar();

    // 코드 완성 제공자
    const completionProvider = vscode.languages.registerCompletionItemProvider(
        'psp',
        new PSPCompletionItemProvider(),
        '.' // 점(.) 입력 시 자동완성 트리거
    );

    // 호버 정보 제공자
    const hoverProvider = vscode.languages.registerHoverProvider(
        'psp',
        new PSPHoverProvider()
    );

    context.subscriptions.push(
        runFileDisposable,
        runInteractiveDisposable,
        statusBarItem,
        completionProvider,
        hoverProvider
    );
}

export function deactivate() {
    console.log('PSP Language Support extension is now deactivated!');
}

async function runPSPFile(filePath: string) {
    const config = vscode.workspace.getConfiguration('psp');
    const interpreterPath = config.get<string>('interpreterPath', 'python3');
    const scriptPath = config.get<string>('scriptPath', '');
    
    let pspInterpreterPath: string;
    
    if (scriptPath) {
        pspInterpreterPath = scriptPath;
    } else {
        // 현재 워크스페이스에서 psp_interpreter.py 찾기
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(filePath));
        if (workspaceFolder) {
            pspInterpreterPath = path.join(workspaceFolder.uri.fsPath, 'src', 'psp_interpreter.py');
        } else {
            vscode.window.showErrorMessage('PSP interpreter path not configured. Please set psp.scriptPath in settings.');
            return;
        }
    }

    // 터미널에서 PSP 파일 실행
    const terminal = vscode.window.createTerminal('PSP');
    terminal.show();
    terminal.sendText(`${interpreterPath} "${pspInterpreterPath}" "${filePath}"`);
}

async function startPSPInteractiveMode() {
    const config = vscode.workspace.getConfiguration('psp');
    const interpreterPath = config.get<string>('interpreterPath', 'python3');
    const scriptPath = config.get<string>('scriptPath', '');
    
    let pspInterpreterPath: string;
    
    if (scriptPath) {
        pspInterpreterPath = scriptPath;
    } else {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            pspInterpreterPath = path.join(workspaceFolders[0].uri.fsPath, 'src', 'psp_interpreter.py');
        } else {
            vscode.window.showErrorMessage('PSP interpreter path not configured. Please set psp.scriptPath in settings.');
            return;
        }
    }

    // 터미널에서 PSP 대화형 모드 시작
    const terminal = vscode.window.createTerminal('PSP Interactive');
    terminal.show();
    terminal.sendText(`${interpreterPath} "${pspInterpreterPath}" -i`);
}

class PSPCompletionItemProvider implements vscode.CompletionItemProvider {
    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): vscode.ProviderResult<vscode.CompletionItem[] | vscode.CompletionList> {
        
        const completionItems: vscode.CompletionItem[] = [];

        // 네트워크 함수들
        const networkFunctions = [
            { name: 'scan_port', detail: 'scan_port(host, port)', documentation: 'TCP 포트를 스캔합니다.' },
            { name: 'scan_range', detail: 'scan_range(host, start_port, end_port)', documentation: '포트 범위를 스캔합니다.' },
            { name: 'connect', detail: 'connect(host, port)', documentation: 'TCP 연결을 시도합니다.' },
            { name: 'send', detail: 'send(host, port, data)', documentation: '데이터를 전송합니다.' },
            { name: 'recv', detail: 'recv(host, port, size)', documentation: '데이터를 수신합니다.' }
        ];

        // 암호화 함수들
        const cryptoFunctions = [
            { name: 'md5', detail: 'md5(data)', documentation: 'MD5 해시를 계산합니다.' },
            { name: 'sha1', detail: 'sha1(data)', documentation: 'SHA1 해시를 계산합니다.' },
            { name: 'sha256', detail: 'sha256(data)', documentation: 'SHA256 해시를 계산합니다.' },
            { name: 'base64_encode', detail: 'base64_encode(data)', documentation: 'Base64로 인코딩합니다.' },
            { name: 'base64_decode', detail: 'base64_decode(data)', documentation: 'Base64를 디코딩합니다.' }
        ];

        // 익스플로잇 함수들
        const exploitFunctions = [
            { name: 'create_payload', detail: 'create_payload(type, target)', documentation: '페이로드를 생성합니다.' },
            { name: 'buffer_overflow', detail: 'buffer_overflow(size, pattern)', documentation: '버퍼 오버플로우 패턴을 생성합니다.' },
            { name: 'shellcode', detail: 'shellcode(arch)', documentation: '셸코드를 생성합니다.' }
        ];

        // 시스템 함수들
        const systemFunctions = [
            { name: 'enum_processes', detail: 'enum_processes()', documentation: '실행 중인 프로세스를 열거합니다.' },
            { name: 'enum_services', detail: 'enum_services()', documentation: '윈도우 서비스를 열거합니다.' },
            { name: 'registry_read', detail: 'registry_read(key, value)', documentation: '레지스트리 값을 읽습니다.' },
            { name: 'registry_write', detail: 'registry_write(key, value, data)', documentation: '레지스트리 값을 씁니다.' }
        ];

        // 파일 함수들
        const fileFunctions = [
            { name: 'file_read', detail: 'file_read(path)', documentation: '파일을 읽습니다.' },
            { name: 'file_write', detail: 'file_write(path, content)', documentation: '파일을 씁니다.' },
            { name: 'file_exists', detail: 'file_exists(path)', documentation: '파일 존재 여부를 확인합니다.' },
            { name: 'dir_list', detail: 'dir_list(path)', documentation: '디렉터리 내용을 나열합니다.' }
        ];

        // 출력 함수들
        const outputFunctions = [
            { name: 'print', detail: 'print(message)', documentation: '메시지를 출력합니다.' },
            { name: 'printf', detail: 'printf(format, args)', documentation: '포맷된 메시지를 출력합니다.' },
            { name: 'log', detail: 'log(message, level)', documentation: '로그 메시지를 출력합니다.' }
        ];

        // 모든 함수들을 completion items로 변환
        const allFunctions = [
            ...networkFunctions,
            ...cryptoFunctions,
            ...exploitFunctions,
            ...systemFunctions,
            ...fileFunctions,
            ...outputFunctions
        ];

        allFunctions.forEach(func => {
            const item = new vscode.CompletionItem(func.name, vscode.CompletionItemKind.Function);
            item.detail = func.detail;
            item.documentation = new vscode.MarkdownString(func.documentation);
            item.insertText = new vscode.SnippetString(func.name + '($1)');
            completionItems.push(item);
        });

        // 키워드들
        const keywords = [
            'function', 'class', 'if', 'else', 'elseif', 'for', 'while', 'do',
            'switch', 'case', 'default', 'break', 'continue', 'return',
            'try', 'catch', 'finally', 'throw', 'true', 'false', 'null'
        ];

        keywords.forEach(keyword => {
            const item = new vscode.CompletionItem(keyword, vscode.CompletionItemKind.Keyword);
            completionItems.push(item);
        });

        return completionItems;
    }
}

class PSPHoverProvider implements vscode.HoverProvider {
    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        
        const range = document.getWordRangeAtPosition(position);
        const word = document.getText(range);

        // 함수 설명 매핑
        const functionDescriptions: { [key: string]: string } = {
            'scan_port': '**scan_port**(host: string, port: int) -> bool\n\nTCP 포트를 스캔하여 열려있는지 확인합니다.',
            'scan_range': '**scan_range**(host: string, start_port: int, end_port: int) -> array\n\n지정된 포트 범위를 스캔하여 열린 포트들의 배열을 반환합니다.',
            'connect': '**connect**(host: string, port: int) -> bool\n\nTCP 연결을 시도하여 성공 여부를 반환합니다.',
            'md5': '**md5**(data: string) -> string\n\n문자열의 MD5 해시 값을 계산합니다.',
            'sha256': '**sha256**(data: string) -> string\n\n문자열의 SHA256 해시 값을 계산합니다.',
            'create_payload': '**create_payload**(type: string, target: string) -> string\n\n지정된 타입의 공격 페이로드를 생성합니다.',
            'enum_processes': '**enum_processes**() -> array\n\n현재 실행 중인 모든 프로세스를 열거합니다.',
            'file_read': '**file_read**(path: string) -> string\n\n파일의 내용을 읽어 문자열로 반환합니다.',
            'print': '**print**(message: any) -> void\n\n메시지를 콘솔에 출력합니다.'
        };

        if (functionDescriptions[word]) {
            const hoverText = new vscode.MarkdownString(functionDescriptions[word]);
            hoverText.isTrusted = true;
            return new vscode.Hover(hoverText, range);
        }

        return null;
    }
}
