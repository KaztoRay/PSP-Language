@echo off
REM PSP Windows 설치 스크립트

echo PSP (PowerShellPlus) 설치 중...

REM Python 의존성 설치
echo Python 의존성 설치 중...
pip install cryptography requests

echo 설치 완료!
echo.
echo 사용법:
echo   python src\psp_interpreter.py example.pspp  # 파일 실행
echo   python src\psp_interpreter.py -i           # 대화형 모드
echo.
echo 예제 파일들:
echo   examples\network_scan.pspp
echo   examples\vulnerability_test.pspp
echo   examples\system_recon.pspp

pause
