#!/bin/bash
# PSP 설치 스크립트

echo "PSP (PowerShellPlus) 설치 중..."

# Python 의존성 설치
echo "Python 의존성 설치 중..."
pip install cryptography requests

# 실행 권한 부여
chmod +x src/psp_interpreter.py

# 심볼릭 링크 생성 (선택사항)
if [ "$1" = "--global" ]; then
    echo "전역 설치 중..."
    sudo ln -sf $(pwd)/src/psp_interpreter.py /usr/local/bin/psp
    echo "PSP가 전역적으로 설치되었습니다. 'psp' 명령어를 사용하세요."
fi

echo "설치 완료!"
echo ""
echo "사용법:"
echo "  python src/psp_interpreter.py example.pspp  # 파일 실행"
echo "  python src/psp_interpreter.py -i           # 대화형 모드"
echo ""
echo "예제 파일들:"
echo "  examples/network_scan.pspp"
echo "  examples/vulnerability_test.pspp"
echo "  examples/system_recon.pspp"
