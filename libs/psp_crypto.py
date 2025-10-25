#!/usr/bin/env python3
"""
PSP Advanced Cryptography Library
고급 암호화 및 보안 함수들
"""

import hashlib
import hmac
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class PSPCrypto:
    """PSP 암호화 라이브러리"""
    
    @staticmethod
    def generate_key() -> bytes:
        """암호화 키 생성"""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """데이터 암호화"""
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """데이터 복호화"""
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple:
        """패스워드 해싱 (PBKDF2)"""
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.b64encode(key).decode(), base64.b64encode(salt).decode()
    
    @staticmethod
    def verify_password(password: str, hashed: str, salt: str) -> bool:
        """패스워드 검증"""
        salt_bytes = base64.b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        try:
            kdf.verify(password.encode(), base64.b64decode(hashed.encode()))
            return True
        except:
            return False
    
    @staticmethod
    def hmac_sha256(data: str, key: str) -> str:
        """HMAC-SHA256 생성"""
        return hmac.new(
            key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def generate_random_string(length: int = 32) -> str:
        """랜덤 문자열 생성"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytes:
        """랜덤 바이트 생성"""
        return secrets.token_bytes(length)

class PSPHashCracker:
    """해시 크래킹 유틸리티"""
    
    @staticmethod
    def crack_md5(target_hash: str, wordlist: list) -> str:
        """MD5 해시 크래킹"""
        for word in wordlist:
            if hashlib.md5(word.encode()).hexdigest() == target_hash:
                return word
        return None
    
    @staticmethod
    def crack_sha1(target_hash: str, wordlist: list) -> str:
        """SHA1 해시 크래킹"""
        for word in wordlist:
            if hashlib.sha1(word.encode()).hexdigest() == target_hash:
                return word
        return None
    
    @staticmethod
    def crack_sha256(target_hash: str, wordlist: list) -> str:
        """SHA256 해시 크래킹"""
        for word in wordlist:
            if hashlib.sha256(word.encode()).hexdigest() == target_hash:
                return word
        return None
    
    @staticmethod
    def generate_wordlist(base_words: list, transformations: bool = True) -> list:
        """워드리스트 생성"""
        wordlist = base_words.copy()
        
        if transformations:
            for word in base_words:
                # 대소문자 변형
                wordlist.append(word.upper())
                wordlist.append(word.lower())
                wordlist.append(word.capitalize())
                
                # 숫자 추가
                for i in range(10):
                    wordlist.append(word + str(i))
                    wordlist.append(str(i) + word)
                
                # 특수문자 추가
                special_chars = ['!', '@', '#', '$', '%']
                for char in special_chars:
                    wordlist.append(word + char)
        
        return list(set(wordlist))  # 중복 제거

# 사용 예제
if __name__ == "__main__":
    crypto = PSPCrypto()
    cracker = PSPHashCracker()
    
    # 암호화 테스트
    print("=== PSP Crypto Test ===")
    key = crypto.generate_key()
    print(f"Generated Key: {key}")
    
    data = "secret message"
    encrypted = crypto.encrypt_data(data, key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = crypto.decrypt_data(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    # 패스워드 해싱 테스트
    password = "admin123"
    hashed, salt = crypto.hash_password(password)
    print(f"Password Hash: {hashed}")
    print(f"Salt: {salt}")
    
    is_valid = crypto.verify_password(password, hashed, salt)
    print(f"Password Valid: {is_valid}")
    
    # 해시 크래킹 테스트
    print("\n=== Hash Cracking Test ===")
    target = hashlib.md5("password".encode()).hexdigest()
    wordlist = ["admin", "password", "123456", "test"]
    
    cracked = cracker.crack_md5(target, wordlist)
    print(f"Cracked MD5: {cracked}")
