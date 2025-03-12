import sys
import subprocess
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hmac
import os

try:
    import ast
    import random
    import string
    import zlib
    import base64
    import marshal
    import hashlib
    import time
    import threading
    import types
    from datetime import datetime
    from colorama import Fore, Style
    from typing import Tuple
    import tkinter as tk
    from colorama import init
    from tkinter import filedialog
except ImportError:
    print(f"{Fore.LIGHTMAGENTA_EX}[ {Fore.LIGHTBLACK_EX}+ {Fore.LIGHTMAGENTA_EX}] {Fore.LIGHTBLACK_EX} Installing the missing modules")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    print(f"{Fore.LIGHTMAGENTA_EX}[ {Fore.LIGHTBLACK_EX}+ {Fore.LIGHTMAGENTA_EX}] {Fore.LIGHTBLACK_EX} All modules installed")
    sys.exit()

init()

#############################################################################
#                                 CONFIG
#############################################################################
output_file = "H4ckCod3_obfuscated.py" # Name file after obfuscated
#############################################################################


class UltraAdvancedObfuscator:
    def __init__(self):
        self.var_mapping = {}
        self.string_mapping = {}
        self.used_names = []
        self.key = self._generate_key()

    def _generate_key(self, password: str) -> bytes:
        salt = get_random_bytes(16) 
        key = PBKDF2(password, salt, dkLen=32) 
        return key, salt

    def generate_unique_name(self, length: int = 20) -> str:
        homoglyphs = {
            'a': 'а', 'e': 'е', 'i': 'і', 'o': 'о', 'p': 'р',
            'c': 'с', 'y': 'у', 'l': 'ⅼ', 't': 'т', 'x': 'х'
        }
        while True:
            base = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
            name = ''
            for char in base:
                if char in homoglyphs and random.random() > 0.5:
                    name += homoglyphs[char]
                else:
                    name += char
            if name not in self.used_names and name.isidentifier():
                self.used_names.append(name)
                return name

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i, byte in enumerate(data):
            key_byte = key[i % len(key)]
            result.append(byte ^ key_byte)
        return bytes(result)

    def _aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_GCM) 
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def encrypt_string(self, s: str, password: str) -> Tuple[str, str]:
        key, salt = self._generate_key(password)
        compressed = zlib.compress(s.encode(), level=9)
        encrypted = self._aes_encrypt(compressed, key)
        
        hmac_key = get_random_bytes(32)
        hmac_signature = hmac.new(hmac_key, encrypted, hashlib.sha256).hexdigest()
        
        return (base64.b64encode(encrypted).decode(), base64.b64encode(salt).decode(), hmac_signature)

    def decrypt_string(self, encrypted_data: str, password: str, salt: str, hmac_signature: str) -> str:
        key = PBKDF2(password, base64.b64decode(salt), dkLen=32)
        encrypted_data = base64.b64decode(encrypted_data)
        
        if hmac.new(get_random_bytes(32), encrypted_data, hashlib.sha256).hexdigest() != hmac_signature:
            raise ValueError("Data integrity check failed")

        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return zlib.decompress(decrypted).decode()

    def generate_anti_debug(self) -> str:
        return """
def _verify_environment():
    import sys, time, threading
    from datetime import datetime
    
    def _check_debugger():
        now = time.time()
        time.sleep(0.1)
        if abs(time.time() - now - 0.1) > 0.01:
            sys.exit(1)
    
    def _check_modules():
        blacklist = {'pdb', 'ida', 'pydevd', 'gdb', 'pyspy', 'frida'}
        if any(mod.lower() in blacklist for mod in sys.modules):
            sys.exit(1)
    
    def _timing_check():
        start = datetime.now()
        for _ in range(1000): pass
        duration = (datetime.now() - start).total_seconds()
        if duration > 0.1:  
            sys.exit(1)
    
    checks = [_check_debugger, _check_modules, _timing_check]
    threads = [threading.Thread(target=check) for check in checks]
    for t in threads: t.start()
    for t in threads: t.join()

_verify_environment()
"""

    def generate_decrypt_function(self) -> str:
        return f"""
def decrypt(data: str, key: str, verification: str = None) -> str:
    import base64, zlib, hashlib, sys, time
    from typing import Any
    
    def _xor(data: bytes, key: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    try:
        if verification and hashlib.sha512(data.encode()).hexdigest() != verification:
            sys.exit(1)
        
        key = base64.b85decode(key)
        master_key = {self.key}
        
        encrypted = base64.b64decode(data.encode())
        decrypted = _xor(encrypted, master_key)
        decrypted = base64.b85decode(decrypted)
        decrypted = _xor(decrypted, key)
        
        return zlib.decompress(decrypted).decode()
    except Exception:
        sys.exit(1)
"""

    class ControlFlowObfuscator(ast.NodeTransformer):
        def __init__(self, obfuscator):
            self.obfuscator = obfuscator

        def visit_If(self, node):
            opaque = ast.Compare(
                left=ast.Call(
                    func=ast.Name(id='len', ctx=ast.Load()),
                    args=[ast.Constant(value=''.join(chr(i) for i in range(256)))],
                    keywords=[]
                ),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=256)]
            )
            
            node.test = ast.BoolOp(
                op=ast.And(),
                values=[opaque, node.test]
            )
            
            return self.generic_visit(node)

        def visit_While(self, node):
            complex_true = ast.Compare(
                left=ast.BinOp(
                    left=ast.Call(
                        func=ast.Name(id='hash', ctx=ast.Load()),
                        args=[ast.Constant(value='salt')],
                        keywords=[]
                    ),
                    op=ast.Mod(),
                    right=ast.Constant(value=2)
                ),
                ops=[ast.In()],
                comparators=[ast.List(
                    elts=[ast.Constant(value=0), ast.Constant(value=1)],
                    ctx=ast.Load()
                )]
            )
            
            node.test = ast.BoolOp(
                op=ast.And(),
                values=[complex_true, node.test]
            )
            
            return self.generic_visit(node)

    class AdvancedNameTransformer(ast.NodeTransformer):
        def __init__(self, obfuscator):
            self.obfuscator = obfuscator

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                if node.id not in self.obfuscator.var_mapping:
                    self.obfuscator.var_mapping[node.id] = self.obfuscator.generate_unique_name()
                node.id = self.obfuscator.var_mapping[node.id]
            elif isinstance(node.ctx, ast.Load):
                if node.id in self.obfuscator.var_mapping:
                    node.id = self.obfuscator.var_mapping[node.id]
            return node

        def visit_Str(self, node):
            if node.value not in self.obfuscator.string_mapping:
                encrypted, key = self.obfuscator.encrypt_string(node.value)
                verification = hashlib.sha512(encrypted.encode()).hexdigest()
                self.obfuscator.string_mapping[node.value] = (encrypted, key, verification)
            
            encrypted, key, verification = self.obfuscator.string_mapping[node.value]
            return ast.Call(
                func=ast.Name(id='decrypt', ctx=ast.Load()),
                args=[
                    ast.Constant(value=encrypted),
                    ast.Constant(value=key),
                    ast.Constant(value=verification)
                ],
                keywords=[]
            )

    def obfuscate(self, source_code: str) -> str:
        tree = ast.parse(source_code)
        
        transformers = [
            self.ControlFlowObfuscator(self),
            self.AdvancedNameTransformer(self)
        ]
        
        for transformer in transformers:
            tree = transformer.visit(tree)
            ast.fix_missing_locations(tree)
        
        protection_code = self.generate_anti_debug()
        decrypt_func = self.generate_decrypt_function()
        
        code = compile(tree, '<string>', 'exec')
        marshalled = marshal.dumps(code)
        
        encrypted_bytecode = self._xor_encrypt(marshalled, self.key)
        encoded_bytecode = base64.b85encode(encrypted_bytecode).decode()
       
        final_code = f"""
#/////////////////////////////////////////  OBFUSCATED BY NEXO ////////////////////////////////////     

#                                     ███╗   ██╗███████╗██╗  ██╗ ██████╗       
#                                     ████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗     
#                                     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║     
#                                     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║    
#                                     ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝      
#                                     ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    
#                                                                                      
#              ███████╗███╗   ██╗ ██████╗██╗   ██╗██████╗ ████████╗ █████╗ ████████╗ ██████╗ ██████╗ 
#              ██╔════╝████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗ 
#              █████╗  ██╔██╗ ██║██║      ╚████╔╝ ██████╔╝   ██║   ███████║   ██║   ██║   ██║██████╔╝
#              ██╔══╝  ██║╚██╗██║██║       ╚██╔╝  ██╔═══╝    ██║   ██╔══██║   ██║   ██║   ██║██╔══██╗
#              ███████╗██║ ╚████║╚██████╗   ██║   ██║        ██║   ██║  ██║   ██║   ╚██████╔╝██║  ██║
#              ╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
# 
#///////////////////////////////////////// CREATED BY H4CKCOD3 ////////////////////////////////////////////

import marshal, types, base64, sys, time, threading
from datetime import datetime

{decrypt_func}

def _load_code():
    try:
        _key = {self.key}
        _encrypted = base64.b85decode('{encoded_bytecode}')
        _code = bytes(a ^ b for a, b in zip(_encrypted, _key * (len(_encrypted) // len(_key) + 1)))
        return marshal.loads(_code)
    except:
        sys.exit(1)

def _protected_exec():
    _code = _load_code()
    exec(_code, globals())

_t = threading.Thread(target=_protected_exec)
_t.start()
_t.join()
"""
        return final_code

def obfuscate_file(input_file: str, output_file: str):
    with open(input_file, 'r', encoding='utf-8') as f:
        source = f.read()
    
    obfuscator = UltraAdvancedObfuscator()
    obfuscated = obfuscator.obfuscate(source)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(obfuscated)

def open_file_dialog() -> str:
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select a Python file to obfuscate",
        filetypes=[("Python Files", "*.py")]
    )
    return file_path

def main():
    while True:
        print(f"""{Fore.LIGHTMAGENTA_EX}
         
                                     ███╗   ██╗███████╗██╗  ██╗ ██████╗       
                                     ████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗     
                                     ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║     
                                     ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║    
                                     ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝      
                                     ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝    
                                                                                      
              ███████╗███╗   ██╗ ██████╗██╗   ██╗██████╗ ████████╗ █████╗ ████████╗ ██████╗ ██████╗ 
              ██╔════╝████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗ 
              █████╗  ██╔██╗ ██║██║      ╚████╔╝ ██████╔╝   ██║   ███████║   ██║   ██║   ██║██████╔╝
              ██╔══╝  ██║╚██╗██║██║       ╚██╔╝  ██╔═══╝    ██║   ██╔══██║   ██║   ██║   ██║██╔══██╗
              ███████╗██║ ╚████║╚██████╗   ██║   ██║        ██║   ██║  ██║   ██║   ╚██████╔╝██║  ██║
              ╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝


                                          {Fore.LIGHTMAGENTA_EX}[{Fore.LIGHTBLACK_EX} 1 {Fore.LIGHTMAGENTA_EX}] {Fore.LIGHTBLACK_EX}Obfuscate Code{Fore.RESET}
                                                                                      
""")

        option = input(f"{Fore.LIGHTMAGENTA_EX}[ {Fore.LIGHTBLACK_EX}+ {Fore.LIGHTMAGENTA_EX}] {Fore.LIGHTBLACK_EX}Enter your choice: ")

        if option == "1":
            input_file = open_file_dialog()
            if input_file:
                try:
                    obfuscate_file(input_file, output_file)
                    print(f"{Fore.LIGHTBLACK_EX}[ {Fore.GREEN}+ {Fore.LIGHTBLACK_EX}] {Fore.GREEN}Codigo Encryptado correctamente: {output_file}")
                except Exception as e:
                    print(f"Error: {e}")
        elif option == "2":
            print(f"{Fore.LIGHTBLACK_EX}[ {Fore.RED}- {Fore.LIGHTBLACK_EX}] {Fore.RED}Saliendo de la Tool")
            break
        else:
            print(f"{Fore.LIGHTBLACK_EX}[ {Fore.RED}- {Fore.LIGHTBLACK_EX}] {Fore.RED}Opcion Invalida")

if __name__ == "__main__":
    main()
