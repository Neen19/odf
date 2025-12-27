import zipfile
import xml.etree.ElementTree as ET
import base64
import hashlib
import zlib  # ← Это главное добавление!
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def crack_libreoffice_76_odt(file_path, password_list):
    print(f"[*] Взламываем файл: {file_path}\n")

    # Читаем manifest
    with zipfile.ZipFile(file_path) as zf:
        manifest_data = zf.read('META-INF/manifest.xml')
        encrypted_content = zf.read('content.xml')

    root = ET.fromstring(manifest_data)
    ns = {'m': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'}
    algo = root.find(".//m:algorithm", ns)
    key_der = root.find(".//m:key-derivation", ns)
    start_key = root.find(".//m:start-key-generation", ns)

    iv = base64.b64decode(algo.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}initialisation-vector'))
    salt = base64.b64decode(key_der.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}salt'))
    iterations = int(key_der.get('{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}iteration-count'))
    use_pre_hash = start_key is not None

    print(f"[+] Итераций: {iterations}")
    print(f"[+] Pre-hash SHA256: {'Да' if use_pre_hash else 'Нет'}")
    print(f"[*] Перебор {len(password_list)} паролей...\n")

    backend = default_backend()

    for pwd in password_list:
        print(f"[~] Пробуем: {pwd}")

        # Пробуем с pre-hash и без
        for pre_hash in [True, False]:
            try:
                if pre_hash and use_pre_hash:
                    pwd_bytes = hashlib.sha256(pwd.encode('utf-8')).digest()
                else:
                    pwd_bytes = pwd.encode('utf-8')

                kdf = PBKDF2HMAC(hashes.SHA1(), 32, salt, iterations, backend)
                key = kdf.derive(pwd_bytes)

                # Расшифровка
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()

                # Убираем PKCS7-padding
                unpadder = padding.PKCS7(128).unpadder()
                decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

                # ← ВОТ ГЛАВНОЕ: распаковываем deflate-сжатие!
                decrypted = zlib.decompress(decrypted, -15)  # -15 = raw deflate

                # Проверяем XML
                ET.fromstring(decrypted)

                print(f"\n[+] ПАРОЛЬ НАЙДЕН: {pwd}")
                print(f"    (pre-hash использовался: {'Да' if pre_hash and use_pre_hash else 'Нет'})")

                # Сохраняем расшифрованный файл (удобно!)
                with open("расшифрованный_документ.odt", "wb") as f:
                    with zipfile.ZipFile(file_path) as zin:
                        with zipfile.ZipFile(f, "w") as zout:
                            for item in zin.infolist():
                                if item.filename != "content.xml":
                                    zout.writestr(item, zin.read(item.filename))
                            zout.writestr("content.xml", decrypted)
                print("[+] Файл сохранён как «расшифрованный_документ.odt» — открывай в LibreOffice без пароля!")

                return pwd

            except Exception:
                continue

    print("\n[-] Пароль не найден.")
    return None

# ====================== ЗАПУСК ======================
if __name__ == "__main__":
    odt_file = "encrypted_76.odt"  # твой файл

    passwords = [
        "1234", "simple123", "password", "qwerty", "123456",
        "admin", "letmein", "test", "1111", "mysecretpassword"
    ]

    crack_libreoffice_76_odt(odt_file, passwords)
