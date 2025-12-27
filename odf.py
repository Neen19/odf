#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Полный скрипт для создания и расшифровки ODF файла с паролем
"""

import pyminizip
import zipfile
import os
import sys
import itertools
import string
from pathlib import Path
import shutil


# ===== СОЗДАНИЕ ЗАЩИЩЕННОГО ODF ФАЙЛА =====

def create_simple_odt_content():
    """
    Создает минимальный контент для ODT файла
    """
    manifest_content = '''<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
    <manifest:file-entry manifest:media-type="application/vnd.oasis.opendocument.text" manifest:full-path="/"/>
    <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/>
    <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="styles.xml"/>
    <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="meta.xml"/>
</manifest:manifest>'''

    content_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
    <office:body>
        <office:text>
            <text:p>Это защищенный документ ODF!</text:p>
            <text:p>Этот файл был создан с паролем.</text:p>
            <text:p>Содержимое: конфиденциальная информация.</text:p>
            <text:p>Дата создания: 2024</text:p>
        </office:text>
    </office:body>
</office:document-content>'''

    styles_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
    <office:styles/>
</office:document-styles>'''

    meta_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
    <office:meta>
        <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Protected Document</dc:title>
    </office:meta>
</office:document-meta>'''

    mimetype = 'application/vnd.oasis.opendocument.text'

    return {
        'META-INF/manifest.xml': manifest_content,
        'content.xml': content_xml,
        'styles.xml': styles_xml,
        'meta.xml': meta_xml,
        'mimetype': mimetype
    }


def create_protected_odf(filename, password):
    """
    Создает ODF файл защищенный паролем
    """
    print(f"\n{'='*50}")
    print(f"Создание защищенного ODF файла: {filename}")
    print(f"Пароль: {password}")
    print(f"{'='*50}")
    
    # Создаём временную директорию
    temp_dir = "temp_odf_files"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)
    
    # Получаем контент для ODF
    files_content = create_simple_odt_content()
    
    # Сначала создаём обычный незащищённый ODF
    temp_odf = "temp_unprotected.odt"
    
    with zipfile.ZipFile(temp_odf, 'w') as zf:
        zf.writestr('mimetype', files_content['mimetype'], compress_type=zipfile.ZIP_STORED)
        for file_path, content in files_content.items():
            if file_path != 'mimetype':
                zf.writestr(file_path, content, compress_type=zipfile.ZIP_DEFLATED)
    
    print(f"✓ Создан временный незащищённый файл")
    
    # Извлекаем файлы во временную директорию
    with zipfile.ZipFile(temp_odf, 'r') as zf:
        zf.extractall(temp_dir)
    
    # Создаём список всех файлов для сжатия
    all_files = []
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            filepath = os.path.join(root, file)
            arcname = os.path.relpath(filepath, temp_dir)
            all_files.append((filepath, arcname))
    
    # Используем pyminizip для создания защищённого архива
    try:
        # pyminizip требует список файлов
        src_files = [f[0] for f in all_files]
        prefixes = [os.path.dirname(f[1]) + "/" if os.path.dirname(f[1]) else "" for f in all_files]
        
        # Создаём защищённый ZIP
        compression_level = 5
        pyminizip.compress_multiple(src_files, prefixes, filename, password, compression_level)
        
        print(f"✓ Файл успешно создан с паролем: {filename}")
        print(f"✓ Размер файла: {os.path.getsize(filename)} байт")
        
        # Проверяем, что файл действительно защищён
        print(f"✓ Проверка защиты...")
        try:
            with zipfile.ZipFile(filename, 'r') as zf:
                zf.read('content.xml')  # Попытка чтения без пароля
                print(f"⚠ ВНИМАНИЕ: Файл не защищён паролем!")
        except RuntimeError:
            print(f"✓ Файл защищён паролем корректно!")
        
    except Exception as e:
        print(f"✗ Ошибка при создании защищённого файла: {e}")
        return False
    finally:
        # Удаляем временные файлы
        if os.path.exists(temp_odf):
            os.remove(temp_odf)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    
    return True


# ===== РАСШИФРОВКА ODF ФАЙЛА =====

def try_decrypt_odf(filename, password):
    """
    Пытается расшифровать ODF файл с заданным паролем
    """
    try:
        with zipfile.ZipFile(filename, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            content = zf.read('content.xml')
            return True, content.decode('utf-8')
    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def extract_odf_content(filename, password, output_dir='extracted'):
    """
    Извлекает содержимое ODF файла
    """
    print(f"\n{'='*50}")
    print(f"Расшифровка файла: {filename}")
    print(f"{'='*50}")
    
    if not os.path.exists(filename):
        print(f"✗ Ошибка: файл {filename} не найден!")
        return False
    
    success, result = try_decrypt_odf(filename, password)
    
    if not success:
        print(f"✗ Не удалось расшифровать: {result}")
        return False
    
    print(f"✓ Пароль верный!")
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    Path(output_dir).mkdir(exist_ok=True)
    
    try:
        with zipfile.ZipFile(filename, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.extractall(output_dir)
        
        print(f"✓ Файлы извлечены в папку: {output_dir}")
        
        print(f"\n{'='*50}")
        print("Содержимое документа (content.xml):")
        print(f"{'='*50}")
        print(result)
        
        print(f"\n{'='*50}")
        print("Извлеченные файлы:")
        print(f"{'='*50}")
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                filepath = os.path.join(root, file)
                size = os.path.getsize(filepath)
                rel_path = os.path.relpath(filepath, output_dir)
                print(f"  {rel_path} ({size} байт)")
        
        return True
        
    except Exception as e:
        print(f"✗ Ошибка при извлечении: {e}")
        return False


# ===== ПЕРЕБОР ПАРОЛЕЙ =====

def brute_force_simple(filename, max_length=4):
    """
    Простой перебор паролей
    """
    print(f"\n{'='*50}")
    print(f"Перебор паролей для файла: {filename}")
    print(f"Максимальная длина: {max_length}")
    print(f"{'='*50}")
    
    charset = string.ascii_lowercase + string.digits
    attempts = 0
    
    for length in range(1, max_length + 1):
        print(f"\nПроверяем пароли длиной {length} символов...")
        
        for password_tuple in itertools.product(charset, repeat=length):
            password = ''.join(password_tuple)
            attempts += 1
            
            if attempts % 500 == 0:
                print(f"  Проверено {attempts} паролей... (текущий: {password})")
            
            success, _ = try_decrypt_odf(filename, password)
            
            if success:
                print(f"\n{'='*50}")
                print(f"✓✓✓ ПАРОЛЬ НАЙДЕН: {password} ✓✓✓")
                print(f"{'='*50}")
                print(f"Всего попыток: {attempts}")
                return password
    
    print(f"\n✗ Пароль не найден после {attempts} попыток")
    return None


def brute_force_wordlist(filename, wordlist):
    """
    Перебор паролей из списка
    """
    print(f"\n{'='*50}")
    print(f"Перебор паролей из списка")
    print(f"Количество паролей: {len(wordlist)}")
    print(f"{'='*50}")
    
    for i, password in enumerate(wordlist, 1):
        if i % 10 == 0:
            print(f"  Проверено {i}/{len(wordlist)} паролей...")
        
        success, _ = try_decrypt_odf(filename, password)
        
        if success:
            print(f"\n{'='*50}")
            print(f"✓✓✓ ПАРОЛЬ НАЙДЕН: {password} ✓✓✓")
            print(f"{'='*50}")
            print(f"Позиция в списке: {i}")
            return password
    
    print(f"\n✗ Пароль не найден в списке")
    return None


# ===== ГЛАВНОЕ МЕНЮ =====

def main_menu():
    """
    Интерактивное меню
    """
    while True:
        print(f"\n{'='*50}")
        print("ODF ФАЙЛ - СОЗДАНИЕ И РАСШИФРОВКА")
        print(f"{'='*50}")
        print("1. Создать защищенный ODF файл")
        print("2. Расшифровать ODF файл (известен пароль)")
        print("3. Взломать ODF файл (перебор простых паролей)")
        print("4. Взломать ODF файл (словарь паролей)")
        print("5. Тест: создать и сразу взломать")
        print("0. Выход")
        print(f"{'='*50}")
        
        choice = input("\nВыберите действие: ").strip()
        
        if choice == '1':
            filename = input("Имя файла (например, document.odt): ").strip() or "protected.odt"
            password = input("Введите пароль: ").strip() or "test123"
            create_protected_odf(filename, password)
            
        elif choice == '2':
            filename = input("Имя файла: ").strip() or "protected.odt"
            password = input("Введите пароль: ").strip()
            extract_odf_content(filename, password)
            
        elif choice == '3':
            filename = input("Имя файла: ").strip() or "protected.odt"
            max_len = input("Максимальная длина пароля (1-6): ").strip() or "3"
            found_password = brute_force_simple(filename, int(max_len))
            if found_password:
                extract = input("\nИзвлечь содержимое? (y/n): ").strip().lower()
                if extract == 'y':
                    extract_odf_content(filename, found_password)
            
        elif choice == '4':
            filename = input("Имя файла: ").strip() or "protected.odt"
            print("\nВведите пароли для проверки (по одному на строку, пустая строка = конец):")
            wordlist = []
            while True:
                pwd = input("  > ").strip()
                if not pwd:
                    break
                wordlist.append(pwd)
            
            if wordlist:
                found_password = brute_force_wordlist(filename, wordlist)
                if found_password:
                    extract = input("\nИзвлечь содержимое? (y/n): ").strip().lower()
                    if extract == 'y':
                        extract_odf_content(filename, found_password)
            else:
                print("Список паролей пуст!")
                
        elif choice == '5':
            filename = "demo.odt"
            password = "abc"
            print("\n>>> ДЕМО РЕЖИМ <<<")
            print(f"Создаем файл {filename} с паролем '{password}'")
            create_protected_odf(filename, password)
            
            input("\nНажмите Enter для начала взлома...")
            found = brute_force_simple(filename, max_length=3)
            
            if found:
                input("\nНажмите Enter для извлечения содержимого...")
                extract_odf_content(filename, found)
            
        elif choice == '0':
            print("\nДо свидания!")
            sys.exit(0)
            
        else:
            print("\n✗ Неверный выбор!")


# ===== ЗАПУСК =====

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
