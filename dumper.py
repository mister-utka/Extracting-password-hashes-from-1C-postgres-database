import re
import base64
import binascii
import argparse
import psycopg2

"""
Скрипт подключается к PostgreSQL, извлекает данные из таблицы v8users (по умолчанию),
декодирует зашифрованное поле DATA (XOR-маска), достаёт два SHA1-хэша пароля (обычный и верхнего регистра)
и выводит их в консоль в табличной форме.

The script connects to PostgreSQL, extracts data from the v8users table (by default),
decodes the encrypted DATA field (XOR mask), extracts two SHA1 password hashes (regular and uppercase)
and outputs them to the console in tabular form.

python dumper.py --host <ip> --port 5432 --user postgres --password postgres --dbname 1C_test
"""

def decoded_data_flg(data):                                         # Функция для расшифровки поля DATA

    if data is None:
        return None
    elif len(data) < 2:                                             # Если длина полученных данных меньше чем два байта, то декодировать нечего
        return None
    
    if isinstance(data, bytes):                                     # Если тип данных bytes (который нам нужен)                    
        pass
    elif isinstance(data, memoryview):                              # Если тип данных memoryview (типичный для psycopg2 bytea)
        data = data.tobytes()                                       # преобразуем в bytes
    elif isinstance(data, str):                                     # Если тип данных str
        try:
            data = base64.b64decode(data)                           # пробуем декодировать как base64
        except Exception:
            try:
                data = binascii.unhexlify(data)                     # или пробуем как hex
            except Exception:
                return None
    else:                                                           # Если это какой-то другой тип данных
        return None
    
    try:
        mask_length = data[0]                                       # Первый байт - это длина маски
        if mask_length <= 0 or (mask_length + 1) >= len(data):      # Проверка на корректность 
            return None
        
        mask = data[1:1 + mask_length]                              # Извлекаем байты маски
        data_bytes = data[mask_length + 1:]                         # Оставшаяся часть это зашифрованные данные

        decoded_bytes = bytearray()                                 # Создаем массив для рссшифрованных данных
        j = 0                                                       # Индекс для обхода маски
        for b in data_bytes:                                        # Проходим по каждому байту зашифроыванных данных
            decoded_bytes.append(b ^ mask[j])                       # XOR между байтом данных и соответствующим байтом маски
            j += 1                                                  # Сдвигаем индекс маски
            if j >= mask_length:                                    # Если дошли до конца маски, то обнуляем
                j = 0

        try:
            return decoded_bytes.decode("utf-8-sig")                # Пробуем декодировать в строку UTF-8 (с поддержкой BOM)
        except Exception:
            try:
                possible = binascii.unhexlify(decoded_bytes)        # Пробуем как hex-строку
                return possible.decode("utf-8-sig")                 # и декодирем в UTF
            except Exception:
                return None
    except Exception:
        return None


def extract_hashes(decoded_data):                                   # Функция для извлечения хэшей из расшифрованного текста

    if not isinstance(decoded_data, str):                           # Проверяем что были переданны str данные
        return None

    re_mask = r'\d+,\d+,"([\w+/=]+)","([\w+/=]+)",\d+,\d+'          # Регулярное выражение ищет две base64-строки внутри поля DATA
    result = re.search(re_mask, decoded_data)                       # нпример подходящая строка: 1,0,"QWxhZGRpbjpvcGVuIHNlc2FtZQ==","YWJjZGVmZ2hpamtsbW5vcA==",0,0

    if result is None:
        return None
    
    try:
        groups = result.groups()                                                # Получаем кортеж из двух строк
        hashes = []
        for b64 in groups:                                                      # Перебираем каждую из двух base64-строк
            decoded_bytes = base64.b64decode(b64.encode())                      # Декодируем base64 -> bytes
            hex_str = ''.join('{:02x}'.format(byte) for byte in decoded_bytes)  # Переводим bytes в hex строку
            hashes.append(hex_str)                                              # Добавляем hex-хэш в список
        return tuple(hashes)                                                    # Возвращаем кортеж: (SHA1(password), SHA1(password.upper()))
    except Exception:
        return None

def main():

    parser = argparse.ArgumentParser(description="Извлечение SHA1-хешей пользователей 1С из Postgres")
    parser.add_argument("--host", default="localhost", help="Хост PostgreSQL")
    parser.add_argument("--port", default="5432", help="Порт PostgreSQL")
    parser.add_argument("--user", required=True, help="Пользователь БД")
    parser.add_argument('--password', required=True, help='Пароль пользователя БД')
    parser.add_argument('--dbname', required=True, help='Имя базы данных')
    parser.add_argument('--table', default='v8users', help='Таблица с пользователями (по умолчанию v8users)')
    parser.add_argument('--data-col', default='data', help='Колонка с полем DATA (по умолчанию data)')
    parser.add_argument('--name-col', default='name', help='Колонка с именем пользователя (по умолчанию name)')
    parser.add_argument('--admrole-col', default='admrole', help='Колонка с ролью админа (по умолчанию admrole)')
    args = parser.parse_args()

    conn = psycopg2.connect(                                                                        # Подключение к БД
        host=args.host, port=args.port, user=args.user, password=args.password, dbname=args.dbname
    )
    cur = conn.cursor()                                                                             # Создаем курсор для выполнения SQL запроса

    query = f"SELECT {args.admrole_col}, {args.name_col}, {args.data_col} FROM {args.table}"        # Формируем запрос
    cur.execute(query)                                                                              # Выполняем SQL запрос

    print("+{}+{}+{}+{}+".format(6*'-', 50*'-', 42*'-', 42*'-'))
    print("|{:6}|{:50}|{:42}|{:42}|".format("Админ", "Имя пользователя", "SHA1", "SHA1_SHIFT"))
    print("+{}+{}+{}+{}+".format(6*'-', 50*'-', 42*'-', 42*'-'))

    row_counter = 1
    for row in cur:                                                                                 # Перебираем все строки результата запроса
        
        print(f"String processing: {row_counter}", end="\r")
        admrole, name, data = row                                                                   # Расспаковываем данные

        if data is None:
            data = "None"

        decoded = decoded_data_flg(data)                                                            # Рассшифровываем поле DATA
        if decoded is None:
            print(f"String {row_counter} decoding error")
            continue
            
        hashes = extract_hashes(decoded)                                                            # Извлекаем SHA1 хеши из расшифрованного текста
        if hashes is None:
            print(f"String {row_counter} hash extraction error")
            continue

        print("|{0!r:6}|{1:50}|{2:42}|{3:42}|".format(admrole, name, hashes[0], hashes[1]))
        row_counter += 1
    
    print("+{}+{}+{}+{}+".format(6*'-', 50*'-', 42*'-', 42*'-'))

    cur.close()                                                                                     # Закрываем курсор
    conn.close()                                                                                    # Закрываем соединение с БД

if __name__ == '__main__':
    main() 