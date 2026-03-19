import logging
import os
import socket
import threading
from typing import Tuple


# =========================
# НАСТРОЙКИ ПО УМОЛЧАНИЮ
# =========================
# Эти значения предлагаются пользователю,
# если он просто нажимает Enter.
DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 9090
BUFFER_SIZE = 1024
MAX_PORT = 65535
BACKLOG = 5

# Файл лога кладем рядом со скриптом.
# Так пользователю проще его найти независимо от того,
# из какой папки он запустил сервер.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'server.log')


# =========================
# НАСТРОЙКА ЛОГИРОВАНИЯ
# =========================
# Добавляем в формат threadName, чтобы в логах было видно,
# какой именно поток обслуживал конкретного клиента.
# Это особенно полезно для демонстрации многопоточности.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(threadName)s | %(message)s',
    encoding='utf-8'
)


# =========================
# СЧЕТЧИК КЛИЕНТОВ
# =========================
# Когда сервер работает с несколькими клиентами одновременно,
# удобно давать каждому подключению свой порядковый номер.
# Но тут есть важный момент: несколько потоков могут попытаться
# изменить общий счетчик одновременно.
# Чтобы не возникла гонка данных (race condition),
# используем Lock.
client_counter_lock = threading.Lock()
client_counter = 0



def get_next_client_number() -> int:
    """
    Возвращает следующий номер клиента безопасно для многопоточной среды.

    Почему тут нужен lock?
    Потому что без него два потока теоретически могли бы одновременно
    прочитать одно и то же значение счетчика и получить одинаковый номер.
    С lock мы гарантируем, что увеличение счетчика происходит строго по очереди.
    """
    global client_counter

    with client_counter_lock:
        client_counter += 1
        return client_counter



def ask_host(default_host: str) -> str:
    """
    Безопасно спрашивает у пользователя адрес, на котором сервер будет слушать подключения.

    Частые варианты:
    - 0.0.0.0   -> слушать все сетевые интерфейсы;
    - 127.0.0.1 -> слушать только локальный компьютер.

    Если пользователь ничего не ввел, возвращаем значение по умолчанию.
    """
    while True:
        user_input = input(
            f'Введите адрес хоста для сервера [по умолчанию {default_host}]: '
        ).strip()

        if user_input == '':
            return default_host

        return user_input



def ask_port(default_port: int) -> int:
    """
    Безопасно спрашивает у пользователя номер порта.

    Проверяем, что порт:
    - введен как число;
    - находится в диапазоне 1..65535.

    Если пользователь просто нажал Enter, возвращаем порт по умолчанию.
    """
    while True:
        user_input = input(
            f'Введите начальный порт для сервера [по умолчанию {default_port}]: '
        ).strip()

        if user_input == '':
            return default_port

        if not user_input.isdigit():
            print('Ошибка: порт должен быть целым положительным числом.')
            continue

        port = int(user_input)

        if 1 <= port <= MAX_PORT:
            return port

        print(f'Ошибка: порт должен быть в диапазоне 1..{MAX_PORT}.')



def bind_to_free_port(server_socket: socket.socket, host: str, start_port: int) -> int:
    """
    Пытается привязать серверный сокет к порту start_port.

    Если порт уже занят, пробует следующий: start_port + 1, потом +2 и так далее,
    пока не найдет свободный.

    Возвращает реальный порт, на котором сервер начал слушать подключения.
    """
    current_port = start_port

    while current_port <= MAX_PORT:
        try:
            server_socket.bind((host, current_port))
            return current_port
        except OSError:
            current_port += 1

    raise OSError(
        f'Не удалось найти свободный порт в диапазоне {start_port}..{MAX_PORT}.'
    )



def send_text_line(conn: socket.socket, text: str) -> None:
    """
    Отправляет одну строку текста клиенту, гарантированно завершая ее символом '\n'.

    Мы специально делаем отдельную функцию, чтобы:
    1. не дублировать код отправки в нескольких местах;
    2. зафиксировать единый протокол обмена.

    Наш простой протокол такой:
    - одна логическая строка = обычный текст + символ перевода строки.
    """
    message = text + '\n'
    conn.sendall(message.encode('utf-8'))



def receive_lines_from_client(conn: socket.socket,
                              client_address: Tuple[str, int],
                              client_number: int) -> None:
    """
    Обрабатывает одного клиента в ОТДЕЛЬНОМ ПОТОКЕ.

    Это главный шаг для поддержки нескольких одновременных клиентов.

    Раньше сервер работал так:
    - принял клиента через accept();
    - целиком обслуживал этого клиента;
    - только потом возвращался к accept().

    Из-за этого второй клиент ждал, пока закончится работа с первым.

    Теперь логика другая:
    - главный поток принимает подключение;
    - для клиента создается новый поток;
    - новый поток занимается только этим клиентом;
    - главный поток сразу возвращается к accept() и готов принимать новых клиентов.

    Именно это и позволяет нескольким клиентам работать одновременно.
    """
    text_buffer = ''

    try:
        with conn:
            logging.info(
                'Клиент #%s подключен: IP=%s, PORT=%s.',
                client_number,
                client_address[0],
                client_address[1]
            )

            while True:
                data = conn.recv(BUFFER_SIZE)

                # Пустой результат recv() означает,
                # что клиент закрыл соединение со своей стороны.
                if not data:
                    logging.info(
                        'Клиент #%s (%s:%s) закрыл соединение.',
                        client_number,
                        client_address[0],
                        client_address[1]
                    )
                    break

                chunk_text = data.decode('utf-8', errors='replace')
                logging.info(
                    'От клиента #%s (%s:%s) получен фрагмент %r длиной %s байт.',
                    client_number,
                    client_address[0],
                    client_address[1],
                    chunk_text,
                    len(data)
                )

                # TCP - потоковый протокол.
                # Это значит, что recv() может вернуть:
                # - половину строки,
                # - целую строку,
                # - сразу несколько строк.
                # Поэтому складываем данные в буфер и выделяем
                # из него готовые строки по символу '\n'.
                text_buffer += chunk_text

                while '\n' in text_buffer:
                    line, text_buffer = text_buffer.split('\n', 1)
                    line = line.rstrip('\r')

                    logging.info(
                        'От клиента #%s (%s:%s) полностью получена строка: %r.',
                        client_number,
                        client_address[0],
                        client_address[1],
                        line
                    )

                    if line == 'exit':
                        logging.info(
                            'Клиент #%s (%s:%s) отправил команду завершения exit.',
                            client_number,
                            client_address[0],
                            client_address[1]
                        )

                        send_text_line(conn, 'Соединение будет закрыто по команде exit.')
                        logging.info(
                            'Клиенту #%s (%s:%s) отправлено подтверждение закрытия соединения.',
                            client_number,
                            client_address[0],
                            client_address[1]
                        )
                        return

                    # Эхо-логика: возвращаем клиенту ту же строку.
                    send_text_line(conn, line)
                    logging.info(
                        'Клиенту #%s (%s:%s) отправлен эхо-ответ: %r.',
                        client_number,
                        client_address[0],
                        client_address[1],
                        line
                    )

    except ConnectionResetError:
        # Такое бывает, если клиент аварийно оборвал соединение,
        # например просто закрыл окно процесса или сеть внезапно пропала.
        logging.warning(
            'Соединение с клиентом #%s (%s:%s) было принудительно сброшено.',
            client_number,
            client_address[0],
            client_address[1]
        )

    except Exception as error:
        # В многопоточной программе особенно важно,
        # чтобы ошибка одного клиента не роняла весь сервер.
        # Поэтому перехватываем исключение внутри потока,
        # логируем его и позволяем другим потокам продолжать работу.
        logging.exception(
            'Ошибка при обслуживании клиента #%s (%s:%s): %s',
            client_number,
            client_address[0],
            client_address[1],
            error
        )

    finally:
        logging.info(
            'Завершена работа потока обслуживания клиента #%s (%s:%s).',
            client_number,
            client_address[0],
            client_address[1]
        )



def main() -> None:
    """
    Основная функция сервера.

    Что делает сервер:
    1. спрашивает host и стартовый port;
    2. создает TCP-сокет;
    3. при необходимости автоматически подбирает свободный порт;
    4. начинает слушать подключения;
    5. для КАЖДОГО нового клиента создает ОТДЕЛЬНЫЙ поток;
    6. продолжает принимать следующих клиентов, не дожидаясь завершения предыдущих.

    Именно пункт 5 делает сервер многопоточным.
    """
    host = ask_host(DEFAULT_HOST)
    start_port = ask_port(DEFAULT_PORT)

    # Создаем TCP-сокет IPv4.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Разрешаем быстрое повторное использование адреса.
        # Это удобно во время отладки, когда сервер часто перезапускают.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        logging.info('Запуск сервера.')
        logging.info('Выбранные параметры запуска: host=%s, start_port=%s.', host, start_port)

        actual_port = bind_to_free_port(server_socket, host, start_port)

        logging.info(
            'Сервер успешно привязан к адресу %s и порту %s.',
            host,
            actual_port
        )

        # По заданию реальный порт выводим в консоль.
        print(f'Сервер слушает порт: {actual_port}')
        print(f'Лог сервера: {LOG_FILE}')
        print('Можно запускать несколько клиентов одновременно в разных окнах терминала.')

        # backlog задает очередь ожидающих подключений.
        server_socket.listen(BACKLOG)
        logging.info('Начато прослушивание порта %s. Размер очереди ожидания: %s.', actual_port, BACKLOG)

        while True:
            logging.info('Главный поток ожидает новое подключение...')
            conn, addr = server_socket.accept()

            # Получаем уникальный номер клиента.
            client_number = get_next_client_number()

            # Создаем отдельный поток под конкретного клиента.
            # daemon=True означает, что поток не будет удерживать процесс
            # при завершении программы. Для учебного сервера это удобно.
            client_thread = threading.Thread(
                target=receive_lines_from_client,
                args=(conn, addr, client_number),
                daemon=True,
                name=f'ClientThread-{client_number}'
            )
            client_thread.start()

            logging.info(
                'Для клиента #%s (%s:%s) создан поток %s.',
                client_number,
                addr[0],
                addr[1],
                client_thread.name
            )

    except KeyboardInterrupt:
        logging.info('Сервер остановлен пользователем через Ctrl+C.')
        print('\nСервер остановлен.')

    except Exception as error:
        logging.exception('Ошибка в работе сервера: %s', error)
        print(f'Ошибка сервера: {error}')

    finally:
        server_socket.close()
        logging.info('Серверный сокет закрыт.')


if __name__ == '__main__':
    main()
