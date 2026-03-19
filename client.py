import socket


# =========================
# НАСТРОЙКИ ПО УМОЛЧАНИЮ
# =========================
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 9090
BUFFER_SIZE = 1024
MAX_PORT = 65535



def ask_host(default_host: str) -> str:
    """
    Безопасно запрашивает у пользователя имя хоста или IP-адрес сервера.

    Если пользователь ничего не ввел, используется значение по умолчанию.
    """
    while True:
        user_input = input(
            f'Введите адрес сервера [по умолчанию {default_host}]: '
        ).strip()

        if user_input == '':
            return default_host

        return user_input



def ask_port(default_port: int) -> int:
    """
    Безопасно запрашивает номер порта.

    Проверяем, что:
    - введено число;
    - число находится в диапазоне 1..65535.
    """
    while True:
        user_input = input(
            f'Введите порт сервера [по умолчанию {default_port}]: '
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



def receive_line_from_server(client_socket: socket.socket) -> str:
    """
    Принимает от сервера ровно одну строку, заканчивающуюся символом '\n'.

    Почему нельзя просто сделать один recv() и считать, что это "одно сообщение"?
    Потому что TCP - потоковый протокол.
    Он не знает, где начинается и где заканчивается человеческая строка.

    Поэтому клиент собирает данные из сети до тех пор,
    пока не увидит символ конца строки '\n'.
    """
    text_buffer = ''

    while True:
        data = client_socket.recv(BUFFER_SIZE)

        if not data:
            return text_buffer

        text_buffer += data.decode('utf-8', errors='replace')

        if '\n' in text_buffer:
            line, _rest = text_buffer.split('\n', 1)
            return line.rstrip('\r')



def main() -> None:
    """
    Основная функция клиента.

    Этот клиент специально оставлен простым.
    Для проверки многопоточного сервера достаточно запустить НЕСКОЛЬКО копий
    этого же клиента в разных окнах терминала.

    Каждый экземпляр клиента создаст собственное TCP-соединение,
    а сервер должен будет обслуживать их параллельно в разных потоках.
    """
    host = ask_host(DEFAULT_HOST)
    port = ask_port(DEFAULT_PORT)

    print('[КЛИЕНТ] Запуск клиента...')

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
        print(f'[КЛИЕНТ] Соединение с сервером установлено: {host}:{port}')
        print('[КЛИЕНТ] Для проверки многопоточности можно запустить ещё один экземпляр этого клиента.')

        while True:
            message = input('Введите строку (для выхода введите exit): ')

            # Одна строка протокола = введенный текст + '\n'.
            message_to_send = message + '\n'
            message_bytes = message_to_send.encode('utf-8')

            # sendall() сам пытается отправить все байты,
            # но мы дополнительно печатаем в консоль понятное служебное сообщение.
            client_socket.sendall(message_bytes)
            print(
                f'[КЛИЕНТ] Отправлено серверу {len(message_bytes)} байт: '
                f'{message_to_send!r}'
            )

            if message == 'exit':
                final_response = receive_line_from_server(client_socket)
                if final_response:
                    print(f'[КЛИЕНТ] Ответ сервера: {final_response!r}')
                print('[КЛИЕНТ] Получена команда завершения. Закрываем клиент.')
                break

            response = receive_line_from_server(client_socket)

            if response == '':
                print('[КЛИЕНТ] Сервер закрыл соединение.')
                break

            print(f'[КЛИЕНТ] Получен ответ от сервера: {response!r}')

    except ConnectionRefusedError:
        print(
            '[КЛИЕНТ] Ошибка: сервер недоступен. '
            'Проверьте, запущен ли сервер и верны ли адрес/порт.'
        )

    except socket.gaierror:
        print(
            '[КЛИЕНТ] Ошибка: не удалось распознать имя хоста. '
            'Проверьте введенный адрес сервера.'
        )

    except Exception as error:
        print(f'[КЛИЕНТ] Ошибка: {error}')

    finally:
        client_socket.close()
        print('[КЛИЕНТ] Разрыв соединения с сервером.')


if __name__ == '__main__':
    main()
