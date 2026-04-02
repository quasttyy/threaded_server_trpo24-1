import socket
import threading
import queue
import sys


# ============================================================
#                    ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def safe_input_string(prompt: str, default: str) -> str:
    """
    Безопасный ввод строки с значением по умолчанию.

    Как работает:
    1. Показываем пользователю приглашение.
    2. Если он просто нажал Enter, берем default.
    3. Убираем лишние пробелы по краям.

    Пример:
    Пользователь нажал Enter -> вернется default.
    Пользователь ввел "  localhost  " -> вернется "localhost".
    """
    user_value = input(f"{prompt} [{default}]: ").strip()
    if user_value == "":
        return default
    return user_value


def safe_input_int(prompt: str, default: int, min_value: int, max_value: int) -> int:
    """
    Безопасный ввод целого числа.

    Что делает функция:
    - просит пользователя ввести число;
    - если пользователь ничего не ввел, берется значение по умолчанию;
    - если введено не число, повторяет запрос;
    - если число вне допустимого диапазона, повторяет запрос.

    Это удобно для новичка, потому что программа не "падает"
    из-за неправильного ввода.
    """
    while True:
        user_value = input(f"{prompt} [{default}]: ").strip()

        # Если пользователь просто нажал Enter — используем значение по умолчанию
        if user_value == "":
            return default

        try:
            number = int(user_value)
        except ValueError:
            print("Ошибка: нужно ввести целое число.")
            continue

        if number < min_value or number > max_value:
            print(f"Ошибка: число должно быть в диапазоне от {min_value} до {max_value}.")
            continue

        return number


def resolve_host_to_ip(host: str) -> str:
    """
    Преобразует имя хоста в IP-адрес.

    Например:
    - "localhost" -> "127.0.0.1"
    - "ya.ru" -> какой-то IP
    - "8.8.8.8" -> "8.8.8.8"

    Если хост не удается распознать, возбуждается исключение.
    """
    return socket.gethostbyname(host)


def draw_progress_bar(done: int, total: int, bar_length: int = 40) -> None:
    """
    Рисует progress bar (индикатор прогресса) в командной строке.

    done  - сколько портов уже проверено
    total - сколько портов всего нужно проверить

    Пример визуально:
    [##########------------------------------] 25.00% (250/1000)

    Важный момент:
    - используется '\r', чтобы перерисовывать строку на том же месте;
    - flush=True нужен, чтобы вывод сразу появился на экране.
    """
    if total == 0:
        percent = 100.0
        filled = bar_length
    else:
        percent = (done / total) * 100
        filled = int(bar_length * done / total)

    bar = "#" * filled + "-" * (bar_length - filled)

    # end="" означает: не переходить на новую строку
    print(f"\rПрогресс: [{bar}] {percent:6.2f}% ({done}/{total})", end="", flush=True)


# ============================================================
#               КЛАСС ДЛЯ МНОГОПОТОЧНОГО СКАНЕРА
# ============================================================

class PortScanner:
    """
    Класс реализует многопоточный TCP-сканер портов.

    Почему класс удобен:
    - все данные лежат в одном месте;
    - проще передавать их между методами;
    - код становится логичнее и чище.

    Основные поля:
    - target_host: что ввел пользователь (например, localhost или 8.8.8.8)
    - target_ip: IP-адрес после преобразования
    - start_port: начальный порт
    - end_port: конечный порт
    - thread_count: сколько потоков использовать
    - timeout: время ожидания ответа от одного порта
    """

    def __init__(self, target_host: str, target_ip: str,
                 start_port: int, end_port: int,
                 thread_count: int, timeout: float = 0.3):
        self.target_host = target_host
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.thread_count = thread_count
        self.timeout = timeout

        # Очередь задач.
        # В нее мы положим номера портов, которые нужно проверить.
        self.port_queue = queue.Queue()

        # Список открытых портов.
        # Потоки будут находить открытые порты и добавлять их сюда.
        self.open_ports = []

        # Сколько портов уже проверено.
        self.scanned_count = 0

        # Всего портов нужно проверить.
        self.total_ports = self.end_port - self.start_port + 1

        # Блокировка нужна, чтобы несколько потоков
        # не испортили друг другу общие данные.
        self.lock = threading.Lock()

        # Отдельная блокировка для красивого вывода в консоль.
        # Иначе потоки могут печатать одновременно,
        # и текст смешается.
        self.print_lock = threading.Lock()

    def fill_queue(self) -> None:
        """
        Заполняет очередь всеми портами в заданном диапазоне.
        Каждый порт — это отдельная задача для потока.
        """
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

    def scan_one_port(self, port: int) -> bool:
        """
        Проверяет один конкретный порт.

        Возвращает:
        - True, если порт открыт
        - False, если порт закрыт или недоступен

        Логика:
        1. Создаем TCP-сокет.
        2. Устанавливаем таймаут, чтобы не ждать слишком долго.
        3. Пытаемся подключиться.

        Почему используется connect_ex, а не connect:
        - connect_ex удобен тем, что не выбрасывает исключение при обычной неудаче,
          а возвращает код результата.
        - 0 означает успешное подключение.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((self.target_ip, port))
            return result == 0
        except socket.error:
            # Любая сетевая ошибка трактуется как "не удалось подключиться"
            return False
        finally:
            sock.close()

    def worker(self) -> None:
        """
        Функция-поток (рабочий поток).

        Каждый поток:
        1. Берет из очереди номер порта.
        2. Проверяет этот порт.
        3. Если порт открыт — запоминает его.
        4. Увеличивает счетчик прогресса.
        5. Сообщает очереди, что задача завершена.

        Поток работает до тех пор, пока очередь не опустеет.
        """
        while True:
            try:
                # get_nowait() берет задачу из очереди без ожидания.
                # Если очередь пуста, будет исключение queue.Empty.
                port = self.port_queue.get_nowait()
            except queue.Empty:
                # Работы больше нет — поток завершает работу.
                break

            is_open = self.scan_one_port(port)

            # Работаем с общими данными только под блокировкой.
            with self.lock:
                if is_open:
                    self.open_ports.append(port)

                self.scanned_count += 1
                current_done = self.scanned_count

            # Печать делаем отдельно под print_lock,
            # чтобы строки не перемешивались.
            with self.print_lock:
                if is_open:
                    # Сначала переводим строку, чтобы сообщение не "ломало" progress bar
                    print(f"\nПорт {port} открыт")

                # После возможного сообщения заново рисуем progress bar
                draw_progress_bar(current_done, self.total_ports)

            # Сообщаем очереди: эта задача выполнена
            self.port_queue.task_done()

    def run(self) -> list[int]:
        """
        Запускает многопоточное сканирование.

        Шаги:
        1. Заполняем очередь портами.
        2. Создаем несколько потоков.
        3. Запускаем все потоки.
        4. Ждем завершения всех потоков.
        5. Сортируем список открытых портов.
        6. Возвращаем результат.

        Возвращает:
        - отсортированный список открытых портов
        """
        self.fill_queue()

        threads = []

        for _ in range(self.thread_count):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)

        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()

        # После progress bar переводим строку,
        # чтобы следующий print не ехал в той же строке
        print()

        # Требование задания: вывести список открытых портов по порядку.
        self.open_ports.sort()

        return self.open_ports


# ============================================================
#                         ГЛАВНАЯ ЧАСТЬ
# ============================================================

def main():
    """
    Главная функция программы.

    Здесь:
    - получаем данные от пользователя;
    - проверяем хост;
    - запускаем сканер;
    - выводим итоговый список открытых портов.
    """
    print("TCP-сканер портов")
    print("-" * 60)

    # Пользователь вводит имя хоста или IP-адрес
    target_host = safe_input_string("Введите имя хоста или IP-адрес", "localhost")

    # Дополнительно спросим диапазон портов и число потоков.
    # Это не мешает заданию, а делает программу полезнее и гибче.
    start_port = safe_input_int("Введите начальный порт", 1, 1, 65535)
    end_port = safe_input_int("Введите конечный порт", 1024, 1, 65535)

    # Проверка: начальный порт не должен быть больше конечного
    if start_port > end_port:
        print("Ошибка: начальный порт не может быть больше конечного.")
        return

    # Количество потоков.
    # Слишком много потоков тоже плохо: это лишняя нагрузка.
    thread_count = safe_input_int("Введите количество потоков", 100, 1, 1000)

    # Преобразуем имя хоста в IP.
    try:
        target_ip = resolve_host_to_ip(target_host)
    except socket.gaierror:
        print("Ошибка: не удалось определить IP-адрес по указанному хосту.")
        return

    print("\nПараметры сканирования:")
    print(f"Хост: {target_host}")
    print(f"IP: {target_ip}")
    print(f"Диапазон портов: {start_port}-{end_port}")
    print(f"Количество потоков: {thread_count}")
    print("-" * 60)

    scanner = PortScanner(
        target_host=target_host,
        target_ip=target_ip,
        start_port=start_port,
        end_port=end_port,
        thread_count=thread_count,
        timeout=0.3
    )

    open_ports = scanner.run()

    print("-" * 60)
    print("Сканирование завершено.")

    if open_ports:
        print("Открытые порты (по порядку):")
        for port in open_ports:
            print(port)
    else:
        print("Открытые порты не найдены в заданном диапазоне.")


# Эта конструкция означает:
# код ниже выполнится только если файл запущен напрямую,
# а не импортирован как модуль в другой файл.
if __name__ == "__main__":
    main()