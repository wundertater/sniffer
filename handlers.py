"""Функции обработчики."""
import time


def ftp_control_handler(queue):
    """Обработчик для FTP-control пакетов, порт 21. Читает пакеты и записывает в файл ftp.pcap."""
    with open("ftp.pcap", "wb") as f:
        while True:
            packet = queue.get()
            f.write(bytes(packet))
            queue.task_done()


def ftp_data_handler(queue):
    """Обработчик для FTP-data пакетов, порт 20. Читает пакеты и записывает в файл ftp_data.pcap."""
    with open("ftp_data.pcap", "wb") as f:
        while True:
            packet = queue.get()
            f.write(bytes(packet))
            queue.task_done()


def other_handler(queue):
    """Обработчик для оставшихся пакетов."""
    with open("other.pcap", "wb") as f:
        while True:
            packet = queue.get()
            if packet.haslayer('UDP') and 20000 <= packet.sport <= 25000:
                print(f"Обработчик 3: {time.strftime('%H:%M:%S')} "
                      f"пакет {packet.src}:{packet.sport} -> {packet.dst}:{packet.dport} игнорируется")
            elif packet.haslayer('TCP') and packet['TCP'].flags & 0x02:  # 0x02 SYN flag
                print(f"Обработчик 3: {time.strftime('%H:%M:%S')} "
                      f"пакет {packet.src}:{packet.sport} -> {packet.dst}:{packet.dport} инициирует соединение")
            else:
                f.write(bytes(packet))
            queue.task_done()
