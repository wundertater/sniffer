"""Функции обработчики."""
import time
from scapy.all import PcapWriter


def ftp_control_handler(queue):
    """Обработчик для FTP-control пакетов, порт 21. Читает пакеты и записывает в файл ftp.pcap."""
    pcap_writer = PcapWriter("ftp.pcap", append=True, sync=True)
    while True:
        packet = queue.get()
        pcap_writer.write(packet)
        queue.task_done()


def ftp_data_handler(queue):
    """Обработчик для FTP-data пакетов, порт 20. Читает пакеты и записывает в файл ftp_data.pcap."""
    pcap_writer = PcapWriter("ftp_data.pcap", append=True, sync=True)
    while True:
        packet = queue.get()
        pcap_writer.write(packet)
        queue.task_done()


def other_handler(queue):
    """Обработчик для оставшихся пакетов."""
    pcap_writer = PcapWriter("other.pcap", append=True, sync=True)
    while True:
        packet = queue.get()
        if packet.haslayer('UDP') and 20000 <= packet.sport <= 25000:
            print(f"Обработчик 3: {time.strftime('%H:%M:%S')} "
                  f"пакет {packet.src}:{packet.sport} -> {packet.dst}:{packet.dport} игнорируется")
        elif packet.haslayer('TCP') and packet['TCP'].flags & 0x02:  # 0x02 SYN flag
            print(f"Обработчик 3: {time.strftime('%H:%M:%S')} "
                  f"пакет {packet.src}:{packet.sport} -> {packet.dst}:{packet.dport} инициирует соединение")
        else:
            pcap_writer.write(packet)
        queue.task_done()
