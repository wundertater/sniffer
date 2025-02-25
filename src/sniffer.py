"""Программа перехватывает сетевой трафик и распределяет его в файлы."""
import argparse
import threading
import queue
from scapy.packet import Packet
from scapy.all import sniff
from handlers import ftp_control_handler, ftp_data_handler, other_handler

# Очереди для передачи данных обработчикам
ftp_control_queue = queue.Queue()
ftp_data_queue = queue.Queue()
other_queue = queue.Queue()

# Определение обработчиков в отдельных потоках
ftp_control_thread = threading.Thread(target=ftp_control_handler, args=(ftp_control_queue,))
ftp_data_thread = threading.Thread(target=ftp_data_handler, args=(ftp_data_queue,))
other_thread = threading.Thread(target=other_handler, args=(other_queue,))

ftp_control_thread.start()
ftp_data_thread.start()
other_thread.start()


def packet_distribution(packet: Packet):
    """
    Распределительный механизм.

    :param packet: захваченный сетевой пакет
    """
    if packet.haslayer('TCP'):
        sport, dport = packet.sport, packet.dport
        # FTP control
        if sport == 21 or dport == 21:
            ftp_control_queue.put(packet)
        # FTP data
        elif sport == 20 or dport == 20:
            ftp_data_queue.put(packet)
        else:
            other_queue.put(packet)
    elif packet.haslayer('UDP'):
        other_queue.put(packet)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Сниффер и распределитель данных.")
    arg_parser.add_argument("EthX", type=str, help="Имя сетевого интерфейса.")
    args = arg_parser.parse_args()

    sniff(iface=args.EthX, prn=packet_distribution, store=False)
