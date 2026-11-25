#!/usr/bin/env python3
"""
echo_server.py — локальні «цільові» сервіси для демонстрації (без інтернету).

TCP-echo на 9000, 9002–9005 і UDP-echo на 9001 (127.0.0.1).
Запуск: python scripts/echo_server.py
"""
import socket, threading

HOST = '127.0.0.1'
TCP_PORTS = [9000, 9002, 9003, 9004, 9005]
UDP_PORT = 9001


def tcp_echo(port):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((HOST, port)); ls.listen(64)

    def handle(c):
        with c:
            while True:
                d = c.recv(4096)
                if not d:
                    return
                c.sendall(b'ECHO:' + d)

    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(b'ECHO:' + d, a)


if __name__ == '__main__':
    for p in TCP_PORTS:
        threading.Thread(target=tcp_echo, args=(p,), daemon=True).start()
    threading.Thread(target=udp_echo, args=(UDP_PORT,), daemon=True).start()
    print(f'[echo] TCP {TCP_PORTS}  UDP {UDP_PORT}  на {HOST}. Ctrl+C — зупинка.')
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
