#!/usr/bin/env python3
# Author: Sameer Jha

# Importing required Libraries
import socket
import threading
import time
import os
import platform
import sys
import Crypto
from Crypto.Cipher import AES
import socket

try:
    import socks
except:
    import pip

    pip.main(["install", "pysocks"])
import subprocess

try:
    import dns
except:
    import pip

    pip.main(["install", "pydns"])
try:
    from colorama import Fore, Back, Style
except:
    import pip

    pip.main(["install", "colorama"])


# Defining some inital setup values
user_name_peer = ""
username = ""
key_value = ""
socket_val = ""

sock0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# Colorama Class
class c:
    r = "\033[0;31m"
    g = "\033[0;31m"
    o = "\033[0;33m"
    b = "\033[0;94m"
    p = "\033[0;35m"
    w = "\033[0;97m"
    rb = "\033[01;31m"
    gb = "\033[01;31m"
    ob = "\033[01;33m"
    bb = "\033[01;94m"
    pb = "\033[01;35m"
    wb = "\033[01;97m"
    d = "\033[0;00m"


# Making funtions for various operations
def intro():
    logo = """

      /$$$$$$                                 /$$$$$$  /$$                   /$$
     /$$__  $$                               /$$__  $$| $$                  | $$
    | $$  \__/  /$$$$$$   /$$$$$$$  /$$$$$$$| $$  \__/| $$$$$$$   /$$$$$$  /$$$$$$
    |  $$$$$$  /$$__  $$ /$$_____/ /$$_____/| $$      | $$__  $$ |____  $$|_  $$_/
    \____  $$| $$$$$$$$| $$      |  $$$$$$  | $$      | $$  \ $$  /$$$$$$$  | $$
    /$$  \ $$| $$_____/| $$       \____  $$ | $$    $$| $$  | $$ /$$__  $$  | $$ /$$
    |  $$$$$$/|  $$$$$$$|  $$$$$$$ /$$$$$$$/|  $$$$$$/| $$  | $$|  $$$$$$$  |  $$$$/
    \______/  \_______/ \_______/|_______/   \______/ |__/  |__/ \_______/   \___/
    """

    intro = """
                                Developed by GodFather
                                --------- -- ---------
                    `Uses 'AES-256 bit' encryption & Tor Proxies!`
                     ---- -------- ---- ---------- - --- -------
    """

    print(Fore.GREEN + logo)
    print(Fore.RED + Style.BRIGHT + intro)
    print(Fore.RESET)


class os_type:
    os_type1 = platform.system()


class sockets:
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def init_proxy():
    subprocess.call("service tor restart", shell=True)
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)
    socket.socket = socks.socksocket
    try:
        import requests
    except:
        import pip

        pip.main(["install", "requests"])
    r = requests.get("http://ipinfo.io/ip").content
    print(f"Tor IP Address: {str(r.strip())}")


def enc_msg(message, key):
    iv = "Yu_920_v^:[}=+%$"
    enc = AES.new(key, AES.MODE_CFB, iv)
    msg = enc.encrypt(str(message))
    return str(msg, 'utf-8')


def dec_msg(message, key):
    iv = "Yu_920_v^:[}=+%$"
    dec = AES.new(key, AES.MODE_CFB, iv)
    msg = dec.decrypt(str(message))
    return str(msg, 'utf-8')


def start_server(host, port):
    global user_name_peer
    global username
    global client
    global sock0
    sock0.bind((host, int(port)))
    sock0.listen(1)
    (client, (ip, port)) = sock0.accept()
    client.send(bytes(username, 'utf-8'))
    if os_type.os_type1 == "Linux":
        user_name_peer = str(client.recv(1024), 'utf-8')
        print(
            c.w
            + "["
            + c.g
            + "info"
            + c.w
            + "]: "
            + c.b
            + f"{user_name_peer} "
            + c.w
            + "has joined your channel..."
            + c.d
        )
    elif os_type.os_type1 == "Windows":
        user_name_peer = str(client.recv(1024), 'utf-8')
        print(f"[info]: {user_name_peer} has joined your channel...")


def recieve_data():
    global client
    global user_name_peer
    global key_value
    while True:
        data = client.recv(10240)
        if os_type.os_type1 == "Linux":
            print(c.g + f"\n{user_name_peer}:" + c.w + f" {dec_msg(data, key_value)}" + c.d)
        elif os_type == "Windows":
            print(f"\n{user_name_peer}: {dec_msg(data, key_value)}")


def allow_connections():
    global user_name_peer
    global username
    global client
    global sock0
    while True:
        (client, (ip, port)) = sock0.accept()
        client.send(str(username))
        if os_type.os_type1 == "Linux":
            user_name_peer = str(client.recv(1024), 'utf-8')
            print(
                c.w
                + "["
                + c.g
                + "info"
                + c.w
                + "]: "
                + c.b
                + f"{user_name_peer} "
                + c.w
                + "has joined your channel..."
                + c.d
            )
        elif os_type.os_type1 == "Windows":
            user_name_peer = str(client.recv(1024), 'utf-8')
            print(f"[info]: {user_name_peer} has joined your channel...")


def chat(host, port):
    start_server(host, port)
    # 	t1 = threading.Thread(target=allow_connections)
    # 	t1.setDaemon(True)
    # 	t1.start()
    global key_value
    chat_thread = []
    t = threading.Thread(target=recieve_data)
    chat_thread.append(t)
    t.setDaemon(True)
    t.start()
    while True:
        if os_type.os_type1 == "Linux":
            try:
                s_msg = input(c.b + "Send Message: " + c.w)
                client.send(enc_msg(s_msg, key_value))
            except KeyboardInterrupt:
                ex_ = input("Are you sure you would like to exit (y/n): ")
                client.send(enc_msg(str(username + " has left the chat!"), key_value))
                client.close()
                sys.exit(0)

            except Exception as e:
                print(f"Socket Connection Error. {e}")
                try:
                    exit(0)
                except:
                    sys.exit(1)
        elif os_type.os_type1 == "Windows":
            try:
                s_msg = input("Send Message: ")
                client.send(enc_msg(s_msg, key_value))
            except KeyboardInterrupt:
                ex_ = input("Are you sure you would like to exit (y/n): ")
                if ex_ == "y":
                    print("\n")
                    client.send(
                        enc_msg(str(username + " has left the chat!"), key_value)
                    )
                    client.close()
                    try:
                        exit(0)
                    except:
                        sys.exit(0)
            except Exception as e:
                print("Socket Connection Error.")
                try:
                    exit(0)
                except:
                    sys.exit(1)


def exec_server():
    global key_value
    global username
    host = input("Server to host channel on: ")
    port = input("Port to run server on: ")
    key = input("Encryption Key: ")
    username = input("Username: ")
    cc_val = 1
    while cc_val == 1:
        if len(username) > 20:
            print("Username should not exceed 20 characters.")
            username = input("Set your username: ")
        else:
            cc_val = 0
    if len(key) > 32:
        for _ in range(10000):
            if len(key) == 32:
                break
            key = key[:1]
        key_value = key
    elif len(key) < 32:
        for _ in range(10000):
            if len(key) == 32:
                break
            key = key + "}"
        key_value = key
    chat(host, port)


def recieve_data1():
    global user_name_peer
    global key_value
    global sock0
    while True:
        try:
            data = sock0.recv(10240)
            if os_type.os_type1 == "Linux":
                print(c.g + f"\n{user_name_peer}:" + c.w + f" {dec_msg(data, key_value)}" + c.d)
            elif os_type.os_type1 == "Windows":
                print(f"\n{user_name_peer}: {dec_msg(data, key_value)}")
        except Exception as e:
            print(f"\nChannel has been closed {e}")
            try:
                exit(0)
            except:
                sys.exit(1)


def join_server():
    global key_value
    global user_name_peer
    global socket_val
    global sock0
    server_addr = input("Server Address: ")
    server_port = int(input("Server Port: "))
    key = input("Encryption Key: ")
    username = input("Set your username: ")
    cc_val = 1
    while cc_val == 1:
        if len(username) > 20:
            print("Username should not exceed 20 characters.")
            username = input("Set your username: ")
        else:
            cc_val = 0
    if len(key) > 32:
        for _ in range(10000):
            if len(key) == 32:
                break
            key = key[:1]
        key_value = key
    elif len(key) < 32:
        for _ in range(10000):
            if len(key) == 32:
                break
            key = key + "}"
        key_value = key
    sock0.connect((server_addr, server_port))
    user_name_peer = sock0.recv(10240)
    print(user_name_peer)
    sock0.send(bytes(username, 'utf-8'))
    t = threading.Thread(target=recieve_data1)
    t.setDaemon(True)
    t.start()
    while True:
        try:
            s_msg = input("Send Message: ")
            sock0.send(enc_msg(str(s_msg), key_value))
        except KeyboardInterrupt:
            ex_ = input("Are you sure you would like to exit (y/n): ")
            if ex_ == "y":
                print("\n")
                sock0.send(enc_msg(str(username + " has left the chat!"), key_value))
                sock0.close()
                try:
                    exit(0)
                except:
                    sys.exit(0)
        except Exception as e:
            print(f"Socket Connection Error. {e}")
            try:
                exit(0)
            except:
                sys.exit(1)


if __name__ == "__main__":
    intro()
    # init_proxy()
    # subprocess.call('service tor stop', shell=True)
    init_proxy()
    print(
        """
    1 = Create a Channel
    2 = Join a Channel
    """
    )
    opt = input("Option: ")
    if opt == "1":
        exec_server()
    elif opt == "2":
        join_server()
