import socket
from _thread import start_new_thread
from urllib.parse import urlparse

blacklist = "blacklist.txt"
buffer_size = 8192

def load_blacklist():
    try:
        with open(blacklist, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

def start_proxy(ip, port):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((ip, port))
    proxy_socket.listen(5)
    print(f"Прокси-сервер запущен на {ip}:{port}")
    while True:
        client_socket, _ = proxy_socket.accept()
        start_new_thread(working_with_client, (client_socket,))

def working_with_client(client_socket):
    blacklist = load_blacklist()
    server_socket = None
    try:
        request = client_socket.recv(buffer_size)
        if not request:
            return

        first_line = request.split(b'\r\n')[0].decode('latin-1')
        parts = first_line.split()
        if len(parts) < 3:
            return

        method, full_url, http_version = parts

        parsed_url = urlparse(full_url)
        if not parsed_url.netloc:
            return

        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80

        if host.lower() in blacklist:
            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Connection: close\r\n\r\n"
                "<h1>403 FORBIDDEN</h1><p>Доступ запрещен</p>"
            )
            client_socket.sendall(response.encode('utf-8'))
            print(f"{full_url} - 403 Forbidden")
            return

        path = parsed_url.path if parsed_url.path else '/'
        if parsed_url.query:
            path += '?' + parsed_url.query

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))

        new_request = request.replace(
            f"{method} {full_url} {http_version}".encode(),
            f"{method} {path} {http_version}".encode()
        )

        server_socket.sendall(new_request)

        response = server_socket.recv(buffer_size)
        if response:
            status_line = response.split(b'\r\n')[0].decode('latin-1')
            status_parts = status_line.split(' ')
            if len(status_parts) >= 2:
                status_code = status_parts[1]
                status_text = ' '.join(status_parts[2:]) if len(status_parts) > 2 else 'OK'
                print(f"{full_url} - {status_code} {status_text}")
            else:
                print(f"{full_url} - 000 Unknown")
            
            client_socket.sendall(response)
            
            while True:
                try:
                    data = server_socket.recv(buffer_size)
                    if not data:
                        break
                    client_socket.sendall(data)
                except (socket.error, ConnectionResetError):
                    break

    except Exception as e:
        print(f"Ошибка при обработке запроса: {str(e)}")
    finally:
        client_socket.close()
        if server_socket:
            server_socket.close()

if __name__ == "__main__":
    start_proxy("127.0.0.2", 8590)