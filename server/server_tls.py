import socket
import ssl

HOST = '127.0.0.1'
PORT = 8765

CERT = '../certs/cert.pem'
KEY = '../certs/key.pem'

def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    ssl_context.load_cert_chain(certfile = CERT, keyfile = KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f'TLS server listening on https://{HOST}:{PORT}')

        while True:
            connection, address = sock.accept()
            print(f'TCP Connection from {address}')

            try:
                with ssl_context.wrap_socket(connection, server_side = True) as tls_connect:
                    print (f'TLS handshake Complete')

                    data = tls_connect.recv(4096)
                    print(f'Recieved {len(data)} bytes {data!r}')

                    tls_connect.sendall(b'TLS OK\n')
                    tls_connect.close()

                    try:
                        tls_connect.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
            
            except ssl.SSLError as err:
                print(f'TLS error: {err}')
            except Exception as exc:
                print(f'Unexpected error {exc}')

if __name__ == '__main__':
    main()