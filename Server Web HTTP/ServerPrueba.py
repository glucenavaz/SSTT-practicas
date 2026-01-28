import socket

# Configuración del servidor
HOST = '0.0.0.0'    # escucha a cualquier interfaz de red
PORT = 8080         # Puerto de escucha

def start_server():
    # 1. Creación del socket
    # AF_INET indica IPv4 [cite: 58]
    # SOCK_STREAM indica TCP [cite: 59]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)

    # Esto permite reusar la dirección IP/Puerto si cierras y abres el server rápido.
    # Evita el error "Address already in use"
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 2. Vincular el socket a una IP y Puerto (Bind)
    # Liga el socket creado a la dirección y puerto pasados como tupla.
    server_socket.bind((HOST, PORT))

    # 3. Escuchar conexiones entrantes (Listen)
    # El servidor pasa a estado pasivo esperando clientes.
    server_socket.listen(64)
    
    print("Servidor escuchando en {}:{}...".format(HOST, PORT))

    while True:
        # 4. Aceptar conexión (Accept)
        # Se bloquea hasta que llega un cliente (3-way handshake).
        # Retorna un NUEVO socket (client_socket) dedicado a este cliente y su dirección.
        client_socket, client_addr = server_socket.accept()
        print("Conexión establecida con: {}".format(client_addr))

        # 5. Recibir datos (Recv)
        # Leemos del socket del cliente. 1024 es el buffer_size.
        data = client_socket.recv(1024)
        
        # Los datos llegan en binario, hay que decodificarlos para verlos como string
        mensaje_cliente = data.decode()
        print("Mensaje recibido:\n{}".format(mensaje_cliente))

        # 6. Enviar respuesta (Send)
        # Como es un servidor HTTP simple, debemos enviar una cabecera HTTP válida.
        # Si no enviamos "HTTP/1.1 200 OK...", el navegador creerá que ha habido error.
        respuesta = "HTTP/1.1 200 OK\r\n\r\nHola, soy tu servidor TCP de la UMU"
        
        # Hay que codificar el string a binario antes de enviar
        client_socket.send(respuesta.encode())

        # 7. Cerrar la conexión con el cliente (Close)
        # Importante: cerramos el socket del cliente, no el del servidor (que sigue en el bucle)
        client_socket.close()
        print("Conexión cerrada con el cliente.\n")

if __name__ == "__main__":
    start_server()