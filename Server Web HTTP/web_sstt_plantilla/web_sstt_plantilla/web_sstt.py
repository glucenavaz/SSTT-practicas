# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta, timezone # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs



BUFSIZE = 8192 # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 20 # Timout para la conexión persistente
MAX_ACCESOS = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
            "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    # Convertimos a bytes si es necesario
    if type(data) == str:
        data = data.encode()
    return cs.send(data)


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    # Leemos hasta BUFSIZE bytes
    data = cs.recv(BUFSIZE)
    return data.decode()    # Devolvemos el string decodificado


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    nombre_cookie = "cookie_counter_65YY"   #Edu cuando puedas pon en YY los 2 ultimos digitos de tu DNI

    # Se analizan las cabeceras en headers para buscar la cabecera Cookie
    for linea in headers:
        if linea.startswith("Cookie:"):
            # Obtenemos el contenido de la cabecera
            cookie_header_content = linea.split(":", 1)[1].strip()

            # Separamos las cookies individuales
            cookies = cookie_header_content.split(";")

            for cookie in cookies:
                # Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Comprobamos si es la cookie que buscamos
                    if key == nombre_cookie:
                        try:
                            # Intentamos convertir el valor a entero
                            val = int(value)
                            
                            # Si se encuentra y tiene el valor MAX_ACCESOS se devuelve MAX_ACCESOS
                            if val >= MAX_ACCESOS:
                                return MAX_ACCESOS
                            
                            # Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
                            if 1 <= val < MAX_ACCESOS:
                                val += 1
                                return val
                        except ValueError:
                            return 1
    
    # Si no se encuentra cookie_counter , se devuelve 1
    return 1


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()*"""
    comprobacion = False
    while not comprobacion:

        data = recibir_mensaje(cs)

        # Si el cliente cierra la conexión prematuramente (recv devuelve vacío), salimos forzosamente
        if not data:
            logger.info("El cliente cerró la conexión (TCP FIN).")
            break

        """ PROCESAR """
        logger.info("Petición recibida:\n{}".format(data))

        lineas = data.split('\r\n', 1) 
        request_line = lineas[0]

        partes = request_line.split(' ')
        method = ""
        url= ""
        version= ""
        request_valida = False

        if len(partes) == 3:
            method = partes[0]  # GET
            url = partes[1]  # index.html
            version = partes[2] # 1.1

            er_method = r"^GET$"        #Cambiado [A-Z]+ por GET ya que solo nos piden el método GET
            er_url = r"^\S+$"
            er_version = r"^HTTP/1\.1$" #Debe ser 1.1

            # HACEMOS EL MATCH
            if (re.fullmatch(er_method, method) and 
                re.fullmatch(er_url, url) and 
                re.fullmatch(er_version, version)):
                request_valida = True

        else:
            print("Error: La línea de petición no tiene el formato correcto")

        # SI LA PETICIÓN ES VÁLIDA (Cumple formato HTTP 1.1 y GET)
        if request_valida:
            # Leer URL y eliminar parámetros si los hubiera
            if "?" in url:
                url = url.split("?")[0]
            
            # Comprobar si el recurso solicitado es /, en ese caso el recurso es index.html
            if url == "/":
                url = "/index.html"
            
            # Construir la ruta absoluta del recurso (webroot + recurso solicitado)
            filepath = os.path.join(webroot, url.lstrip("/"))

            # Comprobar que el fichero existe, si no devolver Error 404 "Not found"
            if not os.path.isfile(filepath):
                # ERROR 404
                logger.warning("Fichero no encontrado: {}".format(filepath))
                error_msg = "<h1>404 Not Found</h1><p>El recurso no existe.</p>"

                # Construccion cabecera:
                # Linea de estado
                header = "HTTP/1.1 404 Not Found\r\n"
                # Fecha (según RFC de HTTP 1.1):
                header += "Date: {}\r\n".format(datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'))
                # Nombre del servidor:
                header += "Server: SSTT\r\n"
                # Content-length:
                header += "Content-Length: {}\r\n".format(len(error_msg))
                # Conexion:
                header += "Connection: keep-alive\r\n"
                # Content-type:
                header += "Content-Type: text/html\r\n"

                # Linea vacia:
                header += "\r\n"

                enviar_mensaje(cs, header.encode() + error_msg.encode())
            else:
                    # El fichero existe, seguimos procesando
                    
                    # 1. Extraer y Analizar las cabeceras (Headers)
                    # Si hay contenido después de la primera línea, lo troceamos por saltos de línea
                    headers_list = lineas[1].split('\r\n') if len(lineas) > 1 else []
                    
                    logger.info("--- Cabeceras recibidas ---")
                    for h in headers_list:
                        if h: # Si la línea no está vacía, la imprimimos
                            logger.info(h)
                    
                    # 2. Gestión de Cookies
                    # Inicializamos a 1 por defecto (para imágenes u otros recursos)
                    cookie_val = 1 
                    
                    # El enunciado dice: "El valor variará solo para cada petición... al recurso index.html"
                    if url == "/index.html":
                        cookie_val = process_cookies(headers_list, cs)

                    # Ahora cookie_val tiene el número de visita actual o MAX_ACCESOS (10)

                    #ERROR 403
                    if cookie_val >= MAX_ACCESOS:
                        logger.warning("Acceso denegado: Límite de cookies alcanzado")
                        error_msg = "<h1>403 Forbidden</h1><p>Has superado el limite de accesos.</p>"
                        
                        header = "HTTP/1.1 403 Forbidden\r\n"
                        header += "Date: {}\r\n".format(datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'))
                        header += "Server: SSTT\r\n"
                        header += "Content-Length: {}\r\n".format(len(error_msg))
                        header += "Connection: close\r\n\r\n" # Cerramos conexión
                        
                        enviar_mensaje(cs, header.encode() + error_msg.encode())
                        comprobacion = True # Forzamos salida del bucle

                    else:
                        # 4. ÉXITO (200 OK) - Servir el fichero
                        file_size = os.path.getsize(filepath)
                        filename, file_extension = os.path.splitext(filepath)
                        extension = file_extension.lstrip(".")
                        content_type = filetypes.get(extension, "application/octet-stream")

                        # Construimos cabeceras 200 OK
                        header = "HTTP/1.1 200 OK\r\n"
                        header += "Date: {}\r\n".format(datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'))
                        header += "Server: SSTT\r\n"
                        header += "Content-Length: {}\r\n".format(file_size)
                        header += "Content-Type: {}\r\n".format(content_type)
                        
                        if url == "/index.html":
                        # Max-Age=30 segundos como pide el enunciado
                            header += "Set-Cookie: cookie_counter_65YY={}; Max-Age=30\r\n".format(cookie_val)

                            header += "Connection: keep-alive\r\n\r\n"

                            # Enviamos cabeceras
                            enviar_mensaje(cs, header)

                            # 5. Enviar contenido del fichero por bloques
                            with open(filepath, 'rb') as f:
                                while True:
                                    chunk = f.read(BUFSIZE)
                                    if not chunk:
                                        break
                                    cs.send(chunk)

        else:
            # ERROR 400 Bad Request (Si request_valida no es true)
            error_msg = "<h1>400 Bad Request</h1>"
            header = "HTTP/1.1 400 Bad Request\r\n"
            header += "Content-Length: {}\r\n".format(len(error_msg))
            header += "Connection: close\r\n\r\n"
            enviar_mensaje(cs, header.encode() + error_msg.encode())
            comprobacion = True

        # Persistencia
        if not comprobacion:
            recibido, _, _ = select([cs], [], [], TIMEOUT_CONNECTION)

            if not recibido:
                # Si recibido está vacío, significa que ha saltado el TIMEOUT
                logger.info("Timeout de persistencia alcanzado. Cerrando.")
                comprobacion = True
            
            # Si recibido tiene datos, el bucle while se repite 
            # y el 'recibir_mensaje' del principio leerá la nueva petición inmediatamente.


    


    """* Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
            sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
                    * Devuelve una lista con los atributos de las cabeceras.
                    * Comprobar si la versión de HTTP es 1.1
                    * Comprobar si es un método GET. Si no devolver un error Error 405 "Method Not Allowed".
                    * Leer URL y eliminar parámetros si los hubiera (imagen u otra cosa, solo devolver index.html)
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                    el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                    Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                    las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                    Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    """ Procesamiento temporal para probar la conexión """

def main():
    """ Función principal del servidor
    """

    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        """ Funcionalidad a realizar
        * Crea un socket TCP (SOCK_STREAM)
        * Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        * Vinculamos el socket a una IP y puerto elegidos

        * Escucha conexiones entrantes

        * Bucle infinito para mantener el servidor activo indefinidamente
            - Aceptamos la conexión

            - Creamos un proceso hijo

            - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()

            - Si es el proceso padre cerrar el socket que gestiona el hijo.
        """
        # 1. Crear el socket TCP (IPv4, Stream)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Permitir reusar la dirección
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 3. Vincular a IP y Puerto (Bind) usando los argumentos
        server_socket.bind((args.host, args.port))

        # 4. Escuchar conexiones (Listen)
        server_socket.listen(MAX_ACCESOS)

        # 5. Bucle infinito para aceptar clientes
        while True:
            # Aceptar conexión
            client_socket, client_addr = server_socket.accept()
            logger.info("Conexión entrante de: {}".format(client_addr))

            # --- GESTIÓN DE PROCESOS (FORK)  ---
            pid = os.fork()

            if pid == 0:
                # PROCESO HIJO
                server_socket.close()

                # Delegamos TODA la responsabilidad a la función
                process_web_request(client_socket, args.webroot)
    
                # Al terminar (cuando process_web_request decida salir), cerramos
                cerrar_conexion(client_socket)
                sys.exit(0)
            
            else:
                # PROCESO PADRE
                # El padre sigue escuchando, no necesita el socket del cliente actual
                client_socket.close()


    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario.")
        try:
            server_socket.close()
        except:
            pass

if __name__== "__main__":
    main()
