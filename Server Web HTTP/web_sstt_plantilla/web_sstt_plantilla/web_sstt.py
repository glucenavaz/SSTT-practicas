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
TIMEOUT_CONNECTION = 29 # Timout para la conexión persistente - 6 + 5 + 3 + 5 + 10
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
    # Convertimos a bytes si es necesario
    if type(data) == str:
        data = data.encode()
    return cs.send(data)


def recibir_mensaje(cs):
    # Leemos hasta BUFSIZE bytes
    data = cs.recv(BUFSIZE)
    return data.decode()    # Devolvemos el string decodificado


def cerrar_conexion(cs):
    cs.close()


def process_cookies(headers,  cs):
    nombre_cookie = "cookie_counter_6535"

    # Se analizan las cabeceras en headers para buscar la cabecera cookie
    for linea in headers:
        if linea.startswith("Cookie:"):
            # Obtenemos el contenido de la cabecera
            cookie_header_content = linea.split(":", 1)[1].strip()

            # Separamos las cookies individuales
            cookies = cookie_header_content.split(";")

            for cookie in cookies:
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Comprobamos si es la cookie que buscamos
                    if key == nombre_cookie:
                        try:
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
    
    return 1


def process_web_request(cs, webroot):

    comprobacion = False
    while not comprobacion:

        data = recibir_mensaje(cs)

        # Si el cliente cierra la conexión antes de tiempo (recv vacío), salimos forzosamente
        if not data:
            logger.info("El cliente cerró la conexión (TCP FIN).")
            break

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

            er_method = r"^GET$"
            er_url = r"^\S+$"
            er_version = r"^HTTP/1\.1$"

            if (re.fullmatch(er_method, method) and 
                re.fullmatch(er_url, url) and 
                re.fullmatch(er_version, version)):
                request_valida = True

                tiene_host = False
                headers_block = lineas[1].split('\r\n') if len(lineas) > 1 else []
                for h in headers_block:
                    if h.lower().startswith("host:"):
                        tiene_host = True
                        break
                if tiene_host:
                    request_valida = True
                else:
                    logger.error("Error: falta cabecera Host")

        else:
            print("Error 400 (Bad request): La línea de petición no tiene el formato correcto")

        # Se comprueba si la petición es valida
        if request_valida:
            mensaje_email = b""
            # Leer URL y eliminar parámetros si los hubiera
            if "?" in url:
                ruta_base, params = url.split("?",1)
                url = ruta_base     #Nos quedamos con la ruta limpia para buscar el fichero
                params = params.replace("%40", "@")
                regex_correo = r"email=[a-z]([a-z.]*[a-z])?@um\.es"
                if re.search(regex_correo, params):
                    mensaje_email = b"<h1>Correo Correcto</h1><p>Bienvenido estudiante.</p>"
                elif "email=" in params:
                    # Si mandó el parámetro email pero no cumple el patrón:
                    mensaje_email = b"<h1>Correo Erroneo</h1><p>El correo debe ser valido, en minusculas y pertenecer al dominio @um.es.</p>"
            
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
                # Linea de estado:
                header = "HTTP/1.1 404 Not Found\r\n"
                # Fecha:
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
                    
                    # Extraer y Analizar las cabeceras
                    # Si hay contenido después de la primera línea, lo spliteamos por saltos de línea
                    headers_list = lineas[1].split('\r\n') if len(lineas) > 1 else []
                    
                    logger.info("--- Cabeceras recibidas ---")
                    for h in headers_list:
                        if h: # Si la línea no está vacía, la imprimimos
                            logger.info(h)
                    
                    # Gestión de Cookies
                    # Inicializamos a 1 por defecto para las imagenes
                    cookie_val = 1 
                    
                    if url == "/index.html":
                        cookie_val = process_cookies(headers_list, cs)

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
                        # ÉXITO (200 OK)
                        file_size = os.path.getsize(filepath)
                        filename, file_extension = os.path.splitext(filepath)
                        extension = file_extension.lstrip(".")
                        content_type = filetypes.get(extension, "application/octet-stream")

                        # Construimos cabeceras 200 OK
                        header = "HTTP/1.1 200 OK\r\n"
                        header += "Date: {}\r\n".format(datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'))
                        header += "Server: SSTT\r\n"
                        header += "Content-Length: {}\r\n".format(file_size + len(mensaje_email))
                        header += "Content-Type: {}\r\n".format(content_type)
                        
                        if url == "/index.html":
                            header += "Set-Cookie: cookie_counter_65YY={}; Max-Age=30\r\n".format(cookie_val)

                        header += "Connection: keep-alive\r\n"
                        header += "Keep-Alive: timeout={}, max=100\r\n\r\n".format(TIMEOUT_CONNECTION)

                        # Enviamos cabeceras y elaviso del correo
                        enviar_mensaje(cs, header.encode() + mensaje_email)

                            # Enviar contenido del fichero por bloques
                        with open(filepath, 'rb') as f:
                            while True:
                                chunk = f.read(BUFSIZE)
                                if not chunk:
                                    break
                                cs.send(chunk)

        else:
            if len(partes) == 3 and re.fullmatch(er_version, version) and not re.fullmatch(er_method, method):
                error_msg = "405 Method Not Allowed. Metodo no permitido"
                header = "HTTP/1.1 405 Method Not Allowed\r\n"
                header += "Allow: GET\r\n"
                header += "Content-Length: {}\r\n".format(len(error_msg))
                header += "Connection: close\r\n\r\n"
                print("Error 405 (Method Not Allowed): Método no permitido, solo se acepta GET")
                enviar_mensaje(cs, header.encode() + error_msg.encode())
            else:
                # 400 Bad Request
                error_msg = "<h1>400 Bad Request</h1>"
                header = "HTTP/1.1 400 Bad Request\r\n"
                header += "Content-Length: {}\r\n".format(len(error_msg))
                header += "Connection: close\r\n\r\n"
                enviar_mensaje(cs, header.encode() + error_msg.encode())
            
            comprobacion = True

        # Persistencia
        if not comprobacion:
            recibido, _, _ = select.select([cs], [], [], TIMEOUT_CONNECTION)

            if not recibido:
                # Si recibido está vacío, significa que ha saltado el TIMEOUT
                logger.info("Timeout de persistencia alcanzado. Cerrando.")
                comprobacion = True
            
            # Si recibido tiene datos, el bucle while se repite 
            # y recibir_mensaje leerá la nueva peticion inmediatamente

def main():

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

        # Crear el socket TCP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Permitir reusar la dirección
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Vincular a IP y Puerto
        server_socket.bind((args.host, args.port))

        # Escuchar conexiones
        server_socket.listen(MAX_ACCESOS)

        # Bucle infinito para aceptar clientes
        while True:
            # Aceptar conexión
            client_socket, client_addr = server_socket.accept()
            logger.info("Conexión entrante de: {}".format(client_addr))

            # Fork
            pid = os.fork()

            if pid == 0:
                # PROCESO HIJO
                server_socket.close()

                # Delegamos la responsabilidad a la función
                process_web_request(client_socket, args.webroot)
    
                # Cerramos
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
