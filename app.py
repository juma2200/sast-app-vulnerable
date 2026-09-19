"""
Aplicación Flask DELIBERADAMENTE VULNERABLE.

Uso exclusivo educativo: ejercicio "Implementar SAST On-Premise".
NO desplegar en internet ni en producción. Ejecutar solo en una máquina local.

Cada problema intencional está marcado con un comentario:
  [VULN-XX]    -> problema de seguridad (con su CWE y la regla de Bandit)
  [CALIDAD-XX] -> problema de calidad / mantenibilidad
"""
import os
import sys   # [CALIDAD-01] Import no utilizado (code smell).
import json  # [CALIDAD-01] Import no utilizado (code smell).
import base64
import hashlib
import pickle
import random
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# [VULN-01] Credenciales y claves escritas directamente en el código (CWE-798).
# Deberían venir de variables de entorno o de un gestor de secretos.
# Bandit: B105 (hardcoded_password_string).
app.config["SECRET_KEY"] = "supersecreto123"
DB_PASSWORD = "admin1234"
API_KEY = "sk-test-1234567890abcdef"

DB_PATH = "usuarios.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/init")
def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS usuarios "
        "(id INTEGER PRIMARY KEY, usuario TEXT, clave TEXT)"
    )
    conn.commit()
    # [CALIDAD-02] La conexión nunca se cierra (fuga de recursos, CWE-772).
    return "Base de datos lista"


@app.route("/registro", methods=["POST"])
def registro():
    usuario = request.form["usuario"]
    clave = request.form["clave"]

    # [VULN-02] MD5 sin sal para guardar contraseñas (CWE-327 / CWE-328).
    # Debería usarse bcrypt, scrypt o argon2. Bandit: B324 (hashlib).
    clave_hash = hashlib.md5(clave.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO usuarios (usuario, clave) VALUES (?, ?)",
        (usuario, clave_hash),
    )
    conn.commit()
    # [CALIDAD-02] Conexión sin cerrar.
    return "Usuario registrado"


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form["usuario"]
    clave = request.form["clave"]
    clave_hash = hashlib.md5(clave.encode()).hexdigest()  # (ver VULN-02)

    # [VULN-13] Se imprimen credenciales en el log (CWE-532).
    print("Intento de login:", usuario, clave)

    conn = get_db()
    # [VULN-03] Inyección SQL: la consulta se arma concatenando texto del
    # usuario (CWE-89). Debería usar consultas parametrizadas (?).
    # Ejemplo de ataque en el campo usuario:  ' OR '1'='1' --
    # Bandit: B608 (hardcoded_sql_expressions).
    query = (
        "SELECT * FROM usuarios WHERE usuario = '" + usuario
        + "' AND clave = '" + clave_hash + "'"
    )
    fila = conn.execute(query).fetchone()
    # [CALIDAD-02] Conexión sin cerrar.
    if fila:
        return "Bienvenido"
    return "Credenciales inválidas", 401


@app.route("/buscar")
def buscar():
    termino = request.args.get("q", "")
    # [VULN-04] XSS reflejado (CWE-79) e inyección de plantillas SSTI
    # (CWE-1336): el texto del usuario se concatena dentro de la plantilla
    # sin escapar. Debería usarse render_template con {{ termino }}.
    return render_template_string("<h1>Resultados para: " + termino + "</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [VULN-05] Inyección de comandos del sistema operativo (CWE-78):
    # shell=True con entrada del usuario. Ejemplo: host=127.0.0.1; ls
    # Bandit: B602 (subprocess_popen_with_shell_equals_true).
    salida = subprocess.check_output("ping -c 1 " + host, shell=True)
    return salida


@app.route("/calcular")
def calcular():
    expresion = request.args.get("expr", "1+1")
    # [VULN-06] Uso de eval() con datos del usuario (CWE-95): permite
    # ejecutar código Python arbitrario. Bandit: B307 (eval).
    return str(eval(expresion))


@app.route("/archivo")
def leer_archivo():
    nombre = request.args.get("nombre", "readme.txt")
    # [VULN-07] Path traversal (CWE-22): no se valida el nombre, se puede
    # pedir ../../etc/passwd. Debería usarse send_from_directory o validar
    # la ruta final. (Bandit no lo detecta; herramientas como SonarQube sí.)
    with open(os.path.join("archivos", nombre)) as f:
        return f.read()


@app.route("/cargar", methods=["POST"])
def cargar():
    datos = base64.b64decode(request.form["datos"])
    # [VULN-08] Deserialización insegura con pickle (CWE-502): un objeto
    # malicioso puede ejecutar código al cargarse. Bandit: B301 (pickle).
    objeto = pickle.loads(datos)
    return str(objeto)


@app.route("/config", methods=["POST"])
def config():
    # [VULN-09] yaml.load con un Loader inseguro (CWE-502). Debería usarse
    # yaml.safe_load. Bandit: B506 (yaml_load).
    datos = yaml.load(request.form["yaml"], Loader=yaml.Loader)
    return str(datos)


@app.route("/token")
def token():
    # [VULN-10] Generador aleatorio NO criptográfico para un token
    # (CWE-330). Debería usarse el módulo secrets. Bandit: B311 (random).
    return "".join(random.choice("abcdef0123456789") for _ in range(16))


@app.route("/descargar")
def descargar():
    url = request.args.get("url")
    # [VULN-11] Se desactiva la verificación del certificado TLS (CWE-295)
    # y no hay timeout. Además, la URL la controla el usuario (SSRF,
    # CWE-918). Bandit: B501 (request_with_no_cert_validation) y B113.
    r = requests.get(url, verify=False)
    return r.text


@app.route("/temporal")
def temporal():
    # [VULN-12] tempfile.mktemp es inseguro por condición de carrera
    # (CWE-377). Debería usarse tempfile.mkstemp o NamedTemporaryFile.
    # Bandit: B306 (mktemp_q).
    ruta = tempfile.mktemp()
    with open(ruta, "w") as f:
        f.write("datos")
    return ruta


def limpiar_cache():
    try:
        os.remove("cache.tmp")
    except:  # noqa: E722
        # [VULN-15] `except` vacío con `pass`: se ocultan todos los errores
        # (CWE-703). Bandit: B110 (try_except_pass). También es un
        # problema de calidad (E722, except desnudo).
        pass


def calcular_descuento(tipo, monto):
    # [CALIDAD-03] Complejidad ciclomática alta: demasiados if anidados y
    # "números mágicos" (0.9, 0.95, 0.8, 100...) sin constantes con nombre.
    resultado_temporal = 0  # [CALIDAD-04] Variable asignada y nunca usada.
    if tipo == "a":
        if monto > 100:
            return monto * 0.9
        else:
            return monto * 0.95
    elif tipo == "b":
        if monto > 100:
            return monto * 0.8
        else:
            if monto > 50:
                return monto * 0.85
            else:
                return monto * 0.9
    elif tipo == "c":
        if monto > 100:
            return monto * 0.7
        else:
            return monto * 0.75
    return monto


# [CALIDAD-05] Código duplicado: estas dos funciones hacen exactamente lo
# mismo. Debería existir una sola función reutilizable.
def formatear_usuario(nombre, apellido):
    return nombre.strip().title() + " " + apellido.strip().title()


def formatear_cliente(nombre, apellido):
    return nombre.strip().title() + " " + apellido.strip().title()


if __name__ == "__main__":
    # [VULN-14] debug=True expone el depurador de Werkzeug, que permite
    # ejecutar código remoto (CWE-489), y host="0.0.0.0" abre la app a toda
    # la red (CWE-668). Bandit: B201 (flask_debug_true) y B104
    # (hardcoded_bind_all_interfaces).
    app.run(host="0.0.0.0", port=5000, debug=True)
