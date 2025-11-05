# app.py
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify
)
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from functools import wraps

# -------------------------
# CONFIGURACIÓN
# -------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "cambiar_en_produccion")

# MySQL config (ajusta según tu entorno / .env)
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER", "root")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD", "")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB", "base_de_datos")
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# Mail config (usa variables de entorno por seguridad)
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "minigestionsecurelogin@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "tu_contraseña_de_app_o_smtp")  # No dejes esto en prod
MAIL_FROM = MAIL_USERNAME
MAIL_HOST = os.getenv("MAIL_HOST", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))

# Carpeta para uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Diccionario temporal para tokens de reset (si reinicias la app se pierde: idealmente almacenarlo en DB)
# En tu DB ya tienes campos reset_token y token_expiry; la app actual sincroniza con DB.
# Pero conservamos un diccionario por seguridad en memoria para flow alternativo.
reset_tokens_mem = {}

# -------------------------
# UTIL: login_required y rol_required
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'idUsuario' not in session:
            flash("Debes iniciar sesión primero", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('rol') != 'Admin':
            flash("Acceso no autorizado", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapped

# -------------------------
# Helpers: manejo de tokens en DB
# -------------------------
def generar_token_db(username_or_email):
    token = secrets.token_urlsafe(32)
    expiry = datetime.now() + timedelta(hours=1)
    cur = mysql.connection.cursor()
    try:
        # Actualizamos por username o por campo email (si existe)
        cur.execute(
            "UPDATE usuarios SET reset_token=%s, token_expiry=%s WHERE username=%s OR email=%s",
            (token, expiry, username_or_email, username_or_email)
        )
        mysql.connection.commit()
    finally:
        cur.close()
    return token

def obtener_usuario_por_token(token):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute(
            "SELECT idUsuario, username, token_expiry FROM usuarios WHERE reset_token=%s",
            (token,)
        )
        u = cur.fetchone()
        return u
    finally:
        cur.close()

# -------------------------
# Helpers: correo
# -------------------------
def enviar_correo_reset(email_destino, token):
    enlace = url_for('reset', token=token, _external=True)
    cuerpo = f"""Hola,

Recibimos una solicitud para restablecer la contraseña de tu cuenta. Si fuiste tú, haz clic en el siguiente enlace para crear una nueva contraseña (válido por 1 hora):

{enlace}

Si no solicitaste este cambio, ignora este correo.

— Equipo.
"""
    mensaje = MIMEText(cuerpo)
    mensaje['Subject'] = 'Recuperar contraseña'
    mensaje['From'] = MAIL_FROM
    mensaje['To'] = email_destino

    server = smtplib.SMTP(MAIL_HOST, MAIL_PORT)
    server.starttls()
    server.login(MAIL_USERNAME, MAIL_PASSWORD)
    server.sendmail(MAIL_FROM, [email_destino], mensaje.as_string())
    server.quit()


@app.context_processor
@app.context_processor
def contar_items_carrito():
    if 'idUsuario' in session:
        idUsuario = session['idUsuario']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT SUM(dc.cantidad) AS total
            FROM detalle_carrito dc
            JOIN carrito c ON dc.idCarrito = c.idCarrito
            WHERE c.idUsuario = %s
        """, (idUsuario,))
        row = cursor.fetchone()
        cursor.close()

        cantidad = row['total'] if row and row['total'] is not None else 0
        return dict(carrito_cantidad=cantidad)
    return dict(carrito_cantidad=0)


@app.route('/')
def index():
   
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password_ingresada = request.form.get('password')

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cur.execute("""
                SELECT u.idUsuario, u.nombre, u.username, u.password, r.nombreRol
                FROM usuarios u
                LEFT JOIN usuario_rol ur ON u.idUsuario = ur.idUsuario
                LEFT JOIN roles r ON ur.idRol = r.idRol
                WHERE u.username = %s
            """, (username,))
            usuario = cur.fetchone()
        finally:
            cur.close()

        if usuario and check_password_hash(usuario['password'], password_ingresada):
            session['idUsuario'] = usuario['idUsuario']
            session['usuario'] = usuario['nombre'] or usuario['username']
            session['rol'] = usuario['nombreRol'] or 'Usuario'
            flash(f"¡Bienvenido {session['usuario']}!", "success")

            # registrar login (si la tabla existe)
            try:
                cur2 = mysql.connection.cursor()
                cur2.execute("INSERT INTO registro_login (idUsuario, fecha_hora) VALUES (%s, NOW())", (usuario['idUsuario'],))
                mysql.connection.commit()
                cur2.close()
            except Exception:
                # no rompemos si registro_login no existe
                pass

            # Redirige según rol
            if session['rol'] == 'Admin':
                return redirect(url_for('dashboard'))
            return redirect(url_for('index'))
        else:
            flash("Usuario o contraseña incorrecta", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Has cerrado sesión", "info")
    return redirect(url_for('login'))


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        apellido = request.form.get('apellido')
        username = request.form.get('username')
        password = request.form.get('password')

        if not all([nombre, username, password]):
            flash("Completa los campos obligatorios", "warning")
            return redirect(url_for('registro'))

        hash_pw = generate_password_hash(password)
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO usuarios (nombre, apellido, username, password) VALUES (%s, %s, %s, %s)",
                (nombre, apellido, username, hash_pw)
            )
            mysql.connection.commit()

            # Asignar rol por defecto (idRol = 2 por ejemplo)
            cur.execute("SELECT idUsuario FROM usuarios WHERE username=%s", (username,))
            nuevo = cur.fetchone()
            if nuevo:
                cur.execute("INSERT INTO usuario_rol (idUsuario, idRol) VALUES (%s, %s)", (nuevo['idUsuario'], 2))
                mysql.connection.commit()

            flash("Usuario registrado exitosamente", "success")
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error al registrar: {e}", "danger")
            return redirect(url_for('registro'))
        finally:
            cur.close()

    return render_template('registro.html')

# -------------------------
# Recuperación de contraseña (mail + token en DB)
# -------------------------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        identifier = request.form.get('email')  # puede ser username o email
        if not identifier:
            flash("Ingresa tu usuario o correo", "warning")
            return redirect(url_for('forgot'))

        # Verificamos si existe usuario por username o email
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cur.execute("SELECT idUsuario, email, username FROM usuarios WHERE username=%s OR email=%s", (identifier, identifier))
            usuario = cur.fetchone()
        finally:
            cur.close()

        if not usuario:
            flash("No existe un usuario con ese correo/usuario", "danger")
            return redirect(url_for('forgot'))

        # Generamos token y actualizamos DB
        token = generar_token_db(identifier)
        # Enviamos correo: si tienes email en DB úsalo, si no, usamos identifier
        destino = usuario.get('email') or identifier
        try:
            enviar_correo_reset(destino, token)
            flash("Se ha enviado un correo para restablecer tu contraseña", "info")
        except Exception as e:
            # Si falla el envío por SMTP, informamos (en prod registrar el error)
            flash(f"Error enviando correo: {e}", "danger")

        return redirect(url_for('login'))

    return render_template('forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    usuario = obtener_usuario_por_token(token)
    if not usuario:
        flash("Token inválido o ya usado", "danger")
        return redirect(url_for('forgot'))

    token_expiry = usuario.get('token_expiry')
    if token_expiry and datetime.now() > token_expiry:
        flash("El enlace ha expirado", "danger")
        return redirect(url_for('forgot'))

    if request.method == 'POST':
        nueva = request.form.get('password')
        if not nueva or len(nueva) < 6:
            flash("La contraseña debe tener al menos 6 caracteres", "warning")
            return redirect(url_for('reset', token=token))

        hash_nueva = generate_password_hash(nueva)
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "UPDATE usuarios SET password=%s, reset_token=NULL, token_expiry=NULL WHERE idUsuario=%s",
                (hash_nueva, usuario['idUsuario'])
            )
            mysql.connection.commit()
            flash("Contraseña actualizada con éxito", "success")
            return redirect(url_for('login'))
        finally:
            cur.close()

    return render_template('reset.html', token=token)

# -------------------------
# DASHBOARD (admin)
# -------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # Solo admin puede ver usuarios completos; si no admin, mostramos resumen
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT u.idUsuario, u.nombre, u.apellido, u.username, r.nombreRol, r.idRol
            FROM usuarios u
            LEFT JOIN usuario_rol ur ON u.idUsuario = ur.idUsuario
            LEFT JOIN roles r ON ur.idRol = r.idRol
        """)
        usuarios = cur.fetchall()
    finally:
        cur.close()

    return render_template('dashboard.html', usuarios=usuarios)

# -------------------------
# CRUD Usuarios (editar / eliminar) - solo admin
# -------------------------
@app.route('/actualizar/<int:id>', methods=['POST'])
@admin_required
def actualizar(id):
    nombre = request.form.get('nombre')
    apellido = request.form.get('apellido')
    correo = request.form.get('correo')
    rol = request.form.get('rol')

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "UPDATE usuarios SET nombre=%s, apellido=%s, username=%s WHERE idUsuario=%s",
            (nombre, apellido, correo, id)
        )
        # comprobar existencia en usuario_rol
        cur.execute("SELECT * FROM usuario_rol WHERE idUsuario=%s", (id,))
        existe = cur.fetchone()
        if existe:
            cur.execute("UPDATE usuario_rol SET idRol=%s WHERE idUsuario=%s", (rol, id))
        else:
            cur.execute("INSERT INTO usuario_rol(idUsuario, idRol) VALUES (%s, %s)", (id, rol))
        mysql.connection.commit()
        flash("Usuario actualizado", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error al actualizar: {e}", "danger")
    finally:
        cur.close()
    return redirect(url_for('dashboard'))

@app.route('/eliminar/<int:id>')
@admin_required
def eliminar(id):
    cur = mysql.connection.cursor()
    try:
        cur.execute("DELETE FROM usuarios WHERE idUsuario=%s", (id,))
        mysql.connection.commit()
        flash("Usuario eliminado exitosamente", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error al eliminar: {e}", "danger")
    finally:
        cur.close()
    return redirect(url_for('dashboard'))

# -------------------------
# INVENTARIO / PRODUCTOS
# -------------------------
@app.route('/inventario')
@login_required
def inventario():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("SELECT * FROM productos")
        productos = cur.fetchall()
    finally:
        cur.close()
    return render_template('inventario.html', productos=productos)

@app.route('/agregar_producto', methods=['GET', 'POST'])
@admin_required
def agregar_producto():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion')
        precio = request.form.get('precio') or 0
        cantidad = request.form.get('cantidad') or 0
        imagen = request.files.get('imagen')

        filename = None
        if imagen and imagen.filename != '':
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(UPLOAD_FOLDER, filename))

        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO productos (nombre_producto, descripcion, precio, cantidad, imagen)
                VALUES (%s, %s, %s, %s, %s)
            """, (nombre, descripcion, precio, cantidad, filename))
            mysql.connection.commit()
            flash("Producto agregado correctamente", "success")
            return redirect(url_for('inventario'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error al agregar producto: {e}", "danger")
        finally:
            cur.close()

    return render_template('agregar_producto.html')

@app.route('/actualizar_producto/<int:id>', methods=['GET', 'POST'])
@admin_required
def actualizar_producto(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if request.method == 'POST':
            nombre = request.form.get('nombre')
            descripcion = request.form.get('descripcion')
            cantidad = request.form.get('cantidad')
            precio = request.form.get('precio')
            imagen = request.files.get('imagen')

            if imagen and imagen.filename != '':
                filename = secure_filename(imagen.filename)
                imagen.save(os.path.join(UPLOAD_FOLDER, filename))
                cur.execute("""
                    UPDATE productos
                    SET nombre_producto=%s, descripcion=%s, cantidad=%s, precio=%s, imagen=%s
                    WHERE idProducto=%s
                """, (nombre, descripcion, cantidad, precio, filename, id))
            else:
                cur.execute("""
                    UPDATE productos
                    SET nombre_producto=%s, descripcion=%s, cantidad=%s, precio=%s
                    WHERE idProducto=%s
                """, (nombre, descripcion, cantidad, precio, id))
            mysql.connection.commit()
            flash("Producto actualizado con éxito", "success")
            return redirect(url_for('inventario'))
        else:
            cur.execute("SELECT * FROM productos WHERE idProducto=%s", (id,))
            producto = cur.fetchone()
            return render_template('actualizar_producto.html', producto=producto)
    finally:
        cur.close()

@app.route('/catalogo')
def catalogo():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM productos")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('catalogo.html', productos=productos)

@app.route('/agregarCarrito/<int:id>', methods=['POST'])
def agregarCarrito(id):
    if 'usuario' not in session:
        flash("Debes iniciar sesión para agregar productos al carrito")
        return redirect(url_for('login'))
    
    cantidad = int(request.form['cantidad'])
    idUsuario = session.get('idUsuario')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT cantidad FROM productos WHERE idProducto = %s", (id,))
    stock = cursor.fetchone()[0]
    cursor.execute("SELECT idCarrito FROM carrito WHERE idUsuario = %s", (idUsuario,))
    carrito = cursor.fetchone()

    if not carrito:
        cursor.execute("INSERT INTO carrito (idUsuario) VALUES (%s)", (idUsuario,))
        mysql.connection.commit()
        cursor.execute("SELECT LAST_INSERT-ID()")
        carrito = cursor.fetchone()

    idCarrito = carrito[0]
    cursor.execute("""SELECT cantidad FROM detalle_carrito 
                    WHERE idCarrito = %s AND idProducto = %s""",(idCarrito,id))
    existente = cursor.fetchone()
    cantidad_total = cantidad

    if existente:
        cantidad_total += existente[0]

    if cantidad_total > stock:
        flash("no puedes agregar mas unidades de las disponibles en el inventario", "warning")
        cursor.close()
        return redirect(url_for("catalogo"))

    if existente:
        nueva_cantidad = existente[0] + cantidad
        cursor.execute("""
                        UPDATE detalle_carrito 
                        SET cantidad = %s 
                        WHERE idCarrito = %s AND idProducto = %s
                        """, (nueva_cantidad, idCarrito, id))
    else:
        cursor.execute("""
            INSERT INTO detalle_carrito (idCarrito, idProducto, cantidad)
            VALUES (%s, %s, %s)
            """, (idCarrito,id,cantidad))
    mysql.connection.commit()
    cursor.close()

    flash("Producto agregado al carrito")
    return redirect(url_for('catalogo'))

@app.route('/carrito')
def carrito():
    if 'usuario' not in session:
        flash("Debes iniciar sesión para agregar productos al carrito")
        return redirect(url_for('login'))
    
    idUsuario = session.get('idUsuario')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
            SELECT dc.idDetalleCarrito, p.nombre_producto, p.precio, p.imagen, dc.cantidad, p.cantidad AS stock
            FROM detalle_carrito dc
            JOIN carrito c ON dc.idCarrito = c.idCarrito
            JOIN productos p ON dc.idProducto = p.idProducto
            WHERE c.idUsuario = %s
    """, (idUsuario,))
    productos_carrito = cursor.fetchone()
    cursor.close()

    total = sum(item['precio'] * item['cantidad'] for item in productos_carrito)
    return render_template('carrito.html', productos=productos_carrito, total = total)

@app.route('/actualizar_carrito/<int:id>',  methods=["POST"])
def actualizar_carrito(id):
    accion = request.form.get("accion")
    cantidad_actual = int(request.form.get("cantidad_actual",1))
    idUsuario = session.get ("idUsuario")

    if accion == "sumar":
        nueva_cantidad = cantidad_actual +1
    elif accion == "restar":
        nueva_cantidad = max(1, cantidad_actual -1)
    else:
        nueva_cantidad = int(request.form.get("cantidad_manual", cantidad_actual))

        cursor = mysql.connection.cursor()

        cursor.execute("SELECT cantidad FROM productos WHERE idProducto = %s", (id,))
        stock = cursor.fetchone()[0]

    if nueva_cantidad > stock:
            flash("no puedes exceder el inventario disponible", "warning")
            cursor.close()
            return redirect(url_for("carrito"))
    if nueva_cantidad > 0:
        cursor.execute("""
                UPDATE detalle_carrito dc
                JOIN carrito c ON dc.idCarrito= c.idCarrito
                SET dc.cantidad = %s
                WHERE c.idUsuario = %s AND dc.idProducto = %s
                       """, (nueva_cantidad,idUsuario,id))
    else:
        cursor.execute("""
                DELETE dc FROM detalle_carrito dc
                JOIN carrito c ON dc.idCarrito = c.idCarrito
                WHERE c.idUsuario = %s AND dc.idProducto = %s
                       """,(idUsuario,id))
    mysql.connection.commit()
    cursor.close

    flash("carrito actualizado", "info")
    return redirect(url_for("carrito"))

@app.route("/eliminar_del_carrito/<int:id>")
def eliminar_del_carrito(id):
    idUsuario =session.get("idUsuario")
    cursor = mysql.connection.cursor()
    cursor.execute("""
                DELETE dc FROM detalle_carrito dc
                JOIN carrito c ON dc.idCarrito = c.idCarrito
                WHERE c.idUsuario = %s AND dc.idProducto = %s
                       """,(idUsuario,id))
    mysql.connection.commit()
    cursor.close
    flash("producto eliminado", "danger")
    return redirect(url_for("carrito"))

@app.route("/vaciar_carrito")
def vaciar_carrito():
    idUsuario = session.get("idUsuario")
    cursor = mysql.connection.cursor()
    cursor.execute("""
                DELETE dc FROM detalle_carrito dc
                JOIN carrito c ON dc.idCarrito = c.idCarrito
                WHERE c.idUsuario = %s 
                       """,(idUsuario,))
    mysql.connection.commit()
    cursor.close()
    flash("carrito vaciado", "warning")
    return redirect(url_for("carrito"))

@app.route('/pago', methods=['GET', 'POST'])
def pago():
    if 'usuario' not in session:
        flash("Debes iniciar sesión para agregar productos al carrito")
        return redirect(url_for('login'))
    
    idUsuario = session.get('idUsuario')


    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
            SELECT p.idProducto, p.nombre_producto, p.precio, dc.cantidad, p.cantidad AS stock
            FROM detalle_carrito dc
            JOIN carrito c ON dc.idCarrito = c.idCarrito
            JOIN productos p ON dc.idProducto = p.idProducto
            WHERE c.idUsuario = %s
                   """, (idUsuario,))
    productos = cursor.fetchall()

    total = sum(p['precio'] * p ['cantidad'] for p in productos)

    if request.method == 'POST':
        errores = []
        for p in productos:
            if p['cantidad']> p['stock']:
                errores.append(f"{p['nombre_producto']} excede el stock disponible.")
        if errores:
            flash("Error en el pago: " + ", ".join(errores), "danger")
            return redirect(url_for('carrito'))
        
        flash("pago realizado exitosamente. Gracias por tu compra", "success")

        cursor.execute("""
                DELETE dc FROM detalle_carrito dc
                JOIN carrito c ON dc.idCarrito = c.idCarrito
                WHERE c.idUsuario = %s
                       """, (idUsuario,))
        mysql.connection.commit()
        cursor.close()
        return redirect (url_for('catalogo'))
    cursor.close()
    return render_template('pago.html',productos=productos, total=total)



if __name__ == '__main__':
    app.run(port=5000, debug=True)
