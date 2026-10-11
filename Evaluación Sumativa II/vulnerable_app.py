from flask import Flask, request, render_template_string, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import sqlite3
import os
import hashlib

# Fix para evitar MismatchingStateError en HTTP local
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()

app = Flask(__name__)
app.secret_key = 'clave_secreta_eva2'

csrf = CSRFProtect()
csrf.init_app(app)

# CONFIGURACIÓN AUTH0 (Corregido con server_metadata_url)
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'},
)


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    return 'Welcome to the Task Manager Application! <br><a href="/login">Iniciar Sesión con Auth0</a>'


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=url_for('callback', _external=True))


@app.route('/callback')
def callback():
    token = auth0.authorize_access_token()
    
    # Obtener la información del usuario directamente del token
    user_info = token.get('userinfo')
    if not user_info:
        resp = auth0.get(f'https://{AUTH0_DOMAIN}/userinfo')
        user_info = resp.json()

    session['profile'] = user_info
    session['user_id'] = user_info.get('name', user_info.get('email'))

    # Cambia esto por tu correo real con el que inicias sesión en Auth0
    correo_admin = "correo@gmail.com"

    if user_info.get('email') == correo_admin:
        session['role'] = 'admin'
    else:
        session['role'] = 'user'

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    tasks = conn.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    # con CSRF token aplicado al formulario para protegerlo de ataques de falsificación de solicitudes entre sitios
    return render_template_string('''
        <h1>Welcome, user {{ user_id }}!</h1>
        <p><a href="/admin">Panel Admin</a> | <a href="/logout">Logout</a></p>
        <form action="/add_task" method="post">
            <input type="hidden" name="csrf_token" value="{{ token }}"/>
            <input type="text" name="task" placeholder="New task"><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            <li>{{ task['task'] }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
        {% endfor %}
        </ul>
    ''', user_id=user_id, tasks=tasks, token=generate_csrf())

    # SIN SAFE FILTER applied el seguro
    """return render_template_string('''
        <h1>Welcome, user {{ user_id }}!</h1>
        <form action="/add_task" method="post">
            <input type="text" name="task" placeholder="New task"><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            <li>{{ task['task'] }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
        {% endfor %}
        </ul>
    ''', user_id=user_id, tasks=tasks) """

    # Con safe filter applied to avoid XSS attacks
    """
    return render_template_string('''
            <h1>Welcome, user {{ user_id }}!</h1>
            <form action="/add_task" method="post">
                <input type="text" name="task" placeholder="New task"><br>
                <input type="submit" value="Add Task">
            </form>
            <h2>Your Tasks</h2>
            <ul>
            {% for task in tasks %}
                <li>{{ task['task'] | safe }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
            {% endfor %}
            </ul>
        ''', user_id=user_id, tasks=tasks)
    """


@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = request.form['task']
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO tasks (user_id, task) VALUES (?, ?)", (user_id, task))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        return 'Acceso denegado: Requiere rol de administrador', 403

    return 'Welcome to the admin panel!'


@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        f"https://{AUTH0_DOMAIN}/v2/logout?client_id={os.getenv('AUTH0_CLIENT_ID')}&returnTo={url_for('index', _external=True)}"
    )

if __name__ == '__main__':
    app.run(debug=True)