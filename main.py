import sqlite3
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key =  os.getenv('SECRET_KEY', 'fallback_secret_key')  # Use a fallback for development


# Path to the SQLite database file
DATABASE = os.getenv('DATABASE_PATH', 'instance/todolist.db')

# Function to connect to the SQLite database
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enables column access by name
    return conn

# Initialize the database with required tables
def init_db():
    conn = get_db()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                task TEXT NOT NULL,
                completed BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
    conn.close()

# Initialize the database at the start
init_db()

@app.before_request
def ensure_user_session():
    if 'todos' not in session:
        session['todos'] = []

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ? OR username = ?', (email, username)).fetchone()

        if user:
            conn.close()
            if user['email'] == email:
                return "Email is already taken. Please choose a different one."
            if user['username'] == username:
                return "Username is already taken. Please choose a different one."

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                     (email, username, hashed_password))
        conn.commit()

        user_id = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()['id']
        conn.close()
        session['user'] = {'id': user_id, 'email': email, 'username': username}
        return redirect(url_for('home'))

    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = {'id': user['id'], 'email': user['email'], 'username': user['username']}
            return redirect(url_for('home'))
        else:
            return "Invalid username or password. Please try again.", 401

    return render_template('login.html')

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# Home route for displaying and managing todos
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        todos = session.get('todos', [])
        if request.method == 'POST':
            task = request.form.get('task')
            if task:
                if 'todos' not in session:
                    session['todos'] = []
                session['todos'].append({'id': len(session['todos']) + 1, 'task': task, 'completed': False})
                session.modified = True
        return render_template('index.html', todos=todos)

    user = session['user']
    conn = get_db()
    if request.method == 'POST':
        task = request.form.get('task')
        if task:
            conn.execute('INSERT INTO todos (user_id, task, completed) VALUES (?, ?, ?)',
                         (user['id'], task, False))
            conn.commit()
        elif request.form.get('delete_id'):
            delete_id = int(request.form.get('delete_id'))
            conn.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (delete_id, user['id']))
            conn.commit()
        elif request.form.get('complete_id'):
            complete_id = int(request.form.get('complete_id'))
            conn.execute(
                'UPDATE todos SET completed = NOT completed WHERE id = ? AND user_id = ?',
                (complete_id, user['id'])
            )
            conn.commit()

    todos = conn.execute('SELECT * FROM todos WHERE user_id = ?', (user['id'],)).fetchall()
    conn.close()

    return render_template('index.html', todos=todos)

if __name__ == '__main__':
    app.run(debug=True)
