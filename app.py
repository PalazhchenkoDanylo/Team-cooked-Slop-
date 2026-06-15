import sqlite3
from flask import Flask, render_template, jsonify

app = Flask(__name__)
DB_FILE = "gateway.db"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def get_data():
    """Polls the shared SQLite database to return current and historical state data."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch the currently active user session
            cursor.execute("SELECT name, login_time FROM sessions WHERE logout_time IS NULL ORDER BY id DESC LIMIT 1")
            active_row = cursor.fetchone()
            active = [dict(active_row)] if active_row else []
            
            # Fetch completed historic sessions
            cursor.execute("SELECT name, login_time, logout_time, duration FROM sessions WHERE logout_time IS NOT NULL ORDER BY id DESC LIMIT 50")
            history = [dict(row) for row in cursor.fetchall()]
            
        return jsonify({"active": active, "history": history})
    except Exception as e:
        return jsonify({"active": [], "history": [], "error": str(e)})

if __name__ == "__main__":
    # Host on 0.0.0.0 to allow access from other devices on the network
    app.run(host="0.0.0.0", port=5000, debug=False)
