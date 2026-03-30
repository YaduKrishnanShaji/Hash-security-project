
from flask import Flask,render_template,request,redirect,session,url_for
import sqlite3,time
from modules.password_strength import analyze_strength
from modules.entropy import calculate_entropy
from modules.security_score import security_score
from modules.ranking import rank_algorithms
from collections import defaultdict
import time , math
import bcrypt
import hashlib, random
from argon2 import PasswordHasher

app = Flask(__name__)
app.secret_key="secret"
DB="database.db"

def db():
    return sqlite3.connect(DB)

def init_db():
    conn=db()
    cur=conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        algorithm TEXT,
        execution_time REAL)''')
    conn.commit()
    conn.close()

@app.route('/')
def dashboard():
    data = {
        "score": random.randint(30, 95),

        "cpu": [random.randint(40, 90) for _ in range(6)],
        "memory": [random.randint(30, 80) for _ in range(6)],
        "response": [random.randint(100, 500) for _ in range(6)],
        "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],

        "attacks": {
            "DDoS": 35,
            "Phishing": 25,
            "Malware": 20,
            "SQL Injection": 20
        },

        "comparison": {
            "System A": 75,
            "System B": 60,
            "System C": 85
        },

        "recommendations": [
            "Use strong password with symbols",
            "Enable 2FA authentication",
            "Update system regularly",
            "Monitor unusual login activity"
        ]
    }

    return render_template("dashboard.html", data=data)




# @app.route('/clear')
# def clear():
#     session.pop('results', None)
#     return redirect('/')
@app.route('/clear')
def clear():
    session.pop('results', None)   # clear session
    return redirect('/benchmark_page')
@app.route('/benchmark_page')
def benchmark_page():
    results = session.get('results', [])

    avg = {}
    count = defaultdict(int)
    total = defaultdict(float)

    for r in results:
        algo = r['algorithm']
        total[algo] += r['time']
        count[algo] += 1

    for algo in total:
        avg[algo] = round(total[algo] / count[algo], 2)

    # Ranking (fastest = best)
    ranking = sorted(avg.items(), key=lambda x: x[1])

    return render_template(
        "benchmark_page.html",
        results=results,
        avg=avg,
        ranking=ranking
    )
    #return render_template("benchmark_page.html")


@app.route('/benchmark', methods=['POST'])
def benchmark():

    algorithm = request.form['algorithm']
    #password = "Test@123"
    password = "Testuser"

    import time
    start = time.time()

    if algorithm == "bcrypt":
        import bcrypt
        bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    elif algorithm == "argon2":
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        ph.hash(password)

    elif algorithm == "scrypt":
        import hashlib
        hashlib.scrypt(password.encode(), salt=b'salt', n=16384, r=8, p=1)

    end = time.time()

    execution_time = round((end - start) * 1000, 3)

    # 🔥 Store multiple results
    if 'results' not in session:
        session['results'] = []

    results = session['results']

    results.append({
        "algorithm": algorithm,
        "time": execution_time
    })

    session['results'] = results

    return redirect('/benchmark_page') 
    conn=db()
    cur=conn.cursor()
    cur.execute("SELECT algorithm,execution_time FROM results")
    rows=cur.fetchall()

    cur.execute("SELECT algorithm,AVG(execution_time) FROM results GROUP BY algorithm")
    analysis=cur.fetchall()
    conn.close()

    alg=[a[0] for a in analysis]
    avg=[a[1] for a in analysis]

    scores={
        "argon2":security_score("argon2"),
        "bcrypt":security_score("bcrypt"),
        "scrypt":security_score("scrypt")
    }

    ranking=rank_algorithms(scores)

    return render_template("dashboard.html",
        username=session["user"],
        rows=rows,
        alg=alg,
        avg=avg,
        scores=scores,
        ranking=ranking)

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        u=request.form["username"]
        p=request.form["password"]
        conn=db()
        cur=conn.cursor()
        cur.execute("INSERT INTO users(username,password) VALUES(?,?)",(u,p))
        conn.commit()
        conn.close()
        return redirect("/login")
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form["username"]
        p=request.form["password"]
        conn=db()
        cur=conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?",(u,p))
        user=cur.fetchone()
        conn.close()
        if user:
            session["user"]=u
            return redirect("/")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user",None)
    return redirect("/login")

@app.route("/strength",methods=["GET","POST"])
def strength():
    result=None
    if request.method=="POST":
        pw=request.form["password"]
        result=analyze_strength(pw)
    return render_template("strength.html",result=result)
def calculate_entropy(password):

    charset = 0

    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32

    entropy = len(password) * math.log2(charset)

    return round(entropy,2)


@app.route('/entropy', methods=['GET', 'POST'])
def entropy():

    entropy_value = None
    password = ""

    if request.method == "POST":
        password = request.form.get("password", "")
        entropy_value = calculate_entropy(password)

    return render_template(
        "entropy.html",
        password=password,
        entropy=entropy_value
    )
@app.route("/scores")
def scores():
    scores={
        "argon2":security_score("argon2"),
        "bcrypt":security_score("bcrypt"),
        "scrypt":security_score("scrypt")
    }
    return render_template("scores.html",scores=scores)

@app.route("/results")
def results():
    conn=db()
    cur=conn.cursor()
    cur.execute("SELECT algorithm,execution_time FROM results")
    rows=cur.fetchall()
    conn.close()
    return render_template("results.html",rows=rows)
@app.route('/ranking')
def ranking_page():

    results = session.get('results', [])

    total = defaultdict(float)
    count = defaultdict(int)

    for r in results:
        total[r['algorithm']] += r['time']
        count[r['algorithm']] += 1

    avg = {k: round(total[k]/count[k],2) for k in total}
    ranking = sorted(avg.items(), key=lambda x: x[1])

    return render_template("ranking.html", ranking=ranking)


@app.route('/charts')
def charts_page():

    results = session.get('results', [])
    return render_template("chart.html", results=results)

if __name__=="__main__":
    init_db()
    app.run(debug=True)
