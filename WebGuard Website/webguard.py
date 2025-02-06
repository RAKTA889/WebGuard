from flask import Flask,render_template

app = Flask(__name__)

@app.route("/")
@app.route("/home")
def home_page():
    return render_template('home.html')

@app.route("/attack_info")
def attack_info_page():
    return render_template('attack_info.html')

@app.route("/scanner")
def scanner_page():
    return render_template('scanner.html')