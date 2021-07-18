from flask import Flask, render_template, request

from utils import (
    get_totp,
    get_totp_url,
    generate_secret,
)

app = Flask(__name__)

"""
User Details as:
{
    "user": "secret",
    ...
}
"""
user_db = {
    'mvm': 'ECFXNLPMJJJIAUDVTPDYOONUMGAGZAJEZKUPHTBSSQZDMOJBHUFIGSATZPLNBBHXGOHUAZPGFQBCZVRPVMCKYONKSHYNMWZRPAZEIZDIZDACTPCRSRVREUIUJFTJLZYK'
}


@app.route('/')
def home():
    print(user_db)
    return render_template("home.html")


@app.route('/register')
def register_user():
    """
    Generate random string(secret),
    store the user : secret in file
    """
    user = request.args.get("user")
    secret = generate_secret(128)
    user_db[user] = secret
    totp_url = get_totp_url(user, secret)
    return render_template("register.html", totp_url=totp_url)


@app.route('/verify', methods=["GET", "POST"])
def verify_user():
    """
    Get secret from user_db matched to user,
    Verify token is valid or not
    """
    valid = None
    verified = False
    if request.method == 'POST':
        verified = True
        user = request.form['user']
        token = request.form['token']
        secret = user_db.get(user, None)
        if secret:
            totp = get_totp(secret)
            valid = int(token) == int(totp)
    return render_template("verify.html", valid=valid, verified=verified)


if __name__ == '__main__':
    app.run()
