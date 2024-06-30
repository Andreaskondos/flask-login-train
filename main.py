from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key-goes-here"


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB with the UserMixin to get all ther attributes and methods of a User
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        if db.session.query(User).filter_by(email=data["email"]).count() > 0:
            flash("Email already exists.")
            return redirect(url_for("register"))
        hashed_password = generate_password_hash(
            password=data["password"], method="pbkdf2:sha256", salt_length=8
        )
        new_user = User(
            name=data["name"], email=data["email"], password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        load_user(new_user)
        return render_template("secrets.html")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        user = User.query.filter_by(email=data["email"]).first()
        if user:
            if check_password_hash(user.password, data["password"]):
                login_user(user)
                return redirect(url_for("secrets"))
            else:
                flash("Password is incorrect, please try again.")
                return redirect(url_for("login"))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/secrets")
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/download")
@login_required
def download():
    return send_from_directory("static", "files/cheat_sheet.pdf")


@login_manager.unauthorized_handler
def unauthorized():
    return "<h1>Unauthorized Action: Login Required</h1>"


if __name__ == "__main__":
    app.run(debug=True)
