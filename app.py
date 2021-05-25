from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import asc, desc
from flask_wtf import FlaskForm
#from wtforms.validators import DataRequired, Length
#from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import os

dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "Mi clave super secreta"
#Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(30), unique = True)
    password = db.Column(db.String(80))

class Tasks(db.Model):
    # Status = 0 -> DONE
    id = db.Column(db.Integer, primary_key = True)
    task = db.Column(db.String(50), nullable = False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    done_on = db.Column(db.DateTime())
    status = db.Column(db.Integer)
    createdby_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assignby_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    dead_line = db.Column(db.DateTime())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/create_user/<string:user>")
def create_user(user):
    password = generate_password_hash(user, method = "sha256")
    new_user = User(username = user, password = password)
    db.session.add(new_user)
    db.session.commit()
    return(password)

# Ruta para gestionar usuarios
# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(username = request.form["username"]).first()
        stored_password = user.password
        result = check_password_hash(stored_password, request.form["password"])
        if request.form["username"] != user.username or result == False:
            error = 'Invalid Credentials. Please try again.'
        else:
            login_user(user)
            return redirect(url_for('list'))
    return render_template('login.html', error=error)

# Ruta de logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "Logged out!"

## Rutas de para listar, agregar, borrar y modifcar

@app.route("/")
@login_required
def list():
    task = Tasks.query.order_by(desc(Tasks.created_on)).all()
    return render_template("list.html", task=task)

@app.route("/add", methods = ["GET","POST"])
@login_required
def add_task():
    if request.method == "POST":

        try:
            task = request.form["task"]
            dead_line = request.form["dead_line"]
            created_on = datetime.utcnow()
            status = 1
            new_task = Tasks(task = task, created_on = created_on, status = status)
            db.session.add(new_task)
            db.session.commit()
            flash("Task added succesfully", "alert alert-success")
            return redirect(url_for("list"))
        except Exception as e:
            flash("Something went wrong...","alert alert-danger")
            return redirect(url_for("list"))

    return render_template("add.html", date = datetime.utcnow())

@app.route("/delete/<int:id>")
def delete_task(id):
    try:
        task = Tasks.query.filter_by(id=id).one()
        db.session.delete(task)
        db.session.commit()
        flash("Task deleted succesfully", "alert alert-success")
        return redirect(url_for("list"))
    except Exception as e:
        flash("Something went wrong...","alert alert-danger")
        return redirect(url_for("list"))


@app.route("/update",methods=["POST"])
def update():
    try:
        id = request.form["id"]
        task = Tasks.query.filter_by(id=id).one()
        task.task = request.form["task"]
        db.session.commit()
        flash("Task updated succesfully", "alert alert-success")
        return redirect(url_for("list"))
    except Exception as e:
        flash("Something went wrong...","alert alert-danger")
        return redirect(url_for("list"))


@app.route("/update/<int:id>")
def update_task(id):
    task = Tasks.query.filter_by(id=id).one()
    return render_template("/update.html", task=task)

@app.route("/done/<int:id>")
def done(id):
    try:
        task = Tasks.query.filter_by(id=id).one()
        task.done_on = datetime.utcnow()
        task.status = 0
        db.session.commit()
        flash("Task updated to Done succesfully", "alert alert-success")
        return redirect(url_for("list"))
    except Exception as e:
        flash("Something went wrong...","alert alert-danger")
        return redirect(url_for("list"))

@app.route("/undone/<int:id>")
def undone(id):
    try:
        task = Tasks.query.filter_by(id=id).one()
        task.status = 1
        db.session.commit()
        flash("Task updated to Undone succesfully", "alert alert-success")
        return redirect(url_for("list"))
    except Exception as e:
        flash("Something went wrong...","alert alert-danger")
        return redirect(url_for("list"))






if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
