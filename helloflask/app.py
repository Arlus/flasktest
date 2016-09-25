from flask import Flask

app = Flask(__name__)

app.config["DEBUG"] = True


@app.route("/")
@app.route("/hello")
def hello_world():
    return "Hello World!"


@app.route("/test/<queryset>")
def search(queryset):
    return queryset


@app.route("/integer/<int:value>")
def int_type(value):
    print value + 1
    return "correct"


@app.route("/float/<float:value>")
def float_type(value):
    print value + 1
    return "correct"


# Dynamic route that accepts slashes
@app.route("/path/<path:value>")
def path_type(value):
    print value
    return "correct"


@app.route("/name/<name>")
def index(name):
    if name.lower() == "michael":
        return "Hello, {}".format(name), 200
    else:
        return "Not found", 404


if __name__ == "__main__":
    app.run()
