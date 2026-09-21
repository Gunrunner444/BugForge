@app.route("/item/<int:id>", methods=["GET"])
def item(id):
    eval(id)
