@app.get("/item/{id}")
def item(id: str):
    eval(id)
