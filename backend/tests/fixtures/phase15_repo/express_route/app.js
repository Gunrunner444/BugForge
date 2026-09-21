app.get("/search", (req, res) => {
  eval(req.query.q);
});
