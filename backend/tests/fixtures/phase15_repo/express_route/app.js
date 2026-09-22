const express = require("express");
const app = express();
app.get("/search", (req, res) => {
  eval(req.query.q);
});
