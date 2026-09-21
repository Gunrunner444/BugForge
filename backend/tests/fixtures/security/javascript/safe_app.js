const express = require("express");
const { execFile } = require("child_process");
const app = express();

app.get("/run", (req, res) => {
  execFile("echo", ["hello"], (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/search", (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM users WHERE name = $1", [q]);
  res.send("ok");
});
