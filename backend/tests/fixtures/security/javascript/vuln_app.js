const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/search", (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM users WHERE name = '" + q + "'");
  res.send("ok");
});
