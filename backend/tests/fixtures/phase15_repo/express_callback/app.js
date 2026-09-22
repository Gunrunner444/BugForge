const express = require("express");
const app = express();
app.get("/item/:id", function (id) {
  eval(id);
});
