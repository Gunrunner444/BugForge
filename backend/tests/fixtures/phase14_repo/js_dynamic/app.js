const obj = {};
const key = "payload";
obj[key] = req.query.q;
eval(obj[key]);
eval(obj.payload);
