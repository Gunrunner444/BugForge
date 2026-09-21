const obj = {};
obj.payload = req.query.q;
eval(obj.payload);
