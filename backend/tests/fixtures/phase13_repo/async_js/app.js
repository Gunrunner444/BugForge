import { wrap } from "./wrap.js";
const result = await wrap(req.query.q);
eval(result);
