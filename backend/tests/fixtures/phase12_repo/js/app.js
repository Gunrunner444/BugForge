import { runCode } from "./barrel.js";
import { runCode as execute } from "./helpers.js";

runCode(req.query.q);
execute("safe");
