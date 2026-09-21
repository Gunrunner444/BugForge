import { Request, Response } from "express";
import axios from "axios";

export async function proxy(req: Request, res: Response) {
  const target = req.query.url as string;
  const data = await axios.get(target);
  res.send(data.data);
}

export async function search(req: Request, res: Response) {
  const q = req.query.q as string;
  db.query("SELECT * FROM t WHERE x = '" + q + "'");
  res.send("ok");
}
