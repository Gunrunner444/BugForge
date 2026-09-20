import { Request, Response } from "express";
import axios from "axios";

export async function proxy(req: Request, res: Response) {
  const data = await axios.get("https://example.internal/health");
  res.send(data.data);
}

export async function search(req: Request, res: Response) {
  const q = req.query.q as string;
  db.query("SELECT * FROM t WHERE x = $1", [q]);
  res.send("ok");
}
