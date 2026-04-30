import axios from "axios";

const root = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");
const baseURL = root.endsWith("/api") ? root : `${root}/api`;

export const api = axios.create({
  baseURL,
  timeout: 30000,
});
