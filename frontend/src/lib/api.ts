const API_BASE = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE || 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || '';

const getHeaders = (isJson = false) => {
  const headers: Record<string, string> = {};
  if (API_KEY) {
    headers['X-API-Key'] = API_KEY;
  }
  if (isJson) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
};

export async function postJson<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: getHeaders(false),
    body: formData,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}
