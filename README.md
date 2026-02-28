# 🔀 cors-proxy

A lightweight, zero-dependency CORS proxy server written in pure Python 3.  
No third-party libraries. No frameworks. Just the standard library.

> Forward any HTTP request through the proxy and get back a response with proper `Access-Control-*` headers — so your browser stops complaining.

---

## ✨ Features

| Feature                      | Detail                                                                            |
| ---------------------------- | --------------------------------------------------------------------------------- |
| **Zero dependencies**        | Only Python 3 standard library                                                    |
| **All HTTP methods**         | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE                               |
| **Custom headers**           | Forward any header from client to target (Authorization, Cookie, X-Api-Key, etc.) |
| **Body forwarding**          | JSON, form-data, binary, multipart, chunked transfer                              |
| **Preflight handling**       | OPTIONS requests answered immediately — not forwarded                             |
| **SSRF protection**          | Blocks localhost, private IPs, AWS/GCP metadata endpoints                         |
| **Colored terminal log**     | Method, status, response size, elapsed time                                       |
| **Sensitive header masking** | Authorization / Cookie values are partially hidden in logs                        |
| **Configurable origins**     | Whitelist specific origins or allow all with `*`                                  |

---

## 📋 Requirements

- Python **3.10+** (uses `list[str]` type hints)
- No pip install needed

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/yourname/cors-proxy.git
cd cors-proxy

# Run on default port 8080
python cors_proxy.py

# Run on custom port
python cors_proxy.py 3000
```

The server starts and prints:

```
╔══════════════════════════════════════════════════════╗
║            CORS Proxy Server  🚀                     ║
╚══════════════════════════════════════════════════════╝

  ✔ Listening   : http://0.0.0.0:8080
  ✔ Timeout     : 20s
  ✔ Allowed CORS: ['*']
```

---

## 🔧 Usage

All requests go to the proxy with a `?url=` query parameter pointing to the target.

```
http://localhost:8080?url=<TARGET_URL>
```

### JavaScript / fetch

```js
const PROXY = "http://localhost:8080";

// GET
const res = await fetch(`${PROXY}?url=https://api.example.com/users`);
const data = await res.json();
```

```js
// POST with JSON body
const res = await fetch(`${PROXY}?url=https://api.example.com/users`, {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer eyJhbGci...",
    },
    body: JSON.stringify({ name: "Alice", email: "alice@example.com" }),
});
```

```js
// PUT - replace entire resource
await fetch(`${PROXY}?url=https://api.example.com/users/42`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Api-Key": "secret" },
    body: JSON.stringify({ name: "Alice Updated", role: "admin" }),
});
```

```js
// PATCH - partial update
await fetch(`${PROXY}?url=https://api.example.com/users/42`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role: "moderator" }),
});
```

```js
// DELETE
await fetch(`${PROXY}?url=https://api.example.com/users/42`, {
    method: "DELETE",
    headers: { Authorization: "Bearer eyJhbGci..." },
});
```

```js
// HEAD - check if resource exists (no body returned)
const res = await fetch(
    `${PROXY}?url=https://api.example.com/files/report.pdf`,
    {
        method: "HEAD",
    },
);
console.log(res.headers.get("Content-Length"));
```

### curl

```bash
# GET
curl "http://localhost:8080?url=https://api.example.com/data"

# POST JSON
curl -X POST "http://localhost:8080?url=https://api.example.com/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mytoken" \
  -d '{"name": "Alice"}'

# DELETE
curl -X DELETE "http://localhost:8080?url=https://api.example.com/users/1" \
  -H "Authorization: Bearer mytoken"
```

---

## 📡 HTTP Methods Reference

| Method    | Body     | Description                                     |
| --------- | -------- | ----------------------------------------------- |
| `GET`     | ✗        | Fetch data from target                          |
| `POST`    | ✅       | Create a new resource                           |
| `PUT`     | ✅       | Replace entire resource                         |
| `PATCH`   | ✅       | Partially update resource                       |
| `DELETE`  | optional | Delete a resource                               |
| `HEAD`    | ✗        | Fetch headers only (no body)                    |
| `OPTIONS` | ✗        | CORS preflight — handled locally, not forwarded |
| `TRACE`   | ✗        | Debug echo — forwarded if target supports it    |
| `CONNECT` | ✗        | Returns `405` — TCP tunneling not supported     |

---

## 🔑 Header Forwarding

Any header you attach to your request **will be forwarded** to the target, except for a small list of hop-by-hop headers that must not be proxied.

### Headers that ARE forwarded

```
Authorization: Bearer <token>
X-Api-Key: <key>
Cookie: session=abc123
Content-Type: application/json
Accept: application/json
Accept-Language: vi-VN, en-US
X-Custom-Header: anything-you-want
...and any other header
```

### Headers that are BLOCKED (not forwarded to target)

These headers are generated by the network layer or CDN and should not be copied:

```
Host
Connection
Keep-Alive
Transfer-Encoding
Upgrade
TE / Trailers
Proxy-Authenticate / Proxy-Authorization
X-Forwarded-For / X-Forwarded-Proto / X-Real-IP
CF-Connecting-IP / CF-Ray / CF-IPCountry / CF-Visitor
```

### Sensitive header masking in logs

Values for `Authorization`, `Cookie`, and `X-Api-Key` are partially hidden in terminal output to avoid leaking secrets:

```
Authorization: Bearer eyJh••••kpXV
Cookie: sessio••••c123
```

---

## ⚙️ Configuration

Edit the constants at the top of `cors_proxy.py`:

```python
# Allow all origins (default)
ALLOWED_ORIGINS = ["*"]

# Or restrict to specific origins
ALLOWED_ORIGINS = [
    "https://yourdomain.com",
    "http://localhost:3000",
]

# Timeout for requests to target (seconds)
REQUEST_TIMEOUT = 20
```

---

## 🛡️ Security

### SSRF Protection

The proxy blocks requests to private / internal addresses to prevent [Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery):

- `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`
- Private IP ranges: `10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`
- Cloud metadata endpoints: `169.254.169.254` (AWS), `metadata.google.internal` (GCP)
- DNS rebinding is mitigated by resolving the hostname to an IP before checking

### ⚠️ Warning

This proxy is intended for **local development** or **internal/trusted environments**.  
Do **not** expose it on a public IP without adding authentication (e.g. a secret token header check), otherwise anyone on the internet can use your server as an open proxy.

---

## 📊 Terminal Log Example

```
──────────────────────────────────────────────────────────────────────
[14:23:01.842] ▶ POST  from 127.0.0.1
  Target : https://api.example.com/users
  → Forward headers (3):
    Content-Type: application/json
    Authorization: Bearer eyJh••••pXVc
    Accept: application/json
  ↷ Skipped headers (2):
    Host
    Connection
  → Body: 42 bytes [application/json]
  ← Response headers from target:
    Content-Type: application/json
    X-Request-Id: a1b2c3
  Response: 201 │ application/json │ 0.2 KB │ 312.4ms
```

---

## 📁 Project Structure

```
cors-proxy/
├── cors_proxy.py   # Single-file server, no dependencies
├── README.md
└── LICENSE
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.
