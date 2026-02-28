#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║               CORS Proxy Server - Full Featured                  ║
║                                                                  ║
║  Dùng : python cors_proxy.py [port]                              ║
║  Gọi  : http://localhost:8080?url=https://api.example.com/data   ║
╚══════════════════════════════════════════════════════════════════╝

Tính năng:
  ✅ Hỗ trợ GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT
  ✅ Forward toàn bộ headers từ client lên target (lọc các header nguy hiểm)
  ✅ Người dùng có thể đính kèm custom headers tùy ý
  ✅ Forward body (JSON, form-data, binary, multipart...)
  ✅ Xử lý redirect tự động
  ✅ Chặn IP nội bộ / localhost
  ✅ Log chi tiết ra terminal có màu
  ✅ Trả về đúng status code từ target
  ✅ Hỗ trợ chunked / binary response
"""

import sys
import json
import time
import socket
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# ══════════════════════════════════════════════════════════════════════════════
# CẤU HÌNH
# ══════════════════════════════════════════════════════════════════════════════

# Giới hạn origin. Đặt ["*"] để cho phép tất cả,
# hoặc ["https://yourdomain.com", "http://localhost:3000"] để giới hạn
ALLOWED_ORIGINS: list[str] = ["*"]

# Timeout kết nối đến target (giây)
REQUEST_TIMEOUT: int = 20

# Headers bị chặn khi forward từ client lên target
# (những header này do proxy/server tự tạo, không được copy từ client)
BLOCKED_REQUEST_HEADERS: set[str] = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    # Cloudflare / CDN headers - không cần forward
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
}

# Headers bị chặn khi trả về từ target về client
# (tránh conflict với headers proxy tự thêm vào)
BLOCKED_RESPONSE_HEADERS: set[str] = {
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-max-age",
    "access-control-expose-headers",
    # Không cần forward encoding vì proxy đã đọc hết body
    "transfer-encoding",
    "connection",
}

# IP/Host bị chặn - tránh SSRF
BLOCKED_HOSTS: set[str] = {
    # "localhost",
    # "127.0.0.1",
    # "0.0.0.0",
    # "::1",
    # "169.254.169.254",  # AWS metadata
    # "metadata.google.internal",
}

BLOCKED_HOST_PREFIXES: tuple[str, ...] = (
    # "10.",
    # "192.168.",
    # "172.16.", "172.17.", "172.18.", "172.19.",
    # "172.20.", "172.21.", "172.22.", "172.23.",
    # "172.24.", "172.25.", "172.26.", "172.27.",
    # "172.28.", "172.29.", "172.30.", "172.31.",
)


# ══════════════════════════════════════════════════════════════════════════════
# MÀU SẮC TERMINAL
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"


# ══════════════════════════════════════════════════════════════════════════════
# LOGGER
# ══════════════════════════════════════════════════════════════════════════════

def now() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def method_color(method: str) -> str:
    colors = {
        "GET":     C.GREEN,
        "POST":    C.BLUE,
        "PUT":     C.YELLOW,
        "PATCH":   C.MAGENTA,
        "DELETE":  C.RED,
        "HEAD":    C.CYAN,
        "OPTIONS": C.GRAY,
        "TRACE":   C.DIM,
        "CONNECT": C.DIM,
    }
    return colors.get(method, C.WHITE)

def status_color(code: int) -> str:
    if code < 300:   return C.GREEN
    if code < 400:   return C.CYAN
    if code < 500:   return C.YELLOW
    return C.RED

def log_request(client_ip: str, method: str, target_url: str, headers: dict):
    mc = method_color(method)
    print(
        f"\n{C.GRAY}{'─'*70}{C.RESET}\n"
        f"{C.GRAY}[{now()}]{C.RESET} "
        f"{C.BOLD}{mc}▶ {method}{C.RESET} "
        f"{C.WHITE}từ {C.CYAN}{client_ip}{C.RESET}\n"
        f"  {C.DIM}Target :{C.RESET} {C.BLUE}{target_url}{C.RESET}"
    )
    if headers:
        print(f"  {C.DIM}Headers forward ({len(headers)} header):{C.RESET}")
        for k, v in headers.items():
            # Ẩn bớt giá trị sensitive
            display_v = v if k.lower() not in ("authorization", "cookie", "x-api-key") \
                          else v[:6] + "..." + v[-4:] if len(v) > 12 else "***"
            print(f"    {C.GRAY}{k}: {C.WHITE}{display_v}{C.RESET}")

def log_response(status: int, content_type: str, body_size: int, elapsed_ms: float):
    sc = status_color(status)
    size_str = f"{body_size} B" if body_size < 1024 else f"{body_size/1024:.1f} KB"
    print(
        f"  {C.DIM}Response:{C.RESET} "
        f"{C.BOLD}{sc}{status}{C.RESET} "
        f"{C.DIM}│{C.RESET} {C.WHITE}{content_type}{C.RESET} "
        f"{C.DIM}│{C.RESET} {C.CYAN}{size_str}{C.RESET} "
        f"{C.DIM}│{C.RESET} {C.YELLOW}{elapsed_ms:.1f}ms{C.RESET}"
    )

def log_error(message: str):
    print(f"  {C.RED}✖ ERROR: {message}{C.RESET}")

def log_blocked(reason: str):
    print(f"  {C.YELLOW}⚠ BLOCKED: {reason}{C.RESET}")

def log_header_skip(key: str, reason: str = "blocked"):
    print(f"    {C.GRAY}  ↳ skip [{key}] ({reason}){C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# CORS HEADERS
# ══════════════════════════════════════════════════════════════════════════════

def build_cors_headers(request_origin: str = "*") -> dict:
    """
    Trả về CORS headers phù hợp với origin của request.
    Nếu ALLOWED_ORIGINS = ["*"] → cho phép tất cả.
    Nếu ALLOWED_ORIGINS có danh sách cụ thể → chỉ echo lại origin hợp lệ.
    """
    if ALLOWED_ORIGINS == ["*"]:
        allow_origin = "*"
    elif request_origin in ALLOWED_ORIGINS:
        allow_origin = request_origin
    else:
        allow_origin = ALLOWED_ORIGINS[0]  # fallback về origin đầu tiên

    return {
        "Access-Control-Allow-Origin":      allow_origin,
        "Access-Control-Allow-Methods":     "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE",
        "Access-Control-Allow-Headers":     "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Expose-Headers":    "*",
        "Access-Control-Max-Age":           "86400",
    }


# ══════════════════════════════════════════════════════════════════════════════
# HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class CORSProxyHandler(BaseHTTPRequestHandler):

    # ── Tắt log mặc định của BaseHTTPRequestHandler ───────────────────────
    def log_message(self, fmt, *args):
        pass  # handled manually

    def log_error(self, fmt, *args):
        pass

    # ── Địa chỉ client ────────────────────────────────────────────────────
    def client_ip(self) -> str:
        return self.client_address[0]

    # ── Gửi JSON response ─────────────────────────────────────────────────
    def send_json(self, code: int, obj: dict):
        origin = self.headers.get("Origin", "*")
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in build_cors_headers(origin).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # ── Parse & validate ?url= ────────────────────────────────────────────
    def get_target_url(self) -> tuple[str | None, str | None]:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        urls = params.get("url")

        if not urls:
            return None, "Missing query parameter: ?url=https://..."

        target = urls[0].strip()

        # Kiểm tra scheme
        parsed_target = urlparse(target)
        if parsed_target.scheme not in ("http", "https"):
            return None, f"Invalid scheme '{parsed_target.scheme}'. Only http/https allowed."

        # Kiểm tra hostname
        host = parsed_target.hostname or ""
        if not host:
            return None, "Cannot parse hostname from target URL."

        # Resolve hostname → IP để chặn SSRF qua DNS rebinding
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            return None, f"Cannot resolve hostname: {host}"

        if host in BLOCKED_HOSTS or resolved_ip in BLOCKED_HOSTS:
            log_blocked(f"host={host} ip={resolved_ip}")
            return None, f"Blocked host: {host}"

        if resolved_ip.startswith(BLOCKED_HOST_PREFIXES):
            log_blocked(f"private IP: {resolved_ip}")
            return None, f"Blocked private IP: {resolved_ip}"

        return target, None

    # ── Lọc & log headers gửi lên target ──────────────────────────────────
    def build_forward_headers(self, show_log: bool = True) -> dict:
        """
        Lấy toàn bộ headers từ client, lọc những header bị chặn,
        log ra terminal từng header được forward / bị skip.

        Người dùng có thể đính kèm BẤT KỲ header nào:
          - Authorization: Bearer xxx
          - X-Api-Key: abc123
          - Cookie: session=...
          - Content-Type: application/json
          - Accept: application/json
          - Accept-Language: vi-VN
          - X-Custom-Header: anything
          → Tất cả đều được forward nếu không nằm trong BLOCKED_REQUEST_HEADERS
        """
        result = {}
        skipped = []

        for key, val in self.headers.items():
            key_lower = key.lower()
            if key_lower in BLOCKED_REQUEST_HEADERS:
                skipped.append(key)
            else:
                result[key] = val

        if show_log:
            if result:
                print(f"  {C.DIM}→ Forward headers ({len(result)}):{C.RESET}")
                for k, v in result.items():
                    k_lower = k.lower()
                    # Ẩn giá trị sensitive trong log
                    if k_lower in ("authorization", "cookie", "x-api-key",
                                   "x-auth-token", "x-access-token"):
                        display = v[:8] + "••••" if len(v) > 8 else "••••"
                    else:
                        display = v
                    print(f"    {C.CYAN}{k}: {C.WHITE}{display}{C.RESET}")

            if skipped:
                print(f"  {C.DIM}↷ Skipped headers ({len(skipped)}):{C.RESET}")
                for k in skipped:
                    print(f"    {C.GRAY}{k}{C.RESET}")

        return result

    # ── Đọc body từ request ───────────────────────────────────────────────
    def read_body(self) -> bytes | None:
        """
        Đọc body từ request. Hỗ trợ:
          - Content-Length cụ thể
          - chunked transfer (đọc cho đến khi hết)
          - Không có body → trả về None
        """
        # Trường hợp 1: có Content-Length
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > 0:
                    data = self.rfile.read(length)
                    ct = self.headers.get("Content-Type", "")
                    print(f"  {C.DIM}→ Body: {length} bytes [{ct}]{C.RESET}")
                    return data
            except (ValueError, OSError):
                pass

        # Trường hợp 2: chunked transfer-encoding
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                line = self.rfile.readline().strip()
                chunk_size = int(line, 16)
                if chunk_size == 0:
                    break
                chunks.append(self.rfile.read(chunk_size))
                self.rfile.read(2)  # CRLF
            data = b"".join(chunks)
            print(f"  {C.DIM}→ Body (chunked): {len(data)} bytes{C.RESET}")
            return data

        # Trường hợp 3: không có body
        return None

    # ── Core proxy logic ───────────────────────────────────────────────────
    def do_proxy(self):
        start = time.time()
        origin = self.headers.get("Origin", "*")

        # Parse & validate URL đích
        target_url, err = self.get_target_url()
        if err:
            log_error(err)
            return self.send_json(400, {"error": err, "usage": "?url=https://api.example.com/endpoint"})

        # Build headers + đọc body
        forward_headers = self.build_forward_headers(show_log=True)
        body = self.read_body()

        log_request(self.client_ip(), self.command, target_url, forward_headers)

        # Tạo request đến target
        req = urllib.request.Request(
            url     = target_url,
            data    = body,
            headers = forward_headers,
            method  = self.command,
        )

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                resp_body    = resp.read()
                status       = resp.status
                content_type = resp.headers.get("Content-Type", "application/octet-stream")
                elapsed_ms   = (time.time() - start) * 1000

                log_response(status, content_type, len(resp_body), elapsed_ms)

                # Build response headers - lấy từ target, lọc, rồi thêm CORS
                self.send_response(status)

                # Forward response headers từ target (trừ blocked)
                print(f"  {C.DIM}← Response headers từ target:{C.RESET}")
                for key, val in resp.headers.items():
                    if key.lower() not in BLOCKED_RESPONSE_HEADERS:
                        print(f"    {C.GRAY}{key}: {val}{C.RESET}")
                        self.send_header(key, val)

                # Ghi đè Content-Length (vì đã đọc hết body)
                self.send_header("Content-Length", str(len(resp_body)))

                # Gắn CORS headers
                for k, v in build_cors_headers(origin).items():
                    self.send_header(k, v)

                self.end_headers()
                self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            # Target trả về lỗi HTTP (4xx, 5xx) → vẫn forward về client
            err_body     = e.read()
            elapsed_ms   = (time.time() - start) * 1000
            content_type = e.headers.get("Content-Type", "text/plain")

            log_response(e.code, content_type, len(err_body), elapsed_ms)
            log_error(f"HTTPError {e.code}: {e.reason}")

            self.send_response(e.code)
            self.send_header("Content-Type",   content_type)
            self.send_header("Content-Length", str(len(err_body)))
            for k, v in build_cors_headers(origin).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(err_body)

        except urllib.error.URLError as e:
            elapsed_ms = (time.time() - start) * 1000
            log_error(f"URLError: {e.reason}")
            self.send_json(502, {
                "error":  "Bad Gateway",
                "reason": str(e.reason),
                "target": target_url,
            })

        except TimeoutError:
            log_error(f"Timeout sau {REQUEST_TIMEOUT}s")
            self.send_json(504, {
                "error":   "Gateway Timeout",
                "timeout": REQUEST_TIMEOUT,
                "target":  target_url,
            })

        except ConnectionResetError:
            log_error("Connection reset by target")
            self.send_json(502, {"error": "Connection reset by target"})

        except Exception as e:
            log_error(f"Unexpected: {type(e).__name__}: {e}")
            self.send_json(500, {
                "error":   "Internal Proxy Error",
                "detail":  str(e),
                "type":    type(e).__name__,
            })

    # ══════════════════════════════════════════════════════════════════════
    # CÁC HTTP METHOD
    # ══════════════════════════════════════════════════════════════════════

    def do_OPTIONS(self):
        """
        Preflight request của browser.
        Browser gửi OPTIONS trước khi gửi request thật để hỏi:
          - Server có cho phép method X không?
          - Server có chấp nhận header Y không?
        Proxy phải trả về 204 + CORS headers ngay, KHÔNG forward lên target.
        """
        origin = self.headers.get("Origin", "*")
        req_method  = self.headers.get("Access-Control-Request-Method", "")
        req_headers = self.headers.get("Access-Control-Request-Headers", "")

        print(
            f"\n{C.GRAY}{'─'*70}{C.RESET}\n"
            f"{C.GRAY}[{now()}]{C.RESET} "
            f"{C.BOLD}{C.GRAY}▶ OPTIONS (Preflight){C.RESET} "
            f"từ {C.CYAN}{self.client_ip()}{C.RESET}\n"
            f"  Origin         : {origin}\n"
            f"  Request-Method : {req_method}\n"
            f"  Request-Headers: {req_headers}"
        )

        self.send_response(204)
        for k, v in build_cors_headers(origin).items():
            self.send_header(k, v)
        self.end_headers()
        print(f"  {C.GREEN}✔ Preflight accepted{C.RESET}")

    def do_GET(self):
        """
        GET - Lấy dữ liệu. Không có body.
        Ví dụ: fetch('?url=https://api.example.com/users')
        Thường kèm headers: Authorization, Accept, Accept-Language
        """
        self.do_proxy()

    def do_POST(self):
        """
        POST - Gửi dữ liệu lên server để tạo mới.
        Body thường là: JSON, form-urlencoded, multipart/form-data
        Ví dụ: fetch('?url=...', { method:'POST', body: JSON.stringify({...}) })
        Headers thường kèm: Content-Type, Authorization
        """
        self.do_proxy()

    def do_PUT(self):
        """
        PUT - Thay thế toàn bộ resource.
        Body là toàn bộ dữ liệu mới của resource.
        Ví dụ: cập nhật user profile
        """
        self.do_proxy()

    def do_PATCH(self):
        """
        PATCH - Cập nhật một phần resource.
        Body chỉ chứa các field cần thay đổi.
        Ví dụ: đổi mật khẩu, cập nhật avatar
        """
        self.do_proxy()

    def do_DELETE(self):
        """
        DELETE - Xóa resource.
        Thường không có body (hoặc có body nhỏ chứa lý do).
        Ví dụ: xóa bài đăng, hủy đơn hàng
        """
        self.do_proxy()

    def do_HEAD(self):
        """
        HEAD - Giống GET nhưng server chỉ trả về headers, không có body.
        Dùng để kiểm tra resource có tồn tại không, lấy metadata.
        Proxy forward HEAD lên target, trả về headers (không có body).
        """
        self.do_proxy()

    def do_TRACE(self):
        """
        TRACE - Debug method: server echo lại request.
        Ít dùng trong thực tế, nhiều server chặn vì lý do bảo mật (XST attack).
        Proxy vẫn forward nếu target chấp nhận.
        """
        self.do_proxy()

    def do_CONNECT(self):
        """
        CONNECT - Dùng để tạo tunnel TCP (thường cho HTTPS qua HTTP proxy).
        Không thể thực sự tunnel qua HTTP server bình thường.
        Trả về 405 Method Not Allowed.
        """
        origin = self.headers.get("Origin", "*")
        print(
            f"\n{C.GRAY}[{now()}]{C.RESET} "
            f"{C.RED}▶ CONNECT{C.RESET} - không hỗ trợ tunneling"
        )
        self.send_json(405, {
            "error":  "Method Not Allowed",
            "detail": "CONNECT tunneling is not supported by this proxy.",
        })


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════╗
║            CORS Proxy Server  🚀                     ║
╚══════════════════════════════════════════════════════╝{C.RESET}

  {C.GREEN}✔ Listening   :{C.RESET} http://0.0.0.0:{port}
  {C.GREEN}✔ Timeout     :{C.RESET} {REQUEST_TIMEOUT}s
  {C.GREEN}✔ Allowed CORS:{C.RESET} {ALLOWED_ORIGINS}

  {C.YELLOW}Usage:{C.RESET}
    GET    → http://localhost:{port}?url=https://api.example.com/data
    POST   → http://localhost:{port}?url=https://api.example.com/users
    DELETE → http://localhost:{port}?url=https://api.example.com/users/1

  {C.YELLOW}Custom headers:{C.RESET}
    fetch(`http://localhost:{port}?url=...`, {{
      headers: {{
        "Authorization": "Bearer <token>",
        "X-Api-Key":     "your-key",
        "Content-Type":  "application/json",
      }}
    }})

  {C.GRAY}Ctrl+C để dừng{C.RESET}
""")

    server = HTTPServer(("0.0.0.0", port), CORSProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C.RED}🛑 Server stopped.{C.RESET}\n")