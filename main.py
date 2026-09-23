# main.py — API IMEI Colombia v2.1.0
# Seguridad: rate limiting, bloqueo de IPs, validación estricta, headers de seguridad

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import requests
import urllib3
from bs4 import BeautifulSoup
import time
import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Rate Limiter (slowapi) ───────────────────────────────────────────────────
# Instala con: pip install slowapi

limiter = Limiter(key_func=get_remote_address)

# ─── Bloqueo de IPs abusivas (en memoria) ────────────────────────────────────

class IPBlocker:
    """
    Bloquea IPs que superen el umbral de errores 429 consecutivos.
    Si una IP acumula MAX_VIOLATIONS en WINDOW_MINUTES, queda bloqueada
    BLOCK_MINUTES minutos.
    """
    MAX_VIOLATIONS = 10
    WINDOW_MINUTES = 5
    BLOCK_MINUTES  = 30

    def __init__(self):
        self._violations: dict[str, list[datetime]] = defaultdict(list)
        self._blocked:    dict[str, datetime]        = {}
        self._lock = Lock()

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                if datetime.utcnow() < self._blocked[ip]:
                    return True
                else:
                    del self._blocked[ip]
            return False

    def register_violation(self, ip: str):
        with self._lock:
            now = datetime.utcnow()
            cutoff = now - timedelta(minutes=self.WINDOW_MINUTES)
            self._violations[ip] = [
                t for t in self._violations[ip] if t > cutoff
            ]
            self._violations[ip].append(now)
            if len(self._violations[ip]) >= self.MAX_VIOLATIONS:
                self._blocked[ip] = now + timedelta(minutes=self.BLOCK_MINUTES)
                logger.warning(f"IP bloqueada por abuso: {ip}")
                self._violations[ip] = []

ip_blocker = IPBlocker()

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="API IMEI Colombia",
    version="2.1.0",
    # Deshabilitar docs en producción para no exponer endpoints
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — solo permite el origen de tu app/dominio
# En producción cambia "*" por tu dominio real: ["https://tudominio.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],          # solo GET, sin POST/PUT/DELETE
    allow_headers=["Accept", "Content-Type"],
    max_age=3600,
)

# ─── Middleware de seguridad ───────────────────────────────────────────────────

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = get_remote_address(request)

    # 1. Bloquear IPs marcadas como abusivas
    if ip_blocker.is_blocked(ip):
        logger.warning(f"Solicitud bloqueada de IP: {ip}")
        return JSONResponse(
            status_code=403,
            content={"detail": "Acceso bloqueado temporalmente."}
        )

    # 2. Rechazar User-Agents vacíos o de bots conocidos
    ua = request.headers.get("user-agent", "").lower()
    bad_agents = ["sqlmap", "nikto", "nmap", "masscan", "zgrab",
                  "python-requests/2.2", "curl/7.2", "wget/"]
    if not ua or any(b in ua for b in bad_agents):
        logger.warning(f"User-agent sospechoso bloqueado: '{ua}' desde {ip}")
        return JSONResponse(
            status_code=403,
            content={"detail": "Acceso denegado."}
        )

    # 3. Rechazar paths que no existen (escaneos de vulnerabilidades)
    allowed_paths = ["/", "/imei/", "/health"]
    path = request.url.path
    if not any(path == p or path.startswith("/imei/") for p in allowed_paths):
        logger.warning(f"Path no permitido: {path} desde {ip}")
        return JSONResponse(status_code=404, content={"detail": "Not found."})

    response = await call_next(request)

    # 4. Registrar violación si el response fue 429
    if response.status_code == 429:
        ip_blocker.register_violation(ip)

    # 5. Headers de seguridad en todas las respuestas
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=()"
    response.headers["Cache-Control"]             = "no-store"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "font-src https://fonts.gstatic.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    # Quitar header que revela el servidor
    response.headers.pop("server", None)
    response.headers.pop("x-powered-by", None)

    return response

# ─── Modelos ──────────────────────────────────────────────────────────────────

class Reporte(BaseModel):
    causal:       str
    causal_texto: str
    operador:     str

class IMEIResponse(BaseModel):
    imei:             str
    estado:           str
    en_base_negativa: bool
    causales:         list[str]
    operadores:       list[str]
    reportes:         list[Reporte]
    total_reportes:   int
    resumen:          str

# ─── Clasificador de causales ─────────────────────────────────────────────────

CAUSALES_MAP = {
    "robo/hurto":            "ROBO_HURTO",
    "robo":                  "ROBO_HURTO",
    "hurto":                 "ROBO_HURTO",
    "bloqueo/no registrado": "BLOQUEO_NO_REGISTRADO",
    "bloqueo":               "BLOQUEO_NO_REGISTRADO",
    "no registrado":         "BLOQUEO_NO_REGISTRADO",
    "duplicado":             "DUPLICADO",
    "reincidente":           "REINCIDENTE",
    "pérdida":               "PERDIDA",
    "perdida":               "PERDIDA",
    "prepago":               "PREPAGO",
    "postpago":              "POSTPAGO",
}

def clasificar_causal(texto: str) -> str:
    t = texto.lower()
    for clave, codigo in CAUSALES_MAP.items():
        if clave in t:
            return codigo
    return "OTRO"

def extraer_causal_texto(celda) -> str:
    bold = celda.find('b')
    if bold:
        texto = bold.get_text(strip=True)
        texto = re.sub(r':\s*\d+', '', texto).strip()
        return texto
    return celda.get_text(strip=True)

# ─── Parser ───────────────────────────────────────────────────────────────────

def parsear_respuesta(imei: str, html: str) -> IMEIResponse:
    soup  = BeautifulSoup(html, 'html.parser')
    filas = soup.find_all('tr', class_='azlc')

    if not filas:
        return IMEIResponse(
            imei=imei, estado="ERROR", en_base_negativa=False,
            causales=[], operadores=[], reportes=[],
            total_reportes=0,
            resumen="No se encontró resultado en la respuesta del servidor"
        )

    reportes: list[Reporte] = []

    for fila in filas:
        celdas = fila.find_all('td')
        if len(celdas) < 2:
            continue

        celda_msg      = celdas[0]
        celda_operador = celdas[1]
        msg_texto      = celda_msg.get_text(strip=True)
        operador       = celda_operador.get_text(strip=True)
        msg_lower      = msg_texto.lower()

        if "no se encuentra registrado en la base de datos negativa" in \
                celda_operador.get_text(strip=True).lower():
            return IMEIResponse(
                imei=msg_texto, estado="LIMPIO", en_base_negativa=False,
                causales=[], operadores=[], reportes=[],
                total_reportes=0,
                resumen="El IMEI no se encuentra registrado en la Base de Datos Negativa"
            )

        reportes.append(Reporte(
            causal=clasificar_causal(msg_lower),
            causal_texto=extraer_causal_texto(celda_msg),
            operador=operador,
        ))

    if not reportes:
        return IMEIResponse(
            imei=imei, estado="DESCONOCIDO", en_base_negativa=False,
            causales=[], operadores=[], reportes=[],
            total_reportes=0,
            resumen="No se pudo interpretar la respuesta del SRTM"
        )

    causales_unicas   = list(dict.fromkeys(r.causal   for r in reportes))
    operadores_unicos = list(dict.fromkeys(r.operador for r in reportes))
    estado = reportes[0].causal if len(reportes) == 1 else "MULTIPLE"
    resumen = (
        f"Reportado por {len(reportes)} causal(es): "
        f"{', '.join(causales_unicas)}. "
        f"Operador(es): {', '.join(operadores_unicos)}."
    )

    return IMEIResponse(
        imei=imei, estado=estado, en_base_negativa=True,
        causales=causales_unicas, operadores=operadores_unicos,
        reportes=reportes, total_reportes=len(reportes), resumen=resumen
    )

# ─── HTTP al SRTM ─────────────────────────────────────────────────────────────

def consultar_imei_srtm(imei: str) -> IMEIResponse:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://www.imeicolombia.com.co/",
        "Origin":  "https://www.imeicolombia.com.co",
    }
    session = requests.Session()
    session.get("https://www.imeicolombia.com.co/",
                headers=headers, timeout=10, verify=False)
    response = session.post(
        "https://www.imeicolombia.com.co/Consulta",
        data={"IMEI": imei}, headers=headers, timeout=15, verify=False
    )
    response.encoding = 'iso-8859-1'
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"El servidor SRTM respondió con HTTP {response.status_code}"
        )
    return parsear_respuesta(imei, response.text)

def validar_imei(imei: str) -> bool:
    return bool(re.match(r'^\d{15}$', imei))

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/imei/{imei}", response_model=IMEIResponse, include_in_schema=False)
@limiter.limit("10/minute")          # máx 10 consultas por minuto por IP
async def consultar_imei(imei: str, request: Request):
    """
    Consulta el estado de un IMEI en el SRTM Colombia.
    Rate limit: 10 req/min por IP. Bloqueo automático tras abuso.
    """
    # Sanitizar: solo dígitos, exactamente 15
    imei_clean = re.sub(r'\D', '', imei)
    if not validar_imei(imei_clean):
        raise HTTPException(
            status_code=400,
            detail="IMEI inválido. Debe tener exactamente 15 dígitos numéricos."
        )

    ip = get_remote_address(request)
    logger.info(f"Consulta IMEI: {imei_clean[:6]}******* desde {ip}")

    return consultar_imei_srtm(imei_clean)


@app.get("/health", include_in_schema=False)
@limiter.limit("30/minute")
async def health(request: Request):
    return {"status": "ok", "version": "2.1.0"}