import logging
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from app.config import ALLOWED_ORIGINS, SECURITY_HEADERS
from app.routes.health import router as health_router
from app.routes.analysis import router as analysis_router
from app.routes.reports import router as reports_router

logger = logging.getLogger("sentinel_api")

app = FastAPI(
    title="SecureCode Sentinel API",
    description="Backend service for SecureCode Sentinel SAST Platform",
    version="0.1.0",
)

# 1. Configure Hardened CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# 2. Configure Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# 3. Global Exception Handlers (Preventing Stack Trace Leaks)
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.warning(f"Input Validation Error: {exc}")
    err_msg = str(exc)
    if "exceeds maximum allowed limit" in err_msg:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": err_msg}
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": err_msg}
    )

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    msg = errors[0].get("msg", "Invalid request body format.") if errors else "Invalid request body."
    if "exceeds maximum allowed limit" in msg:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": msg}
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": f"Request validation failed: {msg}"}
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Static security analysis encountered an internal error."}
    )

# 4. Register API Routes
app.include_router(health_router)
app.include_router(analysis_router)
app.include_router(reports_router)

@app.get("/")
async def root():
    return {
        "name": "SecureCode Sentinel API",
        "status": "running",
        "docs": "/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
