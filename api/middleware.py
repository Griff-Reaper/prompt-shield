"""
Prompt-Shield: FastAPI Middleware

Drop-in middleware for protecting FastAPI applications from prompt injection attacks.
Automatically scans incoming requests and blocks malicious prompts.
"""

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Callable, Dict, Any, Optional, List
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json

from ..detection.detector import PromptInjectionDetector, ThreatLevel

logger = logging.getLogger(__name__)


class PromptShieldMiddleware:
    """
    FastAPI middleware for prompt injection protection
    
    Features:
    - Automatic prompt scanning
    - Configurable blocking thresholds
    - Rate limiting for suspicious IPs
    - Detailed logging and metrics
    - Customizable response handling
    """
    
    def __init__(
        self,
        app: FastAPI,
        block_threshold: float = 50.0,
        log_threshold: float = 30.0,
        enable_rate_limiting: bool = True,
        rate_limit_window: int = 300,  # 5 minutes
        max_requests_per_window: int = 100,
        protected_fields: Optional[List[str]] = None,
        custom_response: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize Prompt-Shield middleware
        
        Args:
            app: FastAPI application
            block_threshold: Risk score threshold for blocking (0-100)
            log_threshold: Risk score threshold for logging (0-100)
            enable_rate_limiting: Enable rate limiting for suspicious IPs
            rate_limit_window: Time window for rate limiting (seconds)
            max_requests_per_window: Max requests allowed in window
            protected_fields: List of request fields to scan (defaults to common fields)
            custom_response: Custom error response for blocked requests
        """
        self.app = app
        self.detector = PromptInjectionDetector()
        self.block_threshold = block_threshold
        self.log_threshold = log_threshold
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limit_window = rate_limit_window
        self.max_requests_per_window = max_requests_per_window
        
        # Default protected fields if not specified
        self.protected_fields = protected_fields or [
            "prompt", "input", "query", "message", "text", "content",
            "user_input", "question", "command"
        ]
        
        self.custom_response = custom_response or {
            "error": "Potential prompt injection detected",
            "details": "Your request was blocked for security reasons"
        }
        
        # Rate limiting storage
        self.request_counts: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, datetime] = {}
        
        # Metrics
        self.total_requests = 0
        self.blocked_requests = 0
        self.suspicious_requests = 0
    
    async def __call__(self, request: Request, call_next: Callable):
        """Process incoming request"""
        self.total_requests += 1
        client_ip = request.client.host
        
        # Check if IP is temporarily blocked
        if self.enable_rate_limiting and self._is_ip_blocked(client_ip):
            logger.warning(f"Blocked request from rate-limited IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Too many suspicious requests. Please try again later."}
            )
        
        # Scan request for injections
        try:
            # Get request body
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                
                try:
                    # Try to parse as JSON
                    json_body = json.loads(body) if body else {}
                    
                    # Scan protected fields
                    for field in self.protected_fields:
                        if field in json_body:
                            value = json_body[field]
                            
                            if isinstance(value, str):
                                result = self.detector.detect(value)
                                
                                # Log if above threshold
                                if result.risk_score >= self.log_threshold:
                                    self.suspicious_requests += 1
                                    logger.warning(
                                        f"Suspicious prompt detected | "
                                        f"IP: {client_ip} | "
                                        f"Field: {field} | "
                                        f"Risk: {result.risk_score:.1f} | "
                                        f"Patterns: {result.patterns_detected}"
                                    )
                                
                                # Block if above threshold
                                if result.risk_score >= self.block_threshold:
                                    self.blocked_requests += 1
                                    
                                    # Track for rate limiting
                                    if self.enable_rate_limiting:
                                        self._record_suspicious_request(client_ip)
                                    
                                    logger.error(
                                        f"BLOCKED prompt injection | "
                                        f"IP: {client_ip} | "
                                        f"Risk: {result.risk_score:.1f} | "
                                        f"Level: {result.threat_level.name}"
                                    )
                                    
                                    response = self.custom_response.copy()
                                    response["risk_score"] = result.risk_score
                                    response["threat_level"] = result.threat_level.name
                                    
                                    return JSONResponse(
                                        status_code=status.HTTP_400_BAD_REQUEST,
                                        content=response
                                    )
                
                except json.JSONDecodeError:
                    # Not JSON, skip
                    pass
                
                # Rebuild request with original body
                async def receive():
                    return {"type": "http.request", "body": body}
                
                request._receive = receive
        
        except Exception as e:
            logger.error(f"Error in Prompt-Shield middleware: {e}")
            # Don't block on errors, let request through
        
        # Process request normally
        response = await call_next(request)
        return response
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip in self.blocked_ips:
            block_time = self.blocked_ips[ip]
            if datetime.now() - block_time < timedelta(minutes=15):
                return True
            else:
                # Unblock after timeout
                del self.blocked_ips[ip]
        return False
    
    def _record_suspicious_request(self, ip: str):
        """Record a suspicious request for rate limiting"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.rate_limit_window)
        
        # Clean old requests
        while self.request_counts[ip] and self.request_counts[ip][0] < cutoff:
            self.request_counts[ip].popleft()
        
        # Add new request
        self.request_counts[ip].append(now)
        
        # Check if threshold exceeded
        if len(self.request_counts[ip]) >= self.max_requests_per_window:
            self.blocked_ips[ip] = now
            logger.warning(f"IP {ip} blocked due to excessive suspicious requests")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get protection metrics"""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "suspicious_requests": self.suspicious_requests,
            "block_rate": (self.blocked_requests / max(self.total_requests, 1)) * 100,
            "currently_blocked_ips": len(self.blocked_ips)
        }


def create_protected_app(
    title: str = "API with Prompt-Shield",
    block_threshold: float = 50.0,
    **middleware_kwargs
) -> FastAPI:
    """
    Create a FastAPI app with Prompt-Shield protection
    
    Args:
        title: API title
        block_threshold: Risk score threshold for blocking
        **middleware_kwargs: Additional middleware configuration
        
    Returns:
        FastAPI app with protection enabled
    """
    app = FastAPI(title=title)
    
    # Add Prompt-Shield middleware
    middleware = PromptShieldMiddleware(
        app=app,
        block_threshold=block_threshold,
        **middleware_kwargs
    )
    
    app.middleware("http")(middleware)
    
    # Add metrics endpoint
    @app.get("/shield/metrics")
    async def get_shield_metrics():
        """Get Prompt-Shield protection metrics"""
        return middleware.get_metrics()
    
    # Add health check
    @app.get("/shield/health")
    async def shield_health():
        """Health check for Prompt-Shield"""
        return {
            "status": "operational",
            "protection_enabled": True,
            "block_threshold": middleware.block_threshold
        }
    
    return app