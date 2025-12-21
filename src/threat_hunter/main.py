"""
Main application entry point for Autonomous Threat-Hunter
"""

import asyncio
import logging
from fastapi import FastAPI
from contextlib import asynccontextmanager

from .detector import ThreatDetector
from .investigator import ThreatInvestigator
from .responder import ThreatResponder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
detector = None
investigator = None
responder = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global detector, investigator, responder
    
    # Initialize components
    detector = ThreatDetector()
    investigator = ThreatInvestigator()
    responder = ThreatResponder()
    
    # Start monitoring
    monitor_task = asyncio.create_task(detector.start_monitoring())
    
    logger.info("Autonomous Threat-Hunter started")
    
    yield
    
    # Cleanup
    await detector.stop_monitoring()
    monitor_task.cancel()
    logger.info("Autonomous Threat-Hunter stopped")


app = FastAPI(
    title="Autonomous Threat-Hunter",
    description="24/7 autonomous security for AI agents",
    version="0.1.0",
    lifespan=lifespan
)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "Autonomous Threat-Hunter",
        "version": "0.1.0"
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "detector": "running" if detector and detector.running else "stopped",
        "investigator": "ready" if investigator else "not_ready",
        "responder": "ready" if responder else "not_ready"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
