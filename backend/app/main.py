from fastapi import FastAPI
from backend.app.database import Base, engine
from backend.app.models.asset import Asset


# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="CyberAgis AI",
    description="AI-powered cybersecurity risk assessment platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "CyberAgis AI",
        "status": "online",
        "message": "CyberAgis AI backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }