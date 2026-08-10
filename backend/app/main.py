from fastapi import FastAPI

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