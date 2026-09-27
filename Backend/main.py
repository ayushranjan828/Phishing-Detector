"""FastAPI backend for the phishing URL detector.

Run from the project root:
    uvicorn Backend.main:app --reload
"""

import warnings
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .features import extract_features

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "Notebook" / "phishing_model.pkl"
FRONTEND_DIR = ROOT / "Frontend"

with warnings.catch_warnings():
    warnings.simplefilter("ignore")  # minor sklearn version mismatch warnings
    model = joblib.load(MODEL_PATH)

FEATURE_COLUMNS = list(model.feature_names_in_)

app = FastAPI(title="Phishing URL Detector", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


class ExternalOverrides(BaseModel):
    """Optional values for features that need third-party services."""

    google_index: int | None = Field(None, ge=0, le=1, description="0 = indexed, 1 = not indexed")
    page_rank: int | None = Field(None, ge=0, le=10)
    web_traffic: int | None = Field(None, ge=0, description="Alexa-style rank, 0 = unknown")
    domain_age: int | None = Field(None, ge=-1, description="Days, -1 = unknown")
    domain_registration_length: int | None = Field(None, ge=-1, description="Days")
    whois_registered_domain: int | None = Field(None, ge=0, le=1, description="0 = registered")


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    fetch_page: bool = True
    overrides: ExternalOverrides | None = None


class FeatureRequest(BaseModel):
    features: dict[str, float]


def _predict(features: dict) -> dict:
    sample = pd.DataFrame([features]).reindex(columns=FEATURE_COLUMNS, fill_value=0)
    probability = float(model.predict_proba(sample)[0, 1])
    return {
        "label": "phishing" if probability >= 0.5 else "legitimate",
        "phishing_probability": probability,
    }


def _top_features(n: int = 10) -> list[dict]:
    pairs = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_), key=lambda p: p[1], reverse=True
    )
    return [{"feature": f, "importance": float(i)} for f, i in pairs[:n]]


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/model-info")
def model_info():
    return {
        "model_type": type(model).__name__,
        "n_estimators": model.n_estimators,
        "max_depth": model.max_depth,
        "feature_count": len(FEATURE_COLUMNS),
        "top_features": _top_features(),
    }


@app.post("/api/predict")
def predict_url(req: UrlRequest):
    overrides = req.overrides.model_dump() if req.overrides else None
    try:
        extracted = extract_features(req.url, req.fetch_page, overrides)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not analyse URL: {exc}")
    return {**_predict(extracted["features"]), **extracted}


@app.post("/api/predict/features")
def predict_features(req: FeatureRequest):
    unknown = set(req.features) - set(FEATURE_COLUMNS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown features: {sorted(unknown)}")
    return _predict(req.features)


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND_DIR / "index.html")
