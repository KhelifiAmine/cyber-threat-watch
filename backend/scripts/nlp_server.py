"""
NLP Model Server — loads TTPXHunter once, serves classification over HTTP.

Started as a background process inside the celery-worker container.
Spiders call this instead of loading the model per-subprocess.
"""

import os
import sys
import logging

# Add parent dir so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nlp-server")

app = FastAPI()

# Will be loaded on startup
_model = None
_tokenizer = None
_label_to_ttp = None
_ttp_to_name = None


class ClassifyRequest(BaseModel):
    title: str
    description: str = ""


class ClassifyResponse(BaseModel):
    is_relevant: bool
    ttp_codes: str
    ttps: list
    exploit_status: str
    products: list
    max_confidence: float


@app.on_event("startup")
def load_model():
    global _model, _tokenizer, _label_to_ttp, _ttp_to_name

    logger.info("Loading TTPXHunter model...")
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    import pickle

    _tokenizer = AutoTokenizer.from_pretrained("nanda-rani/TTPXHunter")
    _model = AutoModelForSequenceClassification.from_pretrained("nanda-rani/TTPXHunter")

    if torch.cuda.is_available():
        _model = _model.cuda()
        logger.info(f"Model loaded on GPU: {torch.cuda.get_device_name(0)}")
    else:
        logger.info("Model loaded on CPU")

    _model.eval()

    # Load label mappings
    from app.services.nlp_classifier import _download_label_files, LABEL_DICT_PATH, TTP_ID_NAME_PATH
    _download_label_files()

    if os.path.exists(LABEL_DICT_PATH):
        with open(LABEL_DICT_PATH, "rb") as f:
            label_dict = pickle.load(f)
        _label_to_ttp = {int(v): k for k, v in label_dict.items()}
        logger.info(f"Loaded {len(_label_to_ttp)} TTP label mappings")

    if os.path.exists(TTP_ID_NAME_PATH):
        with open(TTP_ID_NAME_PATH, "rb") as f:
            _ttp_to_name = pickle.load(f)
        logger.info(f"Loaded {len(_ttp_to_name)} TTP name mappings")

    logger.info("NLP server ready")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    import torch
    from app.services.nlp_classifier import (
        _split_sentences, detect_exploit_status, extract_products,
        TTP_CONFIDENCE_THRESHOLD,
    )

    full_text = f"{req.title}. {req.description}" if req.description else req.title

    # TTP extraction
    sentences = _split_sentences(full_text)
    ttps_found = []
    seen_ttp_ids = set()
    max_confidence = 0.0

    if sentences and _model is not None:
        device = next(_model.parameters()).device

        for sentence in sentences:
            try:
                inputs = _tokenizer(
                    sentence,
                    return_tensors="pt",
                    truncation=True,
                    max_length=256,
                    padding=True,
                )
                inputs = {k: v.to(device) for k, v in inputs.items()}

                with torch.no_grad():
                    outputs = _model(**inputs)

                probs = torch.softmax(outputs.logits, dim=-1)
                top_prob = probs.max().item()
                predicted_class = probs.argmax().item()

                if top_prob > max_confidence:
                    max_confidence = top_prob

                if top_prob >= TTP_CONFIDENCE_THRESHOLD:
                    ttp_id = ""
                    ttp_name = ""
                    if _label_to_ttp and predicted_class in _label_to_ttp:
                        ttp_id = _label_to_ttp[predicted_class]
                        if _ttp_to_name and ttp_id in _ttp_to_name:
                            ttp_name = _ttp_to_name[ttp_id]
                        else:
                            ttp_name = ttp_id

                    if ttp_id and ttp_id not in seen_ttp_ids:
                        seen_ttp_ids.add(ttp_id)
                        ttps_found.append({
                            "id": ttp_id,
                            "name": ttp_name,
                            "confidence": round(top_prob, 4),
                        })
            except Exception as e:
                logger.debug(f"Error classifying sentence: {e}")
                continue

    is_relevant = len(ttps_found) > 0 or max_confidence >= TTP_CONFIDENCE_THRESHOLD
    ttp_codes = ",".join(t["id"] for t in ttps_found)
    exploit_status = detect_exploit_status(full_text)
    products = extract_products(full_text)

    return ClassifyResponse(
        is_relevant=is_relevant,
        ttp_codes=ttp_codes,
        ttps=ttps_found,
        exploit_status=exploit_status,
        products=products,
        max_confidence=round(max_confidence, 4),
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5062, log_level="info")
