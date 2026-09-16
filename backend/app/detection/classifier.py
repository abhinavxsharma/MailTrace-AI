"""
MAILTRACE AI - Threat Detection Model Inference.
Integrates the fine-tuned Dataset 3 DistilBERT model (ml/models/dataset3_v1.0.0)
for sequence classification (BENIGN vs MALICIOUS).
"""

import logging
import re       
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.schemas.detection import DetectionSchema, DetectionSignal

logger = logging.getLogger(__name__)


def resolve_model_path(path_str: Optional[str] = None) -> Path:
    """
    Resolve model path relative to project root or absolute path.
    """
    target = path_str or settings.MODEL_PATH
    p = Path(target)
    if p.is_absolute() and p.exists():
        return p

    # Check relative to current working directory
    if p.exists():
        return p.resolve()

    # Check relative to project root (e.g., E:\MailTrace-AI)
    # backend/app/detection/classifier.py -> 3 levels up to backend, 4 to root
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = project_root / target
    if candidate.exists():
        return candidate.resolve()

    return p.resolve()


def strip_html_tags(html_content: str) -> str:
    """
    Extract readable plain text from HTML content.
    """
    if not html_content:
        return ""
    # Strip script/style blocks
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_content, flags=re.DOTALL | re.IGNORECASE)
    # Strip remaining HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Normalize whitespace
    return " ".join(text.split())


class ThreatClassifier:
    """
    Thread-safe singleton inference wrapper for MAILTRACE AI Dataset 3
    DistilBertForSequenceClassification model.
    """

    _instance: Optional["ThreatClassifier"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = resolve_model_path(model_path)
        self.max_length = settings.MODEL_MAX_LENGTH
        self.tokenizer = None
        self.model = None
        self.device = "cpu"
        self.model_name = "dataset3_v1.0.0"
        self.is_loaded = False
        self._load_error: Optional[str] = None

    @classmethod
    def get_instance(cls, model_path: Optional[str] = None) -> "ThreatClassifier":
        """Get or initialize singleton instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(model_path)
            return cls._instance

    def load_model(self) -> bool:
        """
        Load tokenizer and model weights into memory.
        Returns True if successful, False otherwise.
        """
        if self.is_loaded:
            return True

        with self._lock:
            if self.is_loaded:
                return True

            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                if not self.model_path.exists():
                    self._load_error = f"Model path not found: {self.model_path}"
                    logger.warning(self._load_error)
                    return False

                # Ensure required files exist
                config_file = self.model_path / "config.json"
                weights_file = self.model_path / "model.safetensors"
                if not config_file.exists() or not weights_file.exists():
                    self._load_error = f"Missing model files in {self.model_path}"
                    logger.warning(self._load_error)
                    return False

                logger.info(f"Loading threat detection model from {self.model_path}")
                self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
                self.model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))

                # Use CUDA if available, otherwise CPU
                if torch.cuda.is_available():
                    self.device = "cuda"
                else:
                    self.device = "cpu"

                self.model.to(self.device)
                self.model.eval()
                self.is_loaded = True
                self._load_error = None
                logger.info(f"Model successfully loaded on {self.device}")
                return True

            except Exception as e:
                self._load_error = str(e)
                logger.error(f"Failed to load threat detection model: {e}", exc_info=True)
                return False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Run inference on raw text.
        Returns a dict with threat_score, label, confidence, and probabilities.
        """
        clean_text = (text or "").strip()
        if not clean_text:
            return {
                "model": self.model_name,
                "label": "BENIGN",
                "threat_score": 0.0,
                "confidence": 1.0,
                "probabilities": {"BENIGN": 1.0, "MALICIOUS": 0.0},
                "status": "EMPTY_INPUT",
            }

        if not self.load_model():
            return {
                "model": f"{self.model_name} (unavailable)",
                "label": "UNKNOWN",
                "threat_score": None,
                "confidence": None,
                "probabilities": {},
                "status": "MODEL_UNAVAILABLE",
                "error": self._load_error,
            }

        try:
            import torch
            import torch.nn.functional as F

            inputs = self.tokenizer(
                clean_text,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = F.softmax(outputs.logits, dim=1)[0].tolist()

            # id2label mapping: 0 -> BENIGN, 1 -> MALICIOUS
            id2label = getattr(self.model.config, "id2label", {0: "BENIGN", 1: "MALICIOUS"})
            benign_prob = float(probs[0])
            malicious_prob = float(probs[1])

            predicted_label = "MALICIOUS" if malicious_prob >= 0.5 else "BENIGN"
            confidence = max(benign_prob, malicious_prob)

            return {
                "model": self.model_name,
                "label": predicted_label,
                "threat_score": round(malicious_prob, 4),
                "confidence": round(confidence, 4),
                "probabilities": {
                    "BENIGN": round(benign_prob, 4),
                    "MALICIOUS": round(malicious_prob, 4),
                },
                "status": "SUCCESS",
            }

        except Exception as e:
            logger.error(f"Inference error: {e}", exc_info=True)
            return {
                "model": self.model_name,
                "label": "UNKNOWN",
                "threat_score": None,
                "confidence": None,
                "probabilities": {},
                "status": "INFERENCE_ERROR",
                "error": str(e),
            }

    def classify_email(
        self,
        subject: Optional[str] = None,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
    ) -> DetectionSchema:
        """
        Classify email content and return canonical DetectionSchema.
        """
        subj = (subject or "").strip()
        body = (body_text or "").strip()
        if not body and body_html:
            body = strip_html_tags(body_html)

        # Prepare model input according to training spec: "email text and subject only"
        if subj and body:
            full_text = f"Subject: {subj}\n\n{body}"
        elif subj:
            full_text = f"Subject: {subj}"
        elif body:
            full_text = body
        else:
            full_text = ""

        pred = self.predict(full_text)

        threat_score = pred.get("threat_score")
        signals: List[DetectionSignal] = []

        if threat_score is not None:
            if threat_score >= 0.85:
                signals.append(
                    DetectionSignal(
                        name="Transformer Threat Detection",
                        contribution=f"+{int(threat_score * 25)}",
                        description=f"DistilBERT fine-tuned model classified email as MALICIOUS with {threat_score:.1%} confidence",
                    )
                )
            elif threat_score >= 0.50:
                signals.append(
                    DetectionSignal(
                        name="Suspicious Semantic Patterns",
                        contribution=f"+{int(threat_score * 15)}",
                        description=f"Semantic analysis detected suspicious phrasing with {threat_score:.1%} probability",
                    )
                )

            return DetectionSchema(
                model=pred.get("model", self.model_name),
                ai_threat_score=threat_score,
                phishing_score=threat_score,
                bec_score=threat_score if threat_score > 0.5 else 0.0,
                semantic_score=threat_score,
                signals=signals,
            )
        else:
            status_desc = pred.get("error") or "Model unavailable"
            signals.append(
                DetectionSignal(
                    name="Model Status",
                    contribution="0",
                    description=f"Transformer inference status: {pred.get('status', 'UNAVAILABLE')} ({status_desc})",
                )
            )
            return DetectionSchema(
                model=pred.get("model", f"{self.model_name} (unavailable)"),
                ai_threat_score=None,
                phishing_score=None,
                bec_score=None,
                semantic_score=None,
                signals=signals,
            )


def get_classifier(model_path: Optional[str] = None) -> ThreatClassifier:
    """Helper to access singleton ThreatClassifier."""
    return ThreatClassifier.get_instance(model_path)
