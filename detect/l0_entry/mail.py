"""L0 mail detector — gradient-boosted phishing classifier.

Feature-engineers a small *synthetic* phishing/benign email dataset (header,
URL-lexical and attachment features), trains a scikit-learn
GradientBoostingClassifier on it, and scores an email's feature vector. When the
phishing probability clears the alert threshold it emits a DetectionEvent.

The dataset is deliberately *overlapping* — some benign mail is urgent or carries
a macro, some phishing passes SPF — so the model learns a real decision boundary
over the joint feature vector rather than memorising one give-away rule. That is
the whole point of L0 vs a single hand-written filter (see attack #1's
`why_hard_to_catch`).
"""
from __future__ import annotations

import numpy as np

from ..events import DetectionEvent, STAGE_DELIVERY

# ordered feature schema — matches attacks.phishing.phishing_sample()["features"]
FEATURES = [
    "sender_domain_age_days", "reply_to_mismatch", "spf_pass", "dkim_pass",
    "dmarc_pass", "subject_has_urgency", "subject_len", "num_urls", "url_len",
    "url_num_dots", "url_has_ip_literal", "url_has_at_symbol", "url_suspicious_tld",
    "url_num_subdomains", "url_has_credential_words", "attachment_is_office",
    "attachment_has_macro", "display_name_spoof",
]


def vectorize(features: dict) -> np.ndarray:
    return np.array([float(features.get(k, 0)) for k in FEATURES], dtype=float)


def synthesize_dataset(n_per_class: int = 400, seed: int = 7):
    """Generate (X, y) with realistic, overlapping benign/phishing distributions."""
    rng = np.random.default_rng(seed)

    def benign():
        return {
            "sender_domain_age_days": rng.integers(200, 5000),
            "reply_to_mismatch": rng.random() < 0.05,
            "spf_pass": rng.random() < 0.95,
            "dkim_pass": rng.random() < 0.93,
            "dmarc_pass": rng.random() < 0.90,
            "subject_has_urgency": rng.random() < 0.15,      # some legit mail is urgent
            "subject_len": int(rng.normal(52, 15)),
            "num_urls": rng.integers(0, 4),
            "url_len": int(abs(rng.normal(40, 15))),
            "url_num_dots": rng.integers(1, 4),
            "url_has_ip_literal": rng.random() < 0.01,
            "url_has_at_symbol": rng.random() < 0.01,
            "url_suspicious_tld": rng.random() < 0.05,
            "url_num_subdomains": rng.integers(0, 2),
            "url_has_credential_words": rng.random() < 0.10,
            "attachment_is_office": rng.random() < 0.30,
            "attachment_has_macro": rng.random() < 0.04,     # some legit macro docs
            "display_name_spoof": rng.random() < 0.03,
        }

    def phishing():
        return {
            "sender_domain_age_days": rng.integers(1, 90),
            "reply_to_mismatch": rng.random() < 0.70,
            "spf_pass": rng.random() < 0.35,                 # some phishing passes SPF
            "dkim_pass": rng.random() < 0.30,
            "dmarc_pass": rng.random() < 0.25,
            "subject_has_urgency": rng.random() < 0.80,
            "subject_len": int(rng.normal(64, 20)),
            "num_urls": rng.integers(1, 6),
            "url_len": int(abs(rng.normal(85, 30))),
            "url_num_dots": rng.integers(3, 8),
            "url_has_ip_literal": rng.random() < 0.20,
            "url_has_at_symbol": rng.random() < 0.15,
            "url_suspicious_tld": rng.random() < 0.65,
            "url_num_subdomains": rng.integers(2, 6),
            "url_has_credential_words": rng.random() < 0.80,
            "attachment_is_office": rng.random() < 0.55,
            "attachment_has_macro": rng.random() < 0.60,
            "display_name_spoof": rng.random() < 0.65,
        }

    rows, labels = [], []
    for _ in range(n_per_class):
        rows.append(vectorize(benign())); labels.append(0)
        rows.append(vectorize(phishing())); labels.append(1)
    return np.array(rows), np.array(labels)


def benign_email_sample() -> dict:
    """A realistic *legitimate* email, for false-positive spot-checks."""
    return {
        "raw": {"from_addr": "notifications@grid-ops.example",
                "to_addr": "j.rivera@grid-ops.example", "target_workstation": "eng-laptop-07"},
        "features": {
            "sender_domain_age_days": 3200, "reply_to_mismatch": False, "spf_pass": True,
            "dkim_pass": True, "dmarc_pass": True, "subject_has_urgency": False,
            "subject_len": 44, "num_urls": 1, "url_len": 38, "url_num_dots": 2,
            "url_has_ip_literal": False, "url_has_at_symbol": False, "url_suspicious_tld": False,
            "url_num_subdomains": 1, "url_has_credential_words": False,
            "attachment_is_office": False, "attachment_has_macro": False, "display_name_spoof": False,
        },
        "label": "benign",
    }


class MailClassifier:
    def __init__(self, threshold: float = 0.6, seed: int = 7):
        from sklearn.ensemble import GradientBoostingClassifier
        self.threshold = threshold
        X, y = synthesize_dataset(seed=seed)
        self.model = GradientBoostingClassifier(random_state=seed, n_estimators=120,
                                                max_depth=3, learning_rate=0.1)
        self.model.fit(X, y)
        self._importance = dict(zip(FEATURES, self.model.feature_importances_))

    def score(self, features: dict) -> float:
        x = vectorize(features).reshape(1, -1)
        return float(self.model.predict_proba(x)[0, 1])

    def detect(self, email_sample: dict) -> DetectionEvent | None:
        """Score an email sample (as produced by attacks.phishing). Returns a
        DetectionEvent if it clears the threshold, else None."""
        features = email_sample.get("features", email_sample)
        raw = email_sample.get("raw", {})
        prob = self.score(features)
        if prob < self.threshold:
            return None

        # explainability: which risky features are present, weighted by importance
        risky = []
        for k in FEATURES:
            v = features.get(k)
            fires = (v is True) or (k == "sender_domain_age_days" and v is not None and v < 60) \
                or (k in ("url_num_dots", "url_num_subdomains") and isinstance(v, (int, float)) and v >= 3)
            if fires:
                risky.append((k, round(self._importance.get(k, 0.0), 3)))
        risky.sort(key=lambda t: t[1], reverse=True)
        top = [t for t in risky if t[1] > 0.005][:5] or risky[:3]

        sev = "high" if prob >= 0.85 else "medium"
        return DetectionEvent(
            detector="L0.mail.gbm",
            layer="L0",
            attack_stage=STAGE_DELIVERY,
            title=f"Phishing email flagged (p={prob:.2f})",
            reason=(f"GradientBoosting phishing classifier scored p={prob:.3f} "
                    f">= threshold {self.threshold:.2f}. Top contributing risk features: "
                    + ", ".join(f"{k}({w})" for k, w in top) + "."),
            confidence=round(prob, 3),
            severity=sev,
            entities={
                "email_from": raw.get("from_addr"),
                "recipient": raw.get("to_addr"),
                "workstation": raw.get("target_workstation"),
                "host": raw.get("target_host"),
            },
            evidence={
                "phish_probability": round(prob, 3),
                "threshold": self.threshold,
                "top_risk_features": top,
                "spf_dkim_dmarc": [features.get("spf_pass"), features.get("dkim_pass"),
                                   features.get("dmarc_pass")],
                "attachment_has_macro": features.get("attachment_has_macro"),
            },
            assets=[raw.get("target_workstation")] if raw.get("target_workstation") else [],
        )
