"""Attack #1 — Phishing delivery (synthetic email, NOT a live send).

Produces one malicious email record with the header, URL-lexical, and
attachment features an L0 mail classifier will score in Phase 4. No email is
ever sent; this is a dataset entry standing in for the entry vector of the
kill chain (the credential-harvesting mail that gets an operator's workstation
compromised).

Target detection layer: L0 (mail) — gradient-boosted classifier over header /
URL / attachment features.
"""
from __future__ import annotations

from .common import AttackResult, register, cli_main


def phishing_sample() -> dict:
    """A single crafted phishing email as raw fields + engineered features."""
    url = "http://grid-ops-support.secure-login-verify.ru/auth/reset?id=ODtl9"
    raw = {
        "from_display": "IT Service Desk",
        "from_addr": "it-servicedesk@grid-ops-support.secure-login-verify.ru",
        # recipient / target workstation — the shared identity that lets Phase 6
        # correlation link this delivery to the endpoint + boundary stages.
        "to_addr": "j.rivera@grid-ops.example",
        "target_workstation": "eng-laptop-07",
        "target_host": "10.0.7.66",
        "reply_to": "helpdesk@mail-relay-33.ru",
        "subject": "URGENT: VPN certificate expires today — re-authenticate now",
        "body_preview": "Your SCADA VPN certificate expires in 2 hours. "
                        "Re-authenticate immediately to avoid losing remote access: " + url,
        "attachment_name": "VPN_Reauth_Tool.xlsm",
        "urls": [url],
    }
    # engineered features (what the classifier consumes)
    features = {
        "sender_domain_age_days": 4,          # freshly registered lookalike domain
        "reply_to_mismatch": True,            # reply-to domain != from domain
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
        "subject_has_urgency": True,          # "URGENT", "today", "immediately"
        "subject_len": len(raw["subject"]),
        "num_urls": 1,
        "url_len": len(url),
        "url_num_dots": url.count("."),
        "url_has_ip_literal": False,
        "url_has_at_symbol": False,
        "url_suspicious_tld": True,           # .ru on a "grid-ops-support" lure
        "url_num_subdomains": 3,
        "url_has_credential_words": True,     # login / verify / auth / reset
        "attachment_is_office": True,
        "attachment_has_macro": True,         # .xlsm macro-enabled
        "display_name_spoof": True,           # "IT Service Desk" vs .ru sender
    }
    return {"raw": raw, "features": features, "label": "phishing"}


@register("phishing", attack_class=1, title="Phishing delivery (synthetic email)", layer="L0 mail")
def run() -> AttackResult:
    sample = phishing_sample()
    f = sample["features"]
    return AttackResult(
        name="phishing",
        attack_class=1,
        title="Phishing delivery (synthetic email)",
        target_detection_layer="L0 mail (gradient-boosted classifier)",
        executed=True,
        changed=[
            "crafted a credential-harvesting email from a 4-day-old lookalike "
            "domain (grid-ops-support.secure-login-verify.ru)",
            "macro-enabled attachment 'VPN_Reauth_Tool.xlsm' (the payload dropper)",
            "no email actually sent — this is a dataset entry for the mail classifier",
        ],
        evidence={
            "from_addr": sample["raw"]["from_addr"],
            "reply_to_mismatch": f["reply_to_mismatch"],
            "spf_dkim_dmarc": [f["spf_pass"], f["dkim_pass"], f["dmarc_pass"]],
            "url_suspicious_tld": f["url_suspicious_tld"],
            "attachment_has_macro": f["attachment_has_macro"],
        },
        why_hard_to_catch=(
            "Individually, none of these fields is conclusive — plenty of real mail "
            "has urgency, or a macro, or a fresh domain. A single rule either misses "
            "this or floods on false positives. It takes a trained classifier over the "
            "joint header+URL+attachment feature vector to score it confidently, which "
            "is what L0 provides. There is also nothing on the SCADA wire yet, so no "
            "protocol/physics layer can see this stage at all."
        ),
        artifacts={"email_sample": sample},
    )


if __name__ == "__main__":
    raise SystemExit(cli_main(run))
