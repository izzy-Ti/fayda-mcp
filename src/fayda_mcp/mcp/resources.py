"""Read-only FastMCP resources exposing sanitized policy metadata and cached health."""

import json
from typing import Any, Dict, List, Optional
from fayda_mcp.predicates import DEFAULT_PREDICATE_REGISTRY
from fayda_mcp.service import FaydaVerificationService


def register_resources(
    server: Any,
    service: FaydaVerificationService,
) -> None:
    """Register read-only FastMCP resources onto the server.

    Registers:
        - fayda://policy/checks: Caller-visible policy checks metadata.
        - fayda://policy/purposes: Permitted business purposes and age constraints.
        - fayda://health: Sanitized cached readiness state (configured/ready/degraded).
    """

    @server.resource(
        "fayda://policy/checks",
        name="policy_checks",
        description="Filter caller-visible policy metadata for available verification checks",
        mime_type="application/json",
    )
    def get_policy_checks() -> str:
        """Return sanitized caller-visible metadata for supported checks."""
        policy = service.policy
        registry = policy.get_registry() if hasattr(policy, "get_registry") else DEFAULT_PREDICATE_REGISTRY

        # Build list of supported checks and their metadata
        optional_set = set(getattr(policy, "optional_checks", []))
        required_list = getattr(policy, "required_checks", None)

        checks_data: List[Dict[str, Any]] = []
        for name in registry.supported_checks():
            pred = registry.get(name)
            if pred:
                if required_list is not None:
                    def_req = "required" if name in required_list else "optional"
                else:
                    def_req = "optional" if name in optional_set else "required"

                checks_data.append(
                    {
                        "name": pred.name,
                        "description": pred.description,
                        "required_claims": sorted(pred.required_claims),
                        "required_scopes": sorted(pred.required_scopes),
                        "default_requirement": def_req,
                    }
                )

        payload = {
            "policy_version": getattr(policy, "version", "v1"),
            "checks": checks_data,
            "custom_age_thresholds": {
                "supported_syntaxes": ["age_over_<N>", "age_at_least(<N>)"],
                "minimum_allowed_age": getattr(policy, "min_age_threshold", 1),
                "maximum_allowed_age": getattr(policy, "max_age_threshold", 120),
            },
        }
        return json.dumps(payload, indent=2)

    @server.resource(
        "fayda://policy/purposes",
        name="policy_purposes",
        description="Filter caller-visible metadata for permitted verification purposes",
        mime_type="application/json",
    )
    def get_policy_purposes() -> str:
        """Return sanitized caller-visible metadata for permitted purposes."""
        policy = service.policy

        allowed_purposes = getattr(policy, "allowed_purposes", ["onboarding", "kyc"])
        purpose_thresholds = getattr(policy, "purpose_age_thresholds", {})

        purpose_details: Dict[str, Any] = {}
        for p in allowed_purposes:
            p_rule: Dict[str, Any] = {"allowed": True}
            if p in purpose_thresholds:
                thresh = purpose_thresholds[p]
                if isinstance(thresh, tuple):
                    p_rule["age_threshold_range"] = {"min": thresh[0], "max": thresh[1]}
                else:
                    p_rule["permitted_age_thresholds"] = list(thresh)
            else:
                p_rule["age_threshold_range"] = {
                    "min": getattr(policy, "min_age_threshold", 1),
                    "max": getattr(policy, "max_age_threshold", 120),
                }
            purpose_details[p] = p_rule

        payload = {
            "policy_version": getattr(policy, "version", "v1"),
            "allowed_purposes": sorted(allowed_purposes),
            "purpose_rules": purpose_details,
        }
        return json.dumps(payload, indent=2)

    @server.resource(
        "fayda://health",
        name="health",
        description="Sanitized cached readiness state reporting configured/ready/degraded",
        mime_type="application/json",
    )
    def get_health() -> str:
        """Return sanitized cached service readiness state.

        Never makes outbound network calls to production Fayda, triggers migrations,
        or initiates verification. Sanitizes all DSNs, keys, credentials, and PII.
        """
        cfg = service.config

        # Check configuration presence
        config_ok = bool(
            cfg.client_id
            and cfg.issuer
            and cfg.authorization_endpoint
            and cfg.token_endpoint
            and cfg.jwks_uri
        )

        # Check storage presence without network probes or migrations
        sessions_backend = service.sessions.__class__.__name__
        results_backend = service.results.__class__.__name__

        # Check key presence
        has_key = bool(cfg.signing_key or cfg.signing_key_path)

        # Evaluate status: ready, configured, or degraded
        if not config_ok or not service.sessions or not service.results:
            overall_status = "degraded"
        elif has_key:
            overall_status = "ready"
        else:
            overall_status = "configured"

        # Map backend to safe canonical names (no DSNs or hosts)
        def _safe_storage_name(cls_name: str) -> str:
            lower = cls_name.lower()
            if "redis" in lower:
                return "redis"
            if "postgres" in lower:
                return "postgres"
            if "memory" in lower:
                return "memory"
            return "custom"

        payload = {
            "status": overall_status,
            "readiness": {
                "configuration": "valid" if config_ok else "invalid",
                "sessions_storage": {
                    "status": "ready" if service.sessions else "degraded",
                    "type": _safe_storage_name(sessions_backend),
                },
                "results_storage": {
                    "status": "ready" if service.results else "degraded",
                    "type": _safe_storage_name(results_backend),
                },
                "signing_key": {
                    "configured": has_key,
                    "status": "configured" if has_key else "missing",
                    "note": "Secret presence does not prove credentials are approved or functional.",
                },
            },
            "policy": {
                "version": getattr(service.policy, "version", "v1"),
            },
            "disclaimer": "Secret presence does not prove credentials are approved or functional.",
            "operational_mode": "cached_readiness_only",
        }
        return json.dumps(payload, indent=2)
