"""Trusted JWKS retrieval and key rotation cache with bounded refresh and single-flight lock."""

import asyncio
from dataclasses import dataclass
import logging
import random
import time
from typing import Any, Dict, Optional, Set, Tuple
import httpx
import jwt
from jwt import PyJWK
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import ProviderError, TokenValidationError

logger = logging.getLogger("fayda_mcp.oidc.jwks")


@dataclass
class JwksCacheEntry:
    """Cache entry for a specific (issuer, jwks_uri) key set."""

    issuer: str
    jwks_uri: str
    keys: Dict[str, Any]
    fetched_at: float
    refresh_at: float
    hard_expiry: float

    def is_fresh(self, now: float) -> bool:
        """True if current time is strictly before refresh_at."""
        return now < self.refresh_at

    def is_near_refresh(self, now: float) -> bool:
        """True if current time is within [refresh_at, hard_expiry)."""
        return self.refresh_at <= now < self.hard_expiry

    def is_hard_expired(self, now: float) -> bool:
        """True if current time is at or beyond hard_expiry."""
        return now >= self.hard_expiry


@dataclass
class BackoffState:
    """Backoff and error tracking for failed JWKS fetches per (issuer, jwks_uri)."""

    consecutive_failures: int = 0
    next_allowed_attempt: float = 0.0
    last_error: Optional[Exception] = None

    def record_failure(
        self,
        exc: Exception,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter_ratio: float = 0.2,
    ) -> None:
        self.consecutive_failures += 1
        self.last_error = exc
        delay = min(max_delay, base_delay * (2 ** (self.consecutive_failures - 1)))
        jitter = random.uniform(0, delay * jitter_ratio) if delay > 0 else 0.0
        self.next_allowed_attempt = time.time() + delay + jitter

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.next_allowed_attempt = 0.0
        self.last_error = None

    def is_backed_off(self, now: float) -> bool:
        return now < self.next_allowed_attempt


class JwksCache:
    """In-memory cache for provider public keys with bounded refresh, single-flight lock, and backoff."""

    def __init__(
        self,
        config: FaydaConfig,
        hard_expiry_factor: Optional[float] = None,
        refresh_factor: Optional[float] = None,
        jitter_ratio: Optional[float] = None,
        base_backoff_seconds: Optional[float] = None,
        max_backoff_seconds: Optional[float] = None,
        stale_grace_seconds: Optional[float] = None,
        unknown_kid_cooldown_seconds: Optional[float] = None,
        negative_cache_ttl_seconds: Optional[float] = None,
    ) -> None:
        self.config = config
        self.hard_expiry_factor = (
            hard_expiry_factor
            if hard_expiry_factor is not None
            else getattr(config, "jwks_hard_expiry_factor", 2.0)
        )
        self.refresh_factor = (
            refresh_factor
            if refresh_factor is not None
            else getattr(config, "jwks_refresh_factor", 0.8)
        )
        self.jitter_ratio = (
            jitter_ratio
            if jitter_ratio is not None
            else getattr(config, "jwks_jitter_ratio", 0.05)
        )
        self.base_backoff_seconds = (
            base_backoff_seconds
            if base_backoff_seconds is not None
            else getattr(config, "jwks_base_backoff_seconds", 1.0)
        )
        self.max_backoff_seconds = (
            max_backoff_seconds
            if max_backoff_seconds is not None
            else getattr(config, "jwks_max_backoff_seconds", 60.0)
        )
        self.stale_grace_seconds = (
            stale_grace_seconds
            if stale_grace_seconds is not None
            else getattr(config, "jwks_stale_grace_seconds", 0.0)
        )
        self.unknown_kid_cooldown_seconds = (
            unknown_kid_cooldown_seconds
            if unknown_kid_cooldown_seconds is not None
            else getattr(config, "jwks_unknown_kid_cooldown_seconds", 10.0)
        )
        self.negative_cache_ttl_seconds = (
            negative_cache_ttl_seconds
            if negative_cache_ttl_seconds is not None
            else getattr(config, "jwks_negative_cache_ttl_seconds", 30.0)
        )

        # Cache keyed by (issuer, jwks_uri)
        self._cache: Dict[Tuple[str, str], JwksCacheEntry] = {}
        self._inflight: Dict[Tuple[str, str], asyncio.Task[Dict[str, Any]]] = {}
        self._backoff: Dict[Tuple[str, str], BackoffState] = {}
        self._last_unknown_kid_refresh: Dict[Tuple[str, str], float] = {}
        self._negative_cache: Dict[Tuple[str, str, str], float] = {}
        self._max_negative_cache_entries: int = 1000

        self._lock = asyncio.Lock()
        self._background_tasks: Set[asyncio.Task[Any]] = set()

        # Backward compatibility attributes
        self._keys: Dict[str, Any] = {}
        self._last_fetched: float = 0.0

    def is_negatively_cached(
        self, issuer: str, jwks_uri: str, kid: str, now: float
    ) -> bool:
        """Check if kid is in the negative cache and not expired."""
        key = (issuer, jwks_uri, kid)
        recorded = self._negative_cache.get(key)
        if recorded is None:
            return False
        if (now - recorded) > self.negative_cache_ttl_seconds:
            self._negative_cache.pop(key, None)
            return False
        return True

    def record_negative_cache(
        self, issuer: str, jwks_uri: str, kid: str, now: float
    ) -> None:
        """Record an unknown kid in the negative cache with bounded capacity."""
        if len(self._negative_cache) >= self._max_negative_cache_entries:
            oldest_key = min(self._negative_cache, key=lambda k: self._negative_cache[k])
            self._negative_cache.pop(oldest_key, None)
        self._negative_cache[(issuer, jwks_uri, kid)] = now

    def add_key(
        self,
        kid: str,
        key: Any,
        issuer: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        fetched_at: Optional[float] = None,
        refresh_at: Optional[float] = None,
        hard_expiry: Optional[float] = None,
    ) -> None:
        """Manually register a trusted public key (for tests or local configurations)."""
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        cache_key = (target_issuer, target_uri)

        now = time.time()
        fa = fetched_at if fetched_at is not None else now
        ttl = float(self.config.jwks_cache_ttl_seconds)
        ra = refresh_at if refresh_at is not None else fa + (ttl * self.refresh_factor)
        he = hard_expiry if hard_expiry is not None else fa + (ttl * self.hard_expiry_factor)

        if cache_key in self._cache:
            entry = self._cache[cache_key]
            entry.keys[kid] = key
            if refresh_at is not None:
                entry.refresh_at = refresh_at
            if hard_expiry is not None:
                entry.hard_expiry = hard_expiry
            if fetched_at is not None:
                entry.fetched_at = fetched_at
        else:
            self._cache[cache_key] = JwksCacheEntry(
                issuer=target_issuer,
                jwks_uri=target_uri,
                keys={kid: key},
                fetched_at=fa,
                refresh_at=ra,
                hard_expiry=he,
            )

        self._keys[kid] = key
        self._last_fetched = fa

    def get_entry(
        self, issuer: Optional[str] = None, jwks_uri: Optional[str] = None
    ) -> Optional[JwksCacheEntry]:
        """Return the cached entry for (issuer, jwks_uri), if present."""
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        return self._cache.get((target_issuer, target_uri))

    def get_backoff_state(
        self, issuer: Optional[str] = None, jwks_uri: Optional[str] = None
    ) -> Optional[BackoffState]:
        """Return the current backoff state for (issuer, jwks_uri), if present."""
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        return self._backoff.get((target_issuer, target_uri))

    def is_refresh_in_flight(
        self, issuer: Optional[str] = None, jwks_uri: Optional[str] = None
    ) -> bool:
        """True if an async refresh job is currently in flight for (issuer, jwks_uri)."""
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        task = self._inflight.get((target_issuer, target_uri))
        return task is not None and not task.done()

    async def fetch_jwks(
        self,
        client: httpx.AsyncClient,
        issuer: Optional[str] = None,
        jwks_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch provider JWKS over HTTPS with bounded timeout, single-flight lock, and backoff."""
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        cache_key = (target_issuer, target_uri)

        task = await self._get_or_create_flight(
            cache_key=cache_key,
            issuer=target_issuer,
            jwks_uri=target_uri,
            client=client,
            is_background=False,
        )
        if task is None:
            raise ProviderError(f"JWKS provider {target_uri} is in backoff.")
        return await task

    async def _get_or_create_flight(
        self,
        cache_key: Tuple[str, str],
        issuer: str,
        jwks_uri: str,
        client: httpx.AsyncClient,
        is_background: bool = False,
    ) -> Optional[asyncio.Task[Dict[str, Any]]]:
        """Return existing in-flight task or create a single-flight task under lock."""
        async with self._lock:
            existing_task = self._inflight.get(cache_key)
            if existing_task is not None and not existing_task.done():
                return existing_task

            now = time.time()
            backoff = self._backoff.get(cache_key)
            if backoff and backoff.is_backed_off(now):
                if is_background:
                    return None
                raise ProviderError(
                    f"JWKS provider {jwks_uri} temporarily in backoff after failure: {backoff.last_error}"
                )

            task = asyncio.create_task(
                self._execute_fetch(cache_key, issuer, jwks_uri, client)
            )
            self._inflight[cache_key] = task
            if is_background:
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
            return task

    async def _execute_fetch(
        self,
        cache_key: Tuple[str, str],
        issuer: str,
        jwks_uri: str,
        client: httpx.AsyncClient,
    ) -> Dict[str, Any]:
        """Perform HTTP GET, atomically replace authoritative key set, and update backoff state."""
        timeout = httpx.Timeout(self.config.http_timeout_seconds)
        now = time.time()

        try:
            resp = await client.get(jwks_uri, timeout=timeout)
            resp.raise_for_status()
            jwks_data = resp.json()
        except Exception as exc:
            async with self._lock:
                backoff = self._backoff.setdefault(cache_key, BackoffState())
                backoff.record_failure(
                    exc=exc,
                    base_delay=self.base_backoff_seconds,
                    max_delay=self.max_backoff_seconds,
                )
            raise ProviderError(
                f"Failed to retrieve provider JWKS from {jwks_uri}: {exc}"
            ) from exc
        finally:
            async with self._lock:
                self._inflight.pop(cache_key, None)

        keys_dict: Dict[str, Any] = {}
        for k in jwks_data.get("keys", []):
            try:
                pyjwk = PyJWK.from_dict(k)
                kid = k.get("kid") or pyjwk.key_id
                if kid:
                    keys_dict[kid] = pyjwk.key
                else:
                    keys_dict["_default"] = pyjwk.key
            except Exception:
                continue

        ttl = float(self.config.jwks_cache_ttl_seconds)
        jitter_val = random.uniform(-self.jitter_ratio, self.jitter_ratio) * ttl
        refresh_at = now + (ttl * self.refresh_factor) + jitter_val
        hard_expiry = now + (ttl * self.hard_expiry_factor)

        if refresh_at >= hard_expiry:
            refresh_at = hard_expiry - 1.0
        if refresh_at <= now:
            refresh_at = now + 1.0

        entry = JwksCacheEntry(
            issuer=issuer,
            jwks_uri=jwks_uri,
            keys=keys_dict,
            fetched_at=now,
            refresh_at=refresh_at,
            hard_expiry=hard_expiry,
        )

        async with self._lock:
            # Atomically replace authoritative keys in cache
            self._cache[cache_key] = entry
            backoff = self._backoff.setdefault(cache_key, BackoffState())
            backoff.record_success()
            if cache_key == (self.config.issuer, self.config.jwks_uri):
                self._keys = dict(keys_dict)
                self._last_fetched = now

        return keys_dict

    async def get_signing_key_for_token(
        self,
        token_str: str,
        client: httpx.AsyncClient,
        issuer: Optional[str] = None,
        jwks_uri: Optional[str] = None,
    ) -> Any:
        """Extract header kid and resolve trusted signing key with bounded cache and single-flight lock."""
        try:
            header = jwt.get_unverified_header(token_str)
        except Exception as exc:
            raise TokenValidationError(f"Failed to read token header: {exc}") from exc

        # Security checks: Never fall back to unsigned decoding or token-supplied jku/x5u URLs
        alg = header.get("alg")
        if not alg or alg.lower() == "none":
            raise TokenValidationError("Unsigned JWT (alg=none) is strictly prohibited")

        # Explicitly enforce host configuration for key endpoints; ignore any token-supplied jku/x5u
        target_issuer = issuer or self.config.issuer
        target_uri = jwks_uri or self.config.jwks_uri
        cache_key = (target_issuer, target_uri)

        kid = header.get("kid")
        now = time.time()

        # Check negative cache for known absent kid
        if kid and self.is_negatively_cached(target_issuer, target_uri, kid, now):
            raise TokenValidationError(
                f"Provider key kid '{kid}' is in negative cache for {target_uri}"
            )

        entry = self._cache.get(cache_key)

        def find_key(keys: Dict[str, Any]) -> Optional[Any]:
            if kid and kid in keys:
                return keys[kid]
            if not kid and "_default" in keys:
                return keys["_default"]
            if not kid and len(keys) == 1:
                return next(iter(keys.values()))
            return None

        # Check legacy keys if entry is None
        if entry is None and self._keys:
            matched = find_key(self._keys)
            if matched:
                return matched

        # Case 1: Entry exists and has matching key
        if entry is not None:
            cached_key = find_key(entry.keys)
            if cached_key is not None:
                # Subcase 1a: Key is fresh (now < refresh_at)
                if entry.is_fresh(now):
                    return cached_key

                # Subcase 1b: Key is near-refresh (refresh_at <= now < hard_expiry)
                # "Near-refresh triggers one job. Concurrent known-kid validation uses cache."
                if entry.is_near_refresh(now):
                    await self._get_or_create_flight(
                        cache_key=cache_key,
                        issuer=target_issuer,
                        jwks_uri=target_uri,
                        client=client,
                        is_background=True,
                    )
                    return cached_key

                # Subcase 1c: Key is past hard expiry (now >= hard_expiry)
                # Requires refresh. If refresh fails, evaluate host stale-while-revalidate policy
                try:
                    new_keys = await self.fetch_jwks(client, target_issuer, target_uri)
                    entry = self._cache.get(cache_key)
                    resolved = find_key(entry.keys if entry else new_keys)
                    if resolved is not None:
                        return resolved
                    # Key was removed in refreshed authoritative set!
                    raise TokenValidationError(
                        f"Provider key kid '{kid}' was removed from trusted JWKS at {target_uri}"
                    )
                except TokenValidationError:
                    raise
                except Exception as exc:
                    # Stale-while-revalidate bounded host policy:
                    if (
                        self.stale_grace_seconds > 0.0
                        and now < (entry.hard_expiry + self.stale_grace_seconds)
                    ):
                        logger.warning(
                            "JWKS refresh failed (%s); permitting known key for kid '%s' within approved hard-stale window until %s",
                            exc,
                            kid,
                            entry.hard_expiry + self.stale_grace_seconds,
                        )
                        return cached_key
                    # Zero stale grace (or past grace window) -> FAIL CLOSED
                    raise ProviderError(
                        f"Keys past hard expiry at {target_uri} and refresh failed (zero stale grace): {exc}"
                    ) from exc

        # Case 2: Unknown kid or cache miss
        # If a single-flight fetch is ALREADY in flight for this cache_key, await it
        flight_task = self._inflight.get(cache_key)
        if flight_task is not None and not flight_task.done():
            try:
                new_keys = await flight_task
            except Exception as exc:
                if kid:
                    self.record_negative_cache(target_issuer, target_uri, kid, now)
                raise ProviderError(
                    f"Failed to refresh JWKS for unknown kid '{kid}' at {target_uri}: {exc}"
                ) from exc
            entry = self._cache.get(cache_key)
            resolved_key = find_key(entry.keys if entry else new_keys)
            if resolved_key is not None:
                if kid:
                    self._negative_cache.pop((target_issuer, target_uri, kid), None)
                return resolved_key
            if kid:
                self.record_negative_cache(target_issuer, target_uri, kid, now)
            raise TokenValidationError(
                f"Provider key kid '{kid}' not found in trusted JWKS at {target_uri} after refresh"
            )

        # Check cooldown to prevent unknown-kid floods from creating unbounded network calls
        last_unknown_refresh = self._last_unknown_kid_refresh.get(cache_key, 0.0)
        if (now - last_unknown_refresh) < self.unknown_kid_cooldown_seconds:
            if kid:
                self.record_negative_cache(target_issuer, target_uri, kid, now)
            raise TokenValidationError(
                f"Unknown kid '{kid}' rejected during provider refresh cooldown for {target_uri}"
            )

        # Perform one bounded synchronous refresh
        self._last_unknown_kid_refresh[cache_key] = now
        try:
            new_keys = await self.fetch_jwks(client, target_issuer, target_uri)
        except Exception as exc:
            if kid:
                self.record_negative_cache(target_issuer, target_uri, kid, now)
            raise ProviderError(
                f"Failed to refresh JWKS for unknown kid '{kid}' at {target_uri}: {exc}"
            ) from exc

        entry = self._cache.get(cache_key)
        resolved_key = find_key(entry.keys if entry else new_keys)
        if resolved_key is not None:
            if kid:
                self._negative_cache.pop((target_issuer, target_uri, kid), None)
            return resolved_key

        # Key remains absent after refresh -> negative cache and reject
        if kid:
            self.record_negative_cache(target_issuer, target_uri, kid, now)
        raise TokenValidationError(
            f"Provider key kid '{kid}' not found in trusted JWKS at {target_uri}"
        )
