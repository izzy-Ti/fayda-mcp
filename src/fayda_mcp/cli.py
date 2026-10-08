"""Command-line interface for Fayda MCP.

Provides commands for schema migrations, configuration verification,
retention cleanup, diagnostic connectivity probes, and launching MCP servers
with stdio or combined HTTP transports.
"""

import argparse
import asyncio
import importlib
import os
import sys
from typing import Any, List, Optional, Tuple
import urllib.parse


def load_env_if_requested(env_file: Optional[str]) -> None:
    """Explicitly load environment variables from file if requested.

    Never silently loads .env without explicit request.
    Existing environment variables always win over file variables.
    """
    if env_file:
        if not os.path.exists(env_file):
            sys.stderr.write(f"Error: Environment file not found: {env_file}\n")
            sys.exit(1)
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=False)
        except ImportError:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v


def validate_port(port: int) -> int:
    """Validate that port number is within the valid TCP range 1-65535."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}. Port must be between 1 and 65535.")
    return port


def validate_callback_uri(uri: str) -> str:
    """Validate that callback URI is an absolute HTTP or HTTPS URL."""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"Invalid callback URI '{uri}'. Must be an absolute http or https URL."
        )
    return uri


def init_storage(
    storage_mode: str,
    redis_url: Optional[str] = None,
    database_url: Optional[str] = None,
) -> Tuple[Any, Any]:
    """Validate storage mode and initialize corresponding session and result stores."""
    mode = (storage_mode or "memory").lower()
    from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

    if mode == "memory":
        return MemorySessionStore(), MemoryResultRepository()

    elif mode == "redis":
        r_url = redis_url or os.environ.get("REDIS_URL")
        if not r_url:
            raise ValueError(
                "Redis storage mode requires --redis-url or REDIS_URL in environment."
            )
        try:
            from fayda_mcp.storage.redis import RedisSessionStore
            sessions = RedisSessionStore.from_url(r_url)
            return sessions, MemoryResultRepository()
        except ImportError as e:
            raise ImportError(f"Redis dependencies missing: {e}. Install with pip install 'fayda-mcp[redis]'")

    elif mode == "postgres":
        db_url = database_url or os.environ.get("DATABASE_URL")
        if not db_url:
            raise ValueError(
                "PostgreSQL storage mode requires --database-url or DATABASE_URL in environment."
            )
        try:
            from fayda_mcp.storage.postgres import PostgresResultRepository
            results = PostgresResultRepository.from_url(db_url)
            return MemorySessionStore(), results
        except ImportError as e:
            raise ImportError(f"PostgreSQL dependencies missing: {e}. Install with pip install 'fayda-mcp[postgres]'")

    elif mode in ("redis+postgres", "postgres+redis"):
        r_url = redis_url or os.environ.get("REDIS_URL")
        db_url = database_url or os.environ.get("DATABASE_URL")
        if not r_url:
            raise ValueError("Redis+Postgres mode requires --redis-url or REDIS_URL.")
        if not db_url:
            raise ValueError("Redis+Postgres mode requires --database-url or DATABASE_URL.")
        try:
            from fayda_mcp.storage.redis import RedisSessionStore
            from fayda_mcp.storage.postgres import PostgresResultRepository
            sessions = RedisSessionStore.from_url(r_url)
            results = PostgresResultRepository.from_url(db_url)
            return sessions, results
        except ImportError as e:
            raise ImportError(f"Storage dependencies missing: {e}. Install with pip install 'fayda-mcp[all]'")

    else:
        raise ValueError(
            f"Unsupported storage mode '{storage_mode}'. Choose from: memory, redis, postgres, redis+postgres."
        )


def init_caller_adapter(adapter_str: Optional[str]) -> Any:
    """Validate and instantiate host caller authorization adapter."""
    from fayda_mcp.context import SimpleCallerAdapter

    if not adapter_str or adapter_str == "default":
        return SimpleCallerAdapter()
    elif adapter_str == "strict":
        return SimpleCallerAdapter(enforce_scopes=True)
    elif ":" in adapter_str:
        module_path, class_name = adapter_str.split(":", 1)
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            return cls()
        except Exception as e:
            raise ValueError(
                f"Failed to load caller adapter '{adapter_str}': {e}"
            )
    else:
        raise ValueError(
            f"Invalid caller adapter specification '{adapter_str}'. Use 'default', 'strict', or 'module:Class'."
        )


def handle_migrate(args: argparse.Namespace) -> int:
    """Handle database migration command."""
    load_env_if_requested(args.env_file)

    db_url = args.database_url
    if not db_url and args.database_url_env:
        db_url = os.environ.get(args.database_url_env)

    if not db_url and not args.database_url_env:
        db_url = os.environ.get("DATABASE_MIGRATION_URL") or os.environ.get("DATABASE_URL")

    if not db_url:
        sys.stderr.write(
            "Error: Database URL must be provided via --database-url or --database-url-env "
            "(or DATABASE_MIGRATION_URL / DATABASE_URL in environment).\n"
        )
        return 1

    try:
        from fayda_mcp.migrations.runner import MigrationRunner
    except ImportError as e:
        sys.stderr.write(f"Error: PostgreSQL migration dependencies missing: {e}\n")
        return 1

    async def _run() -> int:
        async with MigrationRunner(db_url) as runner:
            if args.status:
                status = await runner.get_status()
                print(f"Current version: {status['current_version'] or 'None'}")
                print(f"Applied migrations: {status['applied']}")
                print(f"Pending migrations: {status['pending']}")
                return 0

            if args.rollback:
                steps = getattr(args, "steps", 1) or 1
                rolled = await runner.downgrade(steps=steps)
                if rolled:
                    print(f"Successfully rolled back {len(rolled)} migration(s): {', '.join(rolled)}")
                else:
                    print("No migrations available to roll back.")
                return 0

            applied = await runner.upgrade(target_version=args.target)
            if applied:
                print(f"Successfully applied {len(applied)} migration(s): {', '.join(applied)}")
            else:
                print("Database schema is already up to date.")
            return 0

    return asyncio.run(_run())


def handle_cleanup(args: argparse.Namespace) -> int:
    """Execute retention cleanup of expired verification requests and results."""
    load_env_if_requested(args.env_file)

    db_url = args.database_url
    if not db_url and args.database_url_env:
        db_url = os.environ.get(args.database_url_env)

    if not db_url and not args.database_url_env:
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("DATABASE_MIGRATION_URL")

    if not db_url:
        sys.stderr.write(
            "Error: Database URL must be provided via --database-url or --database-url-env "
            "(or DATABASE_URL in environment).\n"
        )
        return 1

    try:
        from fayda_mcp.storage.postgres import PostgresResultRepository
        from fayda_mcp.storage.retention import RetentionCleanupManager
    except ImportError as e:
        sys.stderr.write(f"Error: PostgreSQL dependencies missing: {e}\n")
        return 1

    async def _run() -> int:
        repo = PostgresResultRepository.from_url(db_url)
        manager = RetentionCleanupManager(repo)
        try:
            purged = await manager.run_once()
            print(f"Retention cleanup completed: {purged} expired record(s) purged.")
            return 0
        finally:
            await repo.close()

    return asyncio.run(_run())


def handle_check_config(args: argparse.Namespace) -> int:
    """Verify and print redacted Fayda MCP configuration."""
    load_env_if_requested(args.env_file)
    try:
        from fayda_mcp.config import FaydaConfig

        cfg = FaydaConfig.from_env(dotenv_path=args.env_file)

        # Validate callback URI override if provided
        if getattr(args, "callback_uri", None):
            validate_callback_uri(args.callback_uri)

        # Validate storage mode if specified
        storage_mode = getattr(args, "storage", "memory") or "memory"
        init_storage(
            storage_mode=storage_mode,
            redis_url=getattr(args, "redis_url", None),
            database_url=getattr(args, "database_url", None),
        )

        has_key = bool(cfg.signing_key or cfg.signing_key_path)

        # Output ONLY redacted, non-secret parameters
        print("Configuration validated successfully:")
        print(f"  Client ID: {cfg.client_id}")
        print(f"  Redirect URI: {cfg.redirect_uri}")
        print(f"  Authorization Endpoint: {cfg.authorization_endpoint}")
        print(f"  Token Endpoint: {cfg.token_endpoint}")
        print(f"  Userinfo Endpoint: {cfg.userinfo_endpoint}")
        print(f"  JWKS URI: {cfg.jwks_uri}")
        print(f"  Signing Key: {'Configured (redacted)' if has_key else 'Not configured'}")
        print(f"  Storage Mode: {storage_mode}")
        return 0
    except Exception as e:
        sys.stderr.write(f"Configuration error: {e}\n")
        return 1


def _run_coro(coro: Any) -> Any:
    """Run an async coroutine safely even if an event loop is already running."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def handle_diagnose(args: argparse.Namespace) -> int:
    """Run diagnostic checks against configuration, provider endpoints, and storage."""
    load_env_if_requested(args.env_file)
    timeout = getattr(args, "timeout", 5.0) or 5.0

    try:
        from fayda_mcp.config import FaydaConfig
        from fayda_mcp.diagnostics import run_diagnostics

        cfg = FaydaConfig.from_env(dotenv_path=args.env_file)

        report = _run_coro(run_diagnostics(config=cfg, timeout_seconds=timeout))
        print(f"Diagnostic Status: {report['status']}")
        for check_name, check_data in report.get("checks", {}).items():
            st = check_data.get("status", "unknown")
            print(f"  [{check_name}] status={st}")
        for note in report.get("notes", []):
            print(f"  Note: {note}")
        return 0 if report["status"] in ("ready", "configured") else 1
    except Exception as e:
        sys.stderr.write(f"Diagnostic error: {e}\n")
        return 1


def handle_run(args: argparse.Namespace) -> int:
    """Launch Fayda MCP server."""
    load_env_if_requested(args.env_file)
    transport = getattr(args, "transport", "stdio") or "stdio"

    try:
        from fayda_mcp.config import FaydaConfig
        from fayda_mcp.mcp.factory import create_mcp_server
        from fayda_mcp.service import FaydaVerificationService

        # 1. Validate transport
        if transport not in ("stdio", "http"):
            sys.stderr.write(f"Error: Unsupported transport '{transport}'. Choose 'stdio' or 'http'.\n")
            return 1

        # 2. Validate port and host
        port = validate_port(getattr(args, "port", 3000) or 3000)
        host = getattr(args, "host", "127.0.0.1") or "127.0.0.1"

        # 3. Load and validate configuration
        cfg = FaydaConfig.from_env(dotenv_path=args.env_file)
        callback_override = getattr(args, "callback_uri", None)
        if callback_override:
            validate_callback_uri(callback_override)
            cfg = cfg.model_copy(update={"redirect_uri": callback_override})
        else:
            validate_callback_uri(cfg.redirect_uri)

        # 4. Validate and initialize storage stores
        storage_mode = getattr(args, "storage", "memory") or "memory"
        sessions, results = init_storage(
            storage_mode=storage_mode,
            redis_url=getattr(args, "redis_url", None),
            database_url=getattr(args, "database_url", None),
        )

        # 5. Validate and initialize caller adapter
        caller_adapter = init_caller_adapter(getattr(args, "caller_adapter", None))

        service = FaydaVerificationService(
            config=cfg,
            sessions=sessions,
            results=results,
        )
        server = create_mcp_server(service=service, caller_adapter=caller_adapter)

        if transport == "stdio":
            # Under stdio transport, stdout is reserved strictly for MCP JSON-RPC protocol
            server.run(transport="stdio")
            return 0
        elif transport == "http":
            # Local combined HTTP mode: hosts MCP endpoint and registered callback using the same service instance
            try:
                from fayda_mcp.integrations.fastapi import create_fastapi_app
                import uvicorn

                # Configure host-owned session-binding route/hook, never a static production cookie
                def host_session_binding_hook(request: Any) -> Optional[str]:
                    binding = request.headers.get("x-session-binding")
                    if not binding and hasattr(request, "cookies"):
                        binding = request.cookies.get("fayda_session_binding")
                    return binding

                app = create_fastapi_app(
                    service=service,
                    session_binding_hook=host_session_binding_hook,
                    mcp_server=server,
                    mcp_path="/mcp",
                )

                uvicorn.run(app, host=host, port=port)
                return 0
            except ImportError:
                # Fallback to server SSE run if fastapi/uvicorn is not installed
                server.run(transport="sse", host=host, port=port)
                return 0

    except Exception as e:
        sys.stderr.write(f"Startup error: {e}\n")
        return 1

    return 0


def create_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="fayda-mcp",
        description="Fayda MCP: eSignet identity verification tools and CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # migrate
    migrate_p = subparsers.add_parser("migrate", help="Manage durable schema migrations")
    migrate_p.add_argument("--database-url", help="Database connection URL")
    migrate_p.add_argument(
        "--database-url-env",
        default="DATABASE_MIGRATION_URL",
        help="Environment variable name for database URL (default: DATABASE_MIGRATION_URL)",
    )
    migrate_p.add_argument("--env-file", help="Path to .env file to load before migrating")
    migrate_p.add_argument("--rollback", action="store_true", help="Roll back the last migration")
    migrate_p.add_argument("--steps", type=int, default=1, help="Number of migrations to roll back")
    migrate_p.add_argument("--target", help="Target migration version to upgrade up to")
    migrate_p.add_argument("--status", action="store_true", help="Display migration status")

    # cleanup
    cleanup_p = subparsers.add_parser("cleanup", help="Execute retention cleanup for expired records")
    cleanup_p.add_argument("--database-url", help="Database connection URL")
    cleanup_p.add_argument(
        "--database-url-env",
        default="DATABASE_URL",
        help="Environment variable name for database URL (default: DATABASE_URL)",
    )
    cleanup_p.add_argument("--env-file", help="Path to .env file to load")

    # check-config
    check_p = subparsers.add_parser("check-config", help="Verify and display redacted configuration")
    check_p.add_argument("--env-file", help="Path to .env file to load")
    check_p.add_argument(
        "--storage",
        choices=["memory", "redis", "postgres", "redis+postgres"],
        default="memory",
        help="Storage mode to validate (default: memory)",
    )
    check_p.add_argument("--redis-url", help="Redis connection URL")
    check_p.add_argument("--database-url", help="Database connection URL")
    check_p.add_argument("--callback-uri", help="Explicit developer callback URI to validate")

    # diagnose
    diag_p = subparsers.add_parser("diagnose", help="Execute diagnostic connectivity checks with timeouts")
    diag_p.add_argument("--timeout", type=float, default=5.0, help="HTTP connection timeout in seconds (default: 5.0)")
    diag_p.add_argument("--env-file", help="Path to .env file to load")

    # run
    run_p = subparsers.add_parser("run", help="Run the Fayda MCP server")
    run_p.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol: stdio or http (default: stdio)",
    )
    run_p.add_argument("--host", default="127.0.0.1", help="Host interface for HTTP transport (default: 127.0.0.1)")
    run_p.add_argument("--port", type=int, default=3000, help="Port for HTTP transport (default: 3000)")
    run_p.add_argument(
        "--storage",
        choices=["memory", "redis", "postgres", "redis+postgres"],
        default="memory",
        help="Session and result storage mode (default: memory)",
    )
    run_p.add_argument("--redis-url", help="Redis connection URL for redis storage mode")
    run_p.add_argument("--database-url", help="PostgreSQL connection URL for postgres storage mode")
    run_p.add_argument("--callback-uri", help="Explicit developer callback URI override")
    run_p.add_argument(
        "--caller-adapter",
        default="default",
        help="Host caller authorization adapter: default, strict, or module:Class",
    )
    run_p.add_argument("--env-file", help="Path to .env file to load")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for fayda-mcp console script."""
    parser = create_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "migrate":
        return handle_migrate(args)
    elif args.subcommand == "cleanup":
        return handle_cleanup(args)
    elif args.subcommand == "check-config":
        return handle_check_config(args)
    elif args.subcommand == "diagnose":
        return handle_diagnose(args)
    elif args.subcommand == "run":
        return handle_run(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
