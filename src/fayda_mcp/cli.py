"""Command-line interface for Fayda MCP.

Provides commands for schema migrations, configuration verification,
and launching MCP servers with stdio or HTTP transports.
"""

import argparse
import asyncio
import os
import sys
from typing import List, Optional


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
            # Fallback simple parser if python-dotenv is not installed
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v


def handle_migrate(args: argparse.Namespace) -> int:
    """Handle database migration command."""
    load_env_if_requested(args.env_file)

    db_url = args.database_url
    if not db_url and args.database_url_env:
        db_url = os.environ.get(args.database_url_env)

    if not db_url:
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

    if not db_url:
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
        cfg = FaydaConfig.from_env()
        has_key = bool(cfg.signing_key or cfg.signing_key_path)
        print("Configuration validated successfully:")
        print(f"  Client ID: {cfg.client_id}")
        print(f"  Redirect URI: {cfg.redirect_uri}")
        print(f"  Authorization Endpoint: {cfg.authorization_endpoint}")
        print(f"  Token Endpoint: {cfg.token_endpoint}")
        print(f"  Userinfo Endpoint: {cfg.userinfo_endpoint}")
        print(f"  Key configured: {'Yes (redacted)' if has_key else 'No'}")
        return 0
    except Exception as e:
        sys.stderr.write(f"Configuration error: {e}\n")
        return 1


def handle_run(args: argparse.Namespace) -> int:
    """Launch Fayda MCP server."""
    load_env_if_requested(args.env_file)
    transport = getattr(args, "transport", "stdio") or "stdio"

    from fayda_mcp.config import FaydaConfig
    from fayda_mcp.mcp.factory import create_mcp_server
    from fayda_mcp.service import FaydaVerificationService
    from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

    cfg = FaydaConfig.from_env()
    service = FaydaVerificationService(
        config=cfg,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )
    server = create_mcp_server(service=service)

    if transport == "stdio":
        # Under stdio transport, stdout is reserved strictly for MCP JSON-RPC protocol
        server.run(transport="stdio")
        return 0
    elif transport == "http":
        host = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
        port = getattr(args, "port", 3000) or 3000
        server.run(transport="sse", host=host, port=port)
        return 0
    else:
        sys.stderr.write(f"Unknown transport: {transport}\n")
        return 1


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

    # run
    run_p = subparsers.add_parser("run", help="Run the Fayda MCP server")
    run_p.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol (stdio or http)",
    )
    run_p.add_argument("--host", default="127.0.0.1", help="Host interface for HTTP transport")
    run_p.add_argument("--port", type=int, default=3000, help="Port for HTTP transport")
    run_p.add_argument("--env-file", help="Path to .env file to load")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for fayda-mcp console script."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "migrate":
        return handle_migrate(args)
    elif args.subcommand == "cleanup":
        return handle_cleanup(args)
    elif args.subcommand == "check-config":
        return handle_check_config(args)
    elif args.subcommand == "run":
        return handle_run(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
