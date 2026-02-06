"""CLI for MCP Gateway operations."""

from __future__ import annotations

import sys

import sqlite_utils

from . import ai_council, registry, scanner


def serve(host: str = "127.0.0.1", port: int = 8000):
    """
    Start the MCP Gateway server.

    Args:
        host: Host to bind to (default: 127.0.0.1 for security)
        port: Port to bind to (default: 8000)
    """
    import uvicorn

    from .gateway import app

    print(f"Starting MCP Gateway on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


def scan(
    server: str,
    db_path: str = "data/mcp_gateway.db",
    origin_url: str | None = None,
    origin_sha: str | None = None,
):
    """
    Run scans on a server.

    Args:
        server: Server ID or URL
        db_path: Path to database
        origin_url: GitHub repo URL (https://github.com/org/repo)
        origin_sha: Git commit SHA
    """
    db = sqlite_utils.Database(db_path)
    if origin_url or origin_sha:
        if not origin_url or not origin_sha:
            print("Error: origin_url and origin_sha must be provided together")
            sys.exit(1)

    # Try to parse as ID first, otherwise as URL
    try:
        server_id = int(server)
        if origin_url and origin_sha:
            server_row = registry.get_server(db, server_id)
            if not server_row:
                print("Error: server_id not found")
                sys.exit(1)
            registry.upsert_server(
                db,
                server_row["name"],
                server_row["base_url"],
                server_row["status"],
                origin_url=origin_url,
                origin_sha=origin_sha,
            )
    except ValueError:
        if not origin_url or not origin_sha:
            print("Error: origin_url and origin_sha are required when registering by URL")
            sys.exit(1)
        # Assume it's a URL, create server entry
        server_id = registry.upsert_server(
            db,
            server,
            server,
            "pending_scan",
            origin_url=origin_url,
            origin_sha=origin_sha,
        )
        print(f"Created server entry with ID: {server_id}")

    print(f"Running scans on server {server_id}...")
    result = scanner.run_scan(db, server_id, scan_types=["static", "mcpsafety"])

    print(f"Scan completed. Run ID: {result['run_id']}")
    print(f"Results: {result['results']}")


def council(server_id: int, db_path: str = "data/mcp_gateway.db"):
    """
    Run AI Council evaluation on a server.

    Args:
        server_id: Server ID
        db_path: Path to database
    """
    db = sqlite_utils.Database(db_path)

    print(f"Running council evaluation on server {server_id}...")
    result = ai_council.evaluate(db, server_id)

    print(f"Evaluation completed. Run ID: {result['run_id']}")
    print(f"Decision: {result['decision']}")
    print(f"Scores: {result['scores']}")
    print(f"Rationale: {result['rationale']}")


def tune(db_path: str = "data/mcp_gateway.db"):
    """
    Run self-tuning weight adjustment.

    Args:
        db_path: Path to database
    """
    from . import self_tuning

    print("Running self-tuning analysis...")
    result = self_tuning.run_self_tuning(db_path)

    print(f"Self-tuning complete. Run ID: {result['run_id']}")
    print(f"Previous weights: {result['previous_weights']}")
    print(f"New weights: {result['new_weights']}")
    print(f"Metrics: {result['metrics']}")


def _parse_db_path(args: list[str]) -> tuple[list[str], str]:
    db_path = "data/mcp_gateway.db"
    if "--db-path" in args:
        idx = args.index("--db-path")
        if idx + 1 >= len(args):
            print("Error: --db-path requires a value")
            sys.exit(1)
        db_path = args[idx + 1]
        args = args[:idx] + args[idx + 2 :]
    return args, db_path


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python -m mcp_gateway.cli <command> [args]")
        print("Commands:")
        print("  serve              - Start gateway server")
        print("  scan <server> [origin_url origin_sha] [--db-path <path>] - Run scans on server")
        print("  council <server_id> - Run council evaluation")
        print("  tune               - Run self-tuning weight adjustment")
        sys.exit(1)

    command = sys.argv[1]

    if command == "serve":
        serve()
    elif command == "scan":
        if len(sys.argv) < 3:
            print(
                "Usage: python -m mcp_gateway.cli scan <server_id_or_url> "
                "[origin_url origin_sha] [--db-path <path>]"
            )
            sys.exit(1)
        args, db_path = _parse_db_path(sys.argv[2:])
        if not args:
            print(
                "Usage: python -m mcp_gateway.cli scan <server_id_or_url> "
                "[origin_url origin_sha] [--db-path <path>]"
            )
            sys.exit(1)
        if len(args) > 3:
            print("Error: too many arguments for scan")
            print(
                "Usage: python -m mcp_gateway.cli scan <server_id_or_url> "
                "[origin_url origin_sha] [--db-path <path>]"
            )
            sys.exit(1)
        origin_url = args[1] if len(args) > 1 else None
        origin_sha = args[2] if len(args) > 2 else None
        scan(args[0], db_path=db_path, origin_url=origin_url, origin_sha=origin_sha)
    elif command == "council":
        if len(sys.argv) < 3:
            print("Usage: python -m mcp_gateway.cli council <server_id>")
            sys.exit(1)
        try:
            server_id = int(sys.argv[2])
        except ValueError:
            print("Error: server_id must be an integer")
            sys.exit(1)
        council(server_id)
    elif command == "tune":
        tune()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
