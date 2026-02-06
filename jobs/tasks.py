"""RQ worker task functions for retest queue."""

from __future__ import annotations


def retest_server(server_id: int, reason: str) -> dict:
    """
    RQ task: Execute retest for MCP server.

    This function is executed by RQ workers. It runs scans and council evaluation
    for the specified server.

    Args:
        server_id: Server ID to retest
        reason: Retest reason (e.g., "quarantine_decision", "deny_decision")

    Returns:
        dict: Retest result with decision and scan status
    """
    from src.mcp_gateway import ai_council, registry, scanner

    # Initialize database
    db = registry.init_db("data/mcp_gateway.db")

    # Run scans (static + mcpsafety if available)
    scan_result = scanner.run_scan(db, server_id, scan_types=["static", "mcpsafety"])

    # Run council evaluation
    evaluation = ai_council.evaluate(db, server_id)

    return {
        "server_id": server_id,
        "decision": evaluation["decision"],
        "scan_status": scan_result.get("status"),
        "reason": reason,
        "completed_at": evaluation.get("evaluated_at"),
    }
