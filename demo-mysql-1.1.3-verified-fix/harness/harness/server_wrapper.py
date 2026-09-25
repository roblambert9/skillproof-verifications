#!/usr/bin/env python3
"""Launch wrapper for awslabs.mysql-mcp-server under test (1.1.3).

The MCP server's credential plumbing calls AWS (RDS describe_db_instances
+ Secrets Manager) even for a direct wire-protocol connection. There is no
AWS on this machine, so two infrastructure shims substitute fixed test
credentials — exactly like the server's own is_test path, which returns
('test_user', 'test_password'):

  * server.internal_get_instance_properties -> fake instance properties
    (port taken from FAKE_MYSQL_PORT)
  * AsyncmyPoolConnection._get_credentials_from_secret -> test creds

These shims touch ONLY credential plumbing. The verification subject —
run_query's read-only gate (mutable_sql_detector) and injection filter —
is unmodified. All behavior under test executes the real shipped code.

Set ALLOW_WRITE_QUERY=1 to append --allow_write_query (write-mode pass).
"""
import os
import sys

PORT = int(os.environ.get("FAKE_MYSQL_PORT", "13306"))

from awslabs.mysql_mcp_server import server as srv  # noqa: E402
from awslabs.mysql_mcp_server.connection import asyncmy_pool_connection as apc  # noqa: E402


def _fake_instance_properties(db_endpoint, region):
    # 1.1.3 added fail-closed endpoint validation: the standalone-instance
    # path now requires instance_properties['Endpoint']['Address'] and
    # refuses to connect to a caller-supplied host when AWS returns none.
    # The shim supplies the fixture address as the "AWS-sourced" endpoint,
    # exactly as the old shim supplied the port.
    return {
        "MasterUsername": "test_user",
        "MasterUserSecret": {},
        "Endpoint": {"Address": "127.0.0.1", "Port": PORT},
    }


def _fake_credentials_from_secret(self, secret_arn, region, is_test=False):
    return ("test_user", "test_password")


srv.internal_get_instance_properties = _fake_instance_properties
apc.AsyncmyPoolConnection._get_credentials_from_secret = _fake_credentials_from_secret

if __name__ == "__main__":
    if os.environ.get("ALLOW_WRITE_QUERY") == "1":
        sys.argv.append("--allow_write_query")
    srv.main()
