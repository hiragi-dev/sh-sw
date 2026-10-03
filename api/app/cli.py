"""管理 API トークンの発行・一覧・失効。

    docker compose exec api shsw-token create <name>
    docker compose exec api shsw-token list
    docker compose exec api shsw-token revoke <id>
"""
import argparse
import sys

from . import auth, db
from .policy import now


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shsw-token", description="shsw 管理 API トークンの管理")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="トークンを発行する(値は一度だけ表示)")
    c.add_argument("name", help="用途を示す名前 (例: web-frontend)")
    c.add_argument("--quiet", "-q", action="store_true", help="トークン値のみ出力する")
    sub.add_parser("list", help="トークン一覧")
    r = sub.add_parser("revoke", help="トークンを失効させる")
    r.add_argument("id", type=int)
    args = parser.parse_args(argv)

    db.init()

    if args.cmd == "create":
        tid, token = auth.create_token(args.name)
        if args.quiet:
            print(token)
        else:
            print(f"created token #{tid} ({args.name})")
            print()
            print(f"  {token}")
            print()
            print("この値は再表示できません。フロントエンドの SHSW_BACKEND_TOKEN に設定してください。")
        return 0

    if args.cmd == "list":
        rows = db.query("SELECT * FROM api_tokens ORDER BY id")
        if not rows:
            print("(no tokens)")
            return 0
        print(f"{'ID':>4}  {'NAME':<20} {'HINT':<18} {'STATUS':<8} {'CREATED':<26} LAST USED")
        for t in rows:
            status = "revoked" if t["revoked_at"] else "active"
            last = f"{t['last_used_at']} ({t['last_used_from']})" if t["last_used_at"] else "-"
            print(f"{t['id']:>4}  {t['name']:<20} {t['hint']:<18} {status:<8} {t['created_at']:<26} {last}")
        return 0

    if args.cmd == "revoke":
        row = db.query_one("SELECT * FROM api_tokens WHERE id = ?", (args.id,))
        if not row:
            print(f"token #{args.id} not found", file=sys.stderr)
            return 1
        db.execute("UPDATE api_tokens SET revoked_at = ? WHERE id = ?", (now().isoformat(), args.id))
        print(f"revoked token #{args.id} ({row['name']})")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
