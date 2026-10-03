# shsw-backend

URL / パス単位でアクセスを遮断する MITM プロキシと、その管理 API。

- **プロキシ**: 公式 [mitmproxy](https://mitmproxy.org/) 12 (`mitmdump`) + 独自 addon (`proxy/shsw_blocker.py`)
- **管理 API**: FastAPI + SQLite (`api/`)
- **管理 UI**: 別リポジトリ [shsw-frontend](../frontend)(トークンでこの API に接続)

```
                    ┌───────────────────── shsw-backend (docker compose) ────────────────────┐
 端末 ── HTTP(S) ──▶│ proxy :8080  mitmdump + shsw_blocker.py                                │──▶ Internet
 (プロキシ設定)     │     │ 2 秒ごとに /internal/sync (ルール取得・ブロックログ送信)         │
                    │     ▼                                                                   │
 shsw-frontend ────▶│ api   :8000  FastAPI ── SQLite (/data)  CA (/certs = mitmproxy confdir) │
 外部トリガー ─────▶│              Bearer トークン認証 / トリガーはトリガー毎のトークン       │
                    └─────────────────────────────────────────────────────────────────────────┘
```

## 特長

- **ポリシー**: ホスト(`*` ワイルドカード・サブドメイン含む/含まない)+ パス(前方一致 or glob)の組み合わせ。遮断 (block) と例外許可 (allow、遮断より優先)。
- **時間帯制御**: 曜日 + 開始/終了時刻の複数ウィンドウ。「時間帯内のみ有効」「時間帯外のみ有効」「常時」。日付またぎ (22:00〜06:00) 対応。
- **API トリガー**: `POST /api/hooks/{id}` で有効化 / 停止 / トグル / スケジュールに戻す。継続時間 (N 分後に自動でスケジュールへ復帰) 指定可。
- **手動上書き**: UI から即時に有効化・停止(期限付き/無期限)。
- **タイムパス**: 普段はロック(遮断)し、API から **指定秒数だけ** 解除する独立機能(例: YouTube Shorts を 5 分だけ見る)。1 回の最大秒数・1 日の合計上限つき。解除期限はプロキシがリクエスト毎に判定するため秒単位で正確に失効する。
- **証明書**: ルート CA の自動生成・再発行(プロキシ自動再起動)・配布 (pem / der / p12)、同じ CA で署名したサーバ証明書の発行。
- **性能・安定性**:
  - 遮断ポリシーに登録されたホスト **だけ** TLS を復号し、それ以外は TCP のまま素通し(`ignore_connection`)。CA 未導入の端末や証明書ピンニングのアプリも、対象外ホストなら影響を受けません。
  - ルール判定はプロキシ内のメモリ上で完結(API に問い合わせない)。API が停止しても最後のルール(ディスクにキャッシュ)で動作継続。
  - `connection_strategy=lazy`、`stream_large_bodies=1m`、ログ抑制、`nofile` 65535、ヘルスチェック + `restart: unless-stopped`。

## 必要環境

- Docker Engine 24+ / Docker Compose v2
- amd64 / arm64(Raspberry Pi 4/5 で動作確認済み)

## セットアップ

```bash
git clone <this repo> /opt/shsw/backend
cd /opt/shsw/backend

# .env 生成(内部トークンを乱数で作成、SHSW_PUBLIC_URL にこのホストの IP を設定)
./scripts/init-env.sh
vi .env   # 必要ならポート等を変更

docker compose up -d --build
docker compose ps        # api / proxy が healthy になることを確認
```

### フロントエンド用トークンの発行

管理 API はトークン必須です。バックエンドのコンテナ内 CLI で発行します(値は **一度だけ** 表示されます)。

```bash
docker compose exec api shsw-token create web-frontend
# created token #1 (web-frontend)
#
#   shsw_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#
# 値のみ出力 (スクリプト用)
docker compose exec -T api shsw-token create web-frontend -q

docker compose exec api shsw-token list        # 一覧 (最終利用日時・送信元付き)
docker compose exec api shsw-token revoke 1    # 失効
```

発行した値をフロントエンドの `SHSW_BACKEND_TOKEN` に設定します(frontend の README 参照)。
スクリプト等から直接 API を叩く場合も同じトークンを `Authorization: Bearer <token>` で送ります。
API 仕様は `http://<host>:8000/api/docs` (Swagger UI) で確認できます。

### 環境変数 (.env)

| 変数 | 既定値 | 説明 |
| --- | --- | --- |
| `SHSW_INTERNAL_TOKEN` | (必須) | プロキシ addon ↔ API の内部通信用。`init-env.sh` が生成 |
| `SHSW_PUBLIC_URL` | 空 | 外部から見た API の URL (例 `http://192.168.1.10:8000`)。UI にトリガー URL・CA 配布 URL として表示 |
| `API_BIND` / `API_PORT` | `0.0.0.0` / `8000` | 管理 API の公開アドレス / ポート |
| `PROXY_BIND` / `PROXY_PORT` | `0.0.0.0` / `8080` | MITM プロキシの公開アドレス / ポート |
| `PROXY_EXTRA_ARGS` | 空 | `mitmdump` への追加引数(例 `--set proxyauth=user:pass`) |
| `PROXY_LOG_LEVEL` | `warn` | mitmproxy のログレベル(`info` で接続ごとのログを出す) |
| `TZ` | `Asia/Tokyo` | スケジュール判定に使うタイムゾーン |

## 端末側の設定

1. 端末の HTTP / HTTPS プロキシを `<このホストの IP>:8080` に設定(OS 設定、PAC、ブラウザ設定など)。
2. ルート CA をインストール:
   - `http://<host>:8000/api/public/ca.pem`(`.crt` = DER、`.p12` も可)を開く、または
   - プロキシ経由で `http://mitm.it` を開く
   - OS ごとの手順は管理 UI の「証明書」ページに記載
3. 遮断対象の URL を開くと 403 のブロックページが表示されます。

> **補足**: mitmproxy は既定でプライベート IP 以外のクライアントを拒否します (`block_global`)。インターネットに公開する場合は必ず `PROXY_EXTRA_ARGS=--set proxyauth=user:pass` 等で認証を掛けてください。

## API トリガー

UI の「API トリガー」でトリガーを作成すると、ID とトークンが払い出されます。

```bash
# 登録済みの動作を実行
curl -X POST http://<host>:8000/api/hooks/1 -H 'X-Trigger-Token: <token>'

# 動作・継続時間をリクエストで上書き
curl -X POST http://<host>:8000/api/hooks/1 \
  -H 'X-Trigger-Token: <token>' -H 'Content-Type: application/json' \
  -d '{"action": "activate", "duration_minutes": 30}'
```

| action | 効果 |
| --- | --- |
| `activate` | 対象ポリシーを強制的に有効化(遮断開始) |
| `deactivate` | 強制的に停止(遮断解除) |
| `toggle` | 現在の状態を反転 |
| `reset` | 上書きを解除しスケジュールに戻す |

トークンは `X-Trigger-Token` ヘッダ / `Authorization: Bearer` / `?token=` クエリ / JSON の `token` のいずれかで渡せます(iOS ショートカットや IFTTT など、ヘッダを付けにくいクライアント向け)。
反映はプロキシの同期間隔 (既定 2 秒) 以内です。

## タイムパス

UI の「タイムパス」で対象 URL(例: ホスト `youtube.com` + パス `/shorts`)と、既定秒数・1 回の最大秒数・1 日の合計上限を設定します。
作成するとタイムパスごとのトークンが払い出されます。

```bash
# 60 秒だけ解除 (秒数を省略すると既定秒数)
curl -X POST http://<host>:8000/api/pass-hooks/1/unlock \
  -H 'X-Pass-Token: <token>' -H 'Content-Type: application/json' -d '{"seconds": 60}'

# 残り時間に 120 秒加算
curl -X POST http://<host>:8000/api/pass-hooks/1/unlock \
  -H 'X-Pass-Token: <token>' -H 'Content-Type: application/json' -d '{"seconds": 120, "extend": true}'

curl -X POST http://<host>:8000/api/pass-hooks/1/lock -H 'X-Pass-Token: <token>'   # 即ロック
curl http://<host>:8000/api/pass-hooks/1 -H 'X-Pass-Token: <token>'                # 状態 (残り秒数・今日の利用量)
```

- レスポンスの `granted_seconds` が実際に解除された秒数。最大秒数や 1 日の上限で切り詰めた場合は `truncated: true`、上限に達していれば HTTP 429。
- 1 日の利用量はローカル時刻 0 時でリセット。
- 反映: API → プロキシはロングポーリングで即時(実測 0.2 秒程度)。失効はプロキシ側で秒単位。
- アクセス制御ポリシーとは独立。同じ URL を遮断するポリシーが有効なら、解除中でも遮断されます(例外許可 allow ポリシーはタイムパスより優先)。
- 注意: `youtube.com/shorts` のようなパス遮断は、ページの読み込み・遷移で効きます。YouTube アプリ内部の API 通信や動画本体 (googlevideo.com) はパスで区別できないため、アプリ利用時の完全な遮断は保証しません。

## 優先順位

1. ポリシーが無効 → 何もしない
2. 手動 / トリガーによる上書き (期限内) → その状態
3. スケジュール (常時 / 時間帯内 / 時間帯外)

リクエストに対しては、**有効な allow ポリシーに一致すれば通過**、そうでなく有効な block ポリシーに一致すれば 403、どちらでもなくロック中のタイムパスに一致すれば 403(ロック中ページ)を返します。

## 常時起動の設定

コンテナは `restart: unless-stopped` で動いているため、プロセス異常終了時やホスト再起動時に Docker が自動で再起動します。ホスト起動時に確実に立ち上げるための手順:

```bash
# 1. Docker デーモンを OS 起動時に自動起動
sudo systemctl enable --now docker

# 2. 初回起動 (以降は restart ポリシーで自動復帰)
cd /opt/shsw/backend && docker compose up -d --build
```

`docker compose down` した後の起動や、compose の設定変更を起動時に確実に反映したい場合は systemd ユニットも登録します。

```bash
sudo cp deploy/shsw-backend.service /etc/systemd/system/
sudo vi /etc/systemd/system/shsw-backend.service   # WorkingDirectory を実際のパスに
sudo systemctl daemon-reload
sudo systemctl enable --now shsw-backend.service

systemctl status shsw-backend.service
```

運用上のポイント:

- **ヘルスチェック**: api は `/api/health`、proxy は 8080 番ポートへの接続で監視。`docker compose ps` で `healthy` を確認。
- **ログ**: json-file ドライバで 10MB × 5 世代にローテーション。`docker compose logs -f proxy api`。
- **CA 再発行時**: API が CA を書き換えると、プロキシ addon が変更を検知して自ら終了し、restart ポリシーで再起動して新しい CA を読み込みます(数秒間通信断)。
- **API 停止時**: プロキシは最後に取得したルールで動作を続けます(時間帯の切り替えは API 復帰後に反映)。
- **バックアップ**: 名前付きボリューム `shsw_shsw-data` (DB) と `shsw_shsw-certs` (CA 秘密鍵) を保存してください。

  ```bash
  docker run --rm -v shsw_shsw-data:/d -v shsw_shsw-certs:/c -v "$PWD":/b alpine \
    tar czf /b/shsw-backup-$(date +%F).tgz -C / d c
  ```

- **更新**: `git pull && docker compose up -d --build`

## トラブルシューティング

| 症状 | 確認事項 |
| --- | --- |
| UI で「プロキシ 応答なし」 | `docker compose logs proxy`。`SHSW_INTERNAL_TOKEN` が api と一致しているか |
| HTTPS で証明書エラー | 端末に現在の CA が入っているか(再発行後は入れ直しが必要)。UI の SHA-256 と端末の CA を比較 |
| 遮断されない | ポリシーが「遮断中」か。ブラウザが既存の接続を使い回している場合はタブを閉じるか数十秒待つ。QUIC (HTTP/3) はプロキシ設定時は使われません |
| ブロックログのクライアント IP が 172.x.x.x | Docker の NAT 経由のため。LAN の端末からのアクセスでは通常実 IP になります |
| フロントエンドが 401 | `docker compose exec api shsw-token list` で有効なトークンか確認 |

## 開発

```bash
cd api
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
SHSW_DB_PATH=./dev.db SHSW_CERT_DIR=./dev-certs SHSW_INTERNAL_TOKEN=dev uvicorn app.main:app --reload
python -m app.cli create dev    # 開発用トークン (SHSW_DB_PATH を合わせる)
```

## ディレクトリ

```
api/app/main.py      REST API
api/app/policy.py    有効判定(時間帯・上書き)とルールセット生成
api/app/certs.py     CA / サーバ証明書
api/app/auth.py      トークン認証
api/app/passes.py    タイムパス(解除・ロック・日次上限)
api/app/cli.py       shsw-token CLI
proxy/shsw_blocker.py  mitmproxy addon
deploy/              systemd ユニット
```
