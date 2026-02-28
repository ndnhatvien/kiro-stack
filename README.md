<div align="center">

# Kiro Stack

**Convert Kiro (Amazon Q Developer) accounts to OpenAI / Anthropic compatible API**

Based on secondary development of [kiro-gateway](https://github.com/jwadow/kiro-gateway) and [Kiro-Go](https://github.com/Quorinex/Kiro-Go)

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

</div>

---

## Why This Project?

The original projects each have their limitations:

| | [kiro-gateway](https://github.com/jwadow/kiro-gateway) | [Kiro-Go](https://github.com/Quorinex/Kiro-Go) |
|---|---|---|
| Web Admin Panel | ❌ No | ✅ Yes |
| Request Stability | ✅ Strong (multiple retries, dual-endpoint fallback) | ⚠️ Basic |
| Multi-Account Pool | ⚠️ Basic | ✅ Complete (rotation + weighted) |
| Auto Token Refresh | ✅ | ✅ |

**This project combines both:**
- **kiro-go** handles Web admin panel + account pool management
- **kiro-gateway** handles underlying API calls (retry, dual-endpoint fallback, error handling)
- kiro-go automatically forwards requests to kiro-gateway when `KIRO_GATEWAY_BASE` is detected

---

## Architecture

```
Client (Claude Code / Cursor / Cline ...)
        │
        ▼  :8088
   ┌─────────────┐
   │   kiro-go   │  Web admin panel + account pool + token refresh
   └──────┬──────┘
          │ (internal forwarding)
          ▼  :8001
   ┌──────────────────┐
   │   kiro-gateway   │  Stable proxy layer: dual-endpoint fallback + auto retry
   └──────┬───────────┘
          │
          ▼
      Kiro API (AWS CodeWhisperer / Amazon Q)
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Kiro account (free or paid)

### Three Steps to Launch

```bash
# 1. Clone repository
git clone https://github.com/your-username/kiro-stack.git
cd kiro-stack

# 2. Configure environment variables
cp .env.example .env
# Edit .env and modify these two items:
#   ADMIN_PASSWORD=your_admin_panel_password
#   INTERNAL_API_KEY=randomly_generated_key (for internal communication)

# 3. Start services
docker compose up -d
```

### Add Account and Use

1. Open `http://localhost:8088/admin`
2. Login with `ADMIN_PASSWORD`
3. Add Kiro account (supports AWS Builder ID / IAM SSO / SSO Token, etc.)
4. Set client base URL to `http://localhost:8088`

```bash
# OpenAI compatible
curl http://localhost:8088/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-sonnet-4.5", "messages": [{"role": "user", "content": "Hello"}]}'

# Anthropic compatible
curl http://localhost:8088/v1/messages \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-sonnet-4.5", "max_tokens": 1024, "messages": [{"role": "user", "content": "Hello"}]}'
```

> **Note:** Account credentials are managed by kiro-go and automatically forwarded to kiro-gateway on request. No need to configure tokens separately in gateway.

---

## Supported Models

Model availability depends on your Kiro subscription tier. Common models include:

| Model | Description |
|------|------|
| `claude-sonnet-4.6` | Latest flagship model (released February 2026) |
| `claude-opus-4.6` | Strongest reasoning model (released February 2026) |
| `claude-sonnet-4.5` | Balanced performance, suitable for programming, writing, and general tasks |
| `claude-haiku-4.5` | Ultra-fast response, suitable for simple tasks |
| `claude-sonnet-4` | Previous generation, stable and reliable |
| `claude-3.7-sonnet` | Legacy version, backward compatible |
| `deepseek-v3.2` | Open-source MoE (685B/37B active), balanced |
| `minimax-m2.1` | Open-source MoE (230B/10B active), suitable for complex tasks |
| `qwen3-coder-next` | Open-source MoE (80B/3B active), code-specialized |

Model names support multiple formats, such as `claude-sonnet-4.5` / `claude-sonnet-4-5` / `claude-sonnet-4-5-20250929` all parse correctly.

> **⚠️ About `claude-sonnet-4.6` / `claude-opus-4.6` Unavailability**
>
> These two models are currently in **limited beta rollout**. Kiro API returns HTTP 429 for unauthorized requests,
> using the same status code as regular "rate limiting", so you'll see `Streaming failed after 3 attempts` errors in logs.
>
> **This is not a code bug, but rather your Kiro account/Region hasn't been granted access to these models yet.**
>
> Troubleshooting steps:
> 1. First send a test request with `claude-sonnet-4.5`. If successful, both account and connection are working
> 2. Wait for AWS to grant your account access to 4.6 models (usually rolled out gradually with Kiro IDE version updates)
> 3. Once granted, no configuration changes needed - use directly

---

## Configuration

### Environment Variables (.env file)

All configuration is in the root `.env` file:

| Variable | Description | Required |
|------|------|------|
| `ADMIN_PASSWORD` | Web admin panel password | ✅ Yes |
| `INTERNAL_API_KEY` | Communication key between kiro-go and kiro-gateway | ✅ Yes |
| `VPN_PROXY_URL` | HTTP/SOCKS5 proxy (if network restricted) | ❌ No |
| `DEBUG_MODE` | Debug mode: `off` (default) / `errors` / `all` | ❌ No |

**Explanation:**
- `ADMIN_PASSWORD`: Used to login to Web admin panel
- `INTERNAL_API_KEY`: Internal authentication between two services, randomly generate (e.g., `openssl rand -hex 32`)
- `VPN_PROXY_URL`: If in China or network restricted, configure proxy address (e.g., `http://127.0.0.1:7890`)
- `DEBUG_MODE`: Recommended `off` for production, set to `errors` when troubleshooting

### Account Management

All Kiro accounts are added and managed through the Web admin panel:
1. Visit `http://localhost:8088/admin`
2. Login with `ADMIN_PASSWORD`
3. Click "Add Account", supports multiple methods:
   - AWS Builder ID (personal account)
   - IAM Identity Center (enterprise SSO)
   - SSO Token (import from browser)
   - Local cache (import from Kiro IDE)

**No need to configure tokens in kiro-gateway**. All account credentials are managed by kiro-go and automatically forwarded on request.

---

## Directory Structure

```
kiro-stack/
├── docker-compose.yml        # Integrated startup configuration
├── kiro-gateway/             # Python/FastAPI stable proxy layer
│   ├── kiro/                 # Core code
│   ├── requirements.txt
│   └── README.md
├── kiro-go/                  # Go Web admin panel + account pool
│   ├── proxy/                # Core proxy logic
│   ├── web/index.html        # Admin panel frontend
│   ├── data/
│   │   └── config.example.json  # Configuration template
│   └── README.md
└── scripts/
    └── sync_tokens.py        # Token sync script
```

---

## Changelog

### `feature/simplify-config-and-add-4.6-models`

**Configuration Simplification:**
- Integrated deployment only requires **one `.env` file in root directory**, no need to maintain separate `kiro-gateway/.env`
- Account credentials (Refresh Token, etc.) are fully managed through kiro-go Web admin panel. kiro-go automatically passes credentials via `X-Kiro-*` HTTP headers when forwarding requests to gateway
- Updated `kiro-gateway/.env.example` comments to clarify this file is only needed for standalone deployment

**New Model Support:**
- Added `claude-sonnet-4.6`, `claude-opus-4.6`, `claude-opus-4.6-1m` to gateway's built-in fallback model list

**Integrated Mode Startup Fix:**
- Added `SKIP_STARTUP_CREDENTIAL_CHECK=true` environment variable (preset in `docker-compose.yml`)
- Fixed issue where kiro-gateway couldn't start in integrated deployment due to missing local static credentials (credentials are dynamically passed via request headers, no startup validation needed)

**Log Improvements:**
- 429 error logs now include response body from Kiro API, making it easier to distinguish between actual rate limiting and model permission issues

---

### Changes from Original Versions

**kiro-go changes:**
- Added `KIRO_GATEWAY_BASE` / `KIRO_GATEWAY_API_KEY` support to forward requests through kiro-gateway, significantly improving stability
- Web admin panel optimizations

**kiro-gateway changes:**
- Adapted for joint deployment scenario with kiro-go

---

## Disclaimer

> ⚠️ **Please read carefully before use**

- **Account Ban Risk**: Using this project to call Kiro API carries risk of account ban or rate limiting. Kiro / Amazon Q Developer's terms of service may not allow such third-party proxy access. Users bear all consequences.
- **Project Positioning**: This project is only an integration and secondary development of [kiro-gateway](https://github.com/jwadow/kiro-gateway) and [Kiro-Go](https://github.com/Quorinex/Kiro-Go), **does not involve writing any underlying request logic**. All actual communication logic with Kiro API comes from the original projects mentioned above.
- **Unofficial Project**: This project has no affiliation with Amazon, AWS, or official Kiro.
- **For Learning and Research Only**: Do not use this project for commercial purposes or large-scale API abuse.

---

## Acknowledgments

This project is based on secondary development of the following excellent open-source projects:

- **[kiro-gateway](https://github.com/jwadow/kiro-gateway)** by [@Jwadow](https://github.com/jwadow) — AGPL-3.0
- **[Kiro-Go](https://github.com/Quorinex/Kiro-Go)** by [@Quorinex](https://github.com/Quorinex) — MIT

---

## License

This project follows the original licenses of each subproject:
- `kiro-gateway/` — [AGPL-3.0](kiro-gateway/LICENSE)
- `kiro-go/` — [MIT](kiro-go/LICENSE) *(if original project has one)*

Integration code follows MIT License.
