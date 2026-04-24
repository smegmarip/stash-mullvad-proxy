# Stash Mullvad Proxy

A domain-routing HTTP/HTTPS proxy that tunnels traffic through [Mullvad VPN](https://mullvad.net/) WireGuard tunnels. Create multiple tunnels to different Mullvad relay servers and assign domain patterns to each one -- traffic matching a pattern exits through that tunnel, everything else goes direct.

Built for [Stash](https://github.com/stashapp/stash) deployments where specific upstream domains need to egress through a VPN, but works as a general-purpose selective proxy for any HTTP client that supports proxy configuration.

## Features

- **Multiple concurrent tunnels** -- create as many WireGuard tunnels as needed, each connecting to a different Mullvad relay server. Tunnels are independent and run simultaneously.
- **Domain-based routing** -- assign domain patterns to tunnels. Supports exact match (`example.com`), wildcard prefix (`*.example.com`), and bare dot (`.example.com`) patterns.
- **HTTP and HTTPS proxying** -- handles both plain HTTP forwarding and HTTPS CONNECT tunneling. Any application that supports an HTTP proxy can use it.
- **Web dashboard** -- a built-in single-page UI for managing tunnels, routes, and monitoring connection status. Accessible on the web port.
- **Mullvad relay browser** -- fetches the live relay list from Mullvad's API (cached hourly) so you can pick servers by country, city, and provider directly from the dashboard.
- **Automatic device registration** -- creating a tunnel generates a WireGuard keypair, registers it as a device on your Mullvad account via their API, and configures the interface and policy routing automatically.
- **Persistent state** -- tunnel configurations, routes, and active state are stored in a JSON file. Tunnels marked active are automatically restored on container restart.
- **Policy routing** -- each tunnel gets its own Linux routing table. Source-based policy rules ensure only traffic bound for a matched domain exits through the tunnel, leaving the container's default route untouched.

## Architecture

```
+-----------------+                    +-------------------------+
|  Stash / any    |  HTTP proxy req    |  stash-mullvad-proxy    |
|  HTTP client    | -----------------> |                         |
|  (proxy config) |                    |  Domain Router          |
+-----------------+                    |    *.example.com → wg1  |
                                       |    other.net     → wg2  |
                                       |    (no match)    → direct|
                                       |                         |
                                       |  WireGuard Manager      |
                                       |    wg1 → se-mma-wg-001  |
                                       |    wg2 → us-nyc-wg-003  |
                                       +----------|---|----------+
                                                  |   |
                                        tunnel 1  |   |  tunnel 2
                                                  v   v
                                       +-------------------+
                                       | Mullvad Relays    |
                                       | (WireGuard)       |
                                       +-------------------+
```

## Mullvad Account Setup

1. Go to [mullvad.net](https://mullvad.net/) and click **Generate account**.
2. Mullvad does not require an email, username, or password -- you receive a 16-digit account number. Save it somewhere secure.
3. Add time to your account using any of Mullvad's payment methods (credit card, cryptocurrency, cash, etc.).
4. Copy your account number -- you will set it as the `MULLVAD_ACCOUNT` environment variable.

The proxy registers WireGuard devices against your account via the Mullvad API. Each tunnel consumes one device slot. Mullvad allows up to 5 devices per account. Deleting a tunnel from the dashboard also removes the device from your Mullvad account.

## Prerequisites

1. **Docker** with Docker Compose.
2. A **Mullvad VPN** account with an active subscription.
3. A **Docker network** that your Stash container (or other HTTP clients) is attached to. The proxy joins this network so clients can reach it by container hostname.

## Installation

1. Clone this repository:

   ```sh
   git clone https://github.com/smegmarip/stash-mullvad-proxy.git
   cd stash-mullvad-proxy
   ```

2. Copy the example environment file and fill in your Mullvad account number:

   ```sh
   cp .env.example .env
   ```

   Edit `.env` and set `MULLVAD_ACCOUNT` to your 16-digit account number.

3. Ensure the Docker network exists (create it if it doesn't):

   ```sh
   docker network create stash-network
   ```

4. Start the container:

   ```sh
   docker compose up -d
   ```

5. Open the web dashboard at `http://localhost:11000` (or whatever you set `WEB_PORT` to).

6. Configure your HTTP client (e.g. Stash) to use the proxy:

   - **Same Docker network** (recommended) -- if Stash is on the same Docker network (`stash-network` by default), it can reach the proxy by container hostname:

     ```
     http://stash-mullvad-proxy:11001
     ```

   - **Different Docker network or external host** -- if Stash runs on a separate Docker network or on a different machine, use the host's IP address and the mapped web port. The proxy port (`11001`) is not published to the host by default, so you will need to add a port mapping in `docker-compose.yml`:

     ```yaml
     ports:
       - "${WEB_PORT:-11000}:11000"
       - "11001:11001"  # expose proxy port to host
     ```

     Then configure Stash to use the host's IP:

     ```
     http://<host-ip>:11001
     ```

     Replace `<host-ip>` with the actual IP of the machine running the proxy (e.g. `192.168.1.50`).

## Usage

### Creating a tunnel

1. Open the web dashboard.
2. Browse the Mullvad relay list -- filter by country or city.
3. Give the tunnel a name (e.g. "Sweden") and select a relay server.
4. Click create. The proxy will generate a WireGuard keypair, register a device with Mullvad, create the interface, and set up policy routing.

### Adding a route

1. In the dashboard, add a domain pattern (e.g. `*.example.com`) and select which tunnel it should use.
2. Traffic to matching domains will immediately begin routing through that tunnel.

### Domain pattern syntax

| Pattern         | Matches                                                 |
| --------------- | ------------------------------------------------------- |
| `example.com`   | Exactly `example.com`                                   |
| `*.example.com` | Any subdomain: `foo.example.com`, `bar.baz.example.com` |
| `.example.com`  | Same as `*.example.com`, plus `example.com` itself      |

### Deleting

- Routes can be deleted independently at any time.
- Tunnels with active routes cannot be deleted -- remove the routes first.
- Deleting a tunnel tears down the WireGuard interface and removes the device from your Mullvad account.

## Configuration

All configuration is via environment variables. See `.env.example` for the full list.

| Variable          | Description                                                      | Default         |
| ----------------- | ---------------------------------------------------------------- | --------------- |
| `MULLVAD_ACCOUNT` | Mullvad 16-digit account number (required)                       | --              |
| `DOCKER_NETWORK`  | Name of the Docker network shared with Stash / other clients     | `stash-network` |
| `WEB_PORT`        | Host port mapped to the web dashboard                            | `11000`         |
| `PROXY_ADDR`      | Listen address for the HTTP proxy (internal to the container)    | `:11001`        |
| `WEB_ADDR`        | Listen address for the web dashboard (internal to the container) | `:11000`        |
| `DATA_PATH`       | Host path for persistent data (tunnel configs, routes)           | `./data`        |

## API Endpoints

The web dashboard communicates via a JSON REST API, which can also be used directly.

| Method   | Path                | Description                             |
| -------- | ------------------- | --------------------------------------- |
| `GET`    | `/api/status`       | Proxy status (active tunnels, routes)   |
| `GET`    | `/api/relays`       | List available Mullvad WireGuard relays |
| `GET`    | `/api/tunnels`      | List all tunnels with status            |
| `POST`   | `/api/tunnels`      | Create a new tunnel                     |
| `DELETE` | `/api/tunnels/{id}` | Delete a tunnel                         |
| `GET`    | `/api/routes`       | List all domain routes                  |
| `POST`   | `/api/routes`       | Create a domain route                   |
| `DELETE` | `/api/routes/{id}`  | Delete a domain route                   |

## Repository Layout

```
stash-mullvad-proxy/
├── README.md                          <- this file
├── Dockerfile                         <- multi-stage Go build + Alpine + WireGuard tools
├── docker-compose.yml                 <- container config with NET_ADMIN capability
├── .env.example                       <- environment variable template
├── go.mod                             <- Go 1.22 module
├── cmd/
│   └── server/
│       └── main.go                    <- entry point, wires components, signal handling
└── internal/
    ├── mullvad/
    │   ├── api.go                     <- Mullvad API client (auth, device registration)
    │   └── relays.go                  <- WireGuard relay list with TTL cache
    ├── proxy/
    │   └── proxy.go                   <- HTTP/CONNECT forward proxy
    ├── router/
    │   └── router.go                  <- domain pattern matching engine
    ├── store/
    │   └── store.go                   <- JSON file persistence (tunnels + routes)
    ├── web/
    │   ├── handler.go                 <- REST API handlers + embedded UI
    │   └── static/
    │       └── index.html             <- single-page web dashboard
    └── wireguard/
        └── manager.go                 <- WireGuard interface lifecycle + policy routing
```

## Credits

- VPN service: [Mullvad VPN](https://mullvad.net/).
