# basic-auth-plugin

A proxy-wasm plugin for Envoy that implements basic authentication. Allowed users can pass through and access the service. The authorization is stored in an encrypted cookie which makes it persistent across sessions.

## Install

### Install Toolchain for WASM in Rust

For developing the [Rust Toolchain](https://www.rust-lang.org/tools/install) has to be installed and the WASM target has to be enabled. E.g. for Ubuntu this can be achieved by:

```sh
# Install Build essentials
apt install build-essential
# Install Rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Enable WASM compilation target
cargo build --target wasm32-wasip1 --release
```

## Run

**Shortcut** (make sure to have [make](https://www.gnu.org/software/make/) installed):

```sh
make run
```

---

### Detailed variant

1. **Building the plugin:**

```sh
cargo build --target wasm32-wasip1 --release
# or
make build
```

2. **Testing locally with Envoy** ([docker](https://www.docker.com/) and [docker-compose](https://docs.docker.com/compose/install/) are needed):

```sh
docker compose up
```

3. **Requests to the locally running envoy with the plugin enabled:**

```sh
curl localhost:10000
```

## Configuration

The plugin is configured via the `envoy.yaml`-file. The following configuration options are required:

| Name | Type | Description | Example | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `allowed_users` | Object | A list of allowed username/password combinations. | See below | ✅ |
| `cookie_name` | String | Name of the Session and Nonce cookie. | `basic-auth-session` | ✅ |
| `cookie_duration` | u64 | A number of seconds that the cookie should live for. | 86400 | ✅ |
| `aes_key` | String | A base64-encoded AES-Key of 32 bits, generate with `openssl rand -base64 32` | g00nv8nuZfNrqc99OKUOqCCatepmscgSeX70nYq4Xdo= | ✅ |

The `allowed_users` key expects a list of username/password combinations, like so:

```yaml
allowed_users:
  - username: user1
    password: password123
```
