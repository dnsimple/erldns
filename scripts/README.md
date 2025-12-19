# Zone Generator Script

A pure Erlang script for generating JSON zone files for erldns with configurable parameters.

The script uses constants from `dns_erlang` and `erldns` headers where applicable, with local definitions for portability when running as a standalone escript.

## Usage

### Direct execution (standalone)

```bash
./scripts/generate_zone.erl --zone-name example.com --output priv/zones/local/example.com.json
```

### Using rebar3 (recommended for development)

```bash
rebar3 escriptize
_build/default/bin/erldns generate_zone --zone-name example.com --output priv/zones/local/example.com.json
```

Or run directly with rebar3's code paths:

```bash
rebar3 shell --eval "generate_zone:main([\"-z\", \"example.com\", \"-o\", \"priv/zones/local/example.com.json\"])."
```

## Options

- `--zone-name NAME` / `-z NAME` - Zone name (required when generating a single zone)
- `--output FILE` / `-o FILE` - Output file path (required when generating a single zone)
- `--num-records N` / `-n N` - Number of records to generate (default: 10)
- `--with-dnssec` - Generate DNSSEC records and keys
- `--dnssec-alg ALG` / `-a ALG` - DNSSEC algorithm: 8=RSA, 13=ECDSA-P256, 14=ECDSA-P384, 15=Ed25519, 16=Ed448 (default: 8)
- `--no-randomize` - Disable randomization
- `--seed SEED` / `-s SEED` - Random seed for reproducible output
- `--count N` / `-c N` - Number of zones to generate (default: 1). When > 1, zones are generated in parallel
- `--base-name NAME` / `-b NAME` - Base zone name for multiple zones (required when --count > 1). Zones will be named: base-name1, base-name2, etc.
- `--output-pattern PATTERN` / `-p PATTERN` - Output file pattern for multiple zones. Use `%d` for index, `%s` for zone name. Default: `output-%d.json` when --count > 1
- `--base-dir DIR` / `-d DIR` - Base directory where all generated files will be placed. Directory will be created if it doesn't exist. If output file is absolute, this is ignored.
- `--help` / `-h` - Show help message

**Note:** When using `--count > 1`, `--zone-name` and `--output` are ignored. Use `--base-name` and optionally `--output-pattern` instead.

## Examples

### Generate a simple zone without DNSSEC

```bash
./scripts/generate_zone.erl \
  --zone-name test.com \
  --output priv/zones/local/test.com.json \
  --num-records 20
```

### Generate a DNSSEC-signed zone with RSA keys

```bash
./scripts/generate_zone.erl \
  --zone-name secure.example.com \
  --output priv/zones/local/secure.example.com.json \
  --with-dnssec \
  --dnssec-alg 8 \
  --num-records 50
```

### Generate a DNSSEC-signed zone with Ed25519 keys

```bash
./scripts/generate_zone.erl \
  --zone-name ed25519.example.com \
  --output priv/zones/local/ed25519.example.com.json \
  --with-dnssec \
  --dnssec-alg 15 \
  --num-records 100
```

### Generate reproducible zones for testing

```bash
./scripts/generate_zone.erl \
  --zone-name reproducible.com \
  --output priv/zones/local/reproducible.com.json \
  --seed 12345 \
  --num-records 30
```

### Generate large zones for load testing

```bash
./scripts/generate_zone.erl \
  --zone-name large.com \
  --output priv/zones/local/large.com.json \
  --num-records 10000 \
  --no-randomize
```

### Generate multiple zones in parallel

```bash
# Generate 100 zones in parallel with default naming
./scripts/generate_zone.erl \
  --count 100 \
  --base-name test.com \
  --num-records 50

# Generate zones with custom output pattern
./scripts/generate_zone.erl \
  --count 50 \
  --base-name example.com \
  --output-pattern "/tmp/zones/zone-%d.json" \
  --num-records 100 \
  --with-dnssec

# Generate zones in a base directory
./scripts/generate_zone.erl \
  --count 100 \
  --base-name test.com \
  --base-dir /tmp/generated-zones \
  --num-records 50

# Single zone in a base directory
./scripts/generate_zone.erl \
  --zone-name example.com \
  --output example.com.json \
  --base-dir /tmp/zones \
  --num-records 20
```

**Performance:** Parallel generation is highly efficient, typically generating thousands of zones per second depending on your system.

## Record Types Generated

The script generates various DNS record types:

- **SOA** - Start of Authority (always included)
- **A** - IPv4 address records
- **AAAA** - IPv6 address records
- **NS** - Name server records
- **MX** - Mail exchange records
- **CNAME** - Canonical name records
- **TXT** - Text records
- **SRV** - Service records
- **CAA** - Certificate Authority Authorization records

When `--with-dnssec` is specified, the following DNSSEC records are also generated:

- **DNSKEY** - DNS Key records (KSK and ZSK)
- **CDS** - Child DS record
- **CDNSKEY** - Child DNSKEY record

## DNSSEC Algorithms

Supported DNSSEC algorithms:

- **8** - RSA/SHA-256 (default)
- **13** - ECDSA P-256/SHA-256
- **14** - ECDSA P-384/SHA-384
- **15** - Ed25519
- **16** - Ed448

## Output Format

The script generates a single zone per file in JSON format compatible with erldns. Each zone file contains:

- `name` - Zone name
- `records` - Array of DNS records
- `keys` - Array of DNSSEC key sets (only when `--with-dnssec` is used)

Each key set contains:

- `ksk` - Key Signing Key (PEM-encoded private key)
- `ksk_keytag` - KSK key tag
- `ksk_alg` - KSK algorithm
- `zsk` - Zone Signing Key (PEM-encoded private key)
- `zsk_keytag` - ZSK key tag
- `zsk_alg` - ZSK algorithm
- `inception` - Key inception time (RFC3339 format)
- `until` - Key expiration time (RFC3339 format)

## Use Cases

- **Correctness Testing**: Generate zones with known patterns to verify DNS resolution
- **Load Testing**: Generate large zones to test performance under load
- **DNSSEC Testing**: Generate signed zones with different algorithms to test DNSSEC functionality
- **Reproducible Testing**: Use `--seed` to generate identical zones for regression testing
