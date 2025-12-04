# Zones

erldns reads zone files from this folder, and loads them on start. Zones must be formatted as JSON, and stored in `.json` files.

## Default zones

All `.json` files within this folder are default zones, packaged with the default `erldns` distribution. They are used to bootstrap the state when you start the project.

## Custom zones

You can place your custom zones files inside the `priv/zones/local` directory. The content of this folder is not tracked by version control, and you can use it freely to add more zones for any purpose.

## JSON files

A JSON zone file contains an array of 1 or more zones. Each zone has a name and an array of records. Each record has a name, type, ttl and data field. The data field contains a JSON object with one or more attributes that are appropriate for the specific record type.

### Contexts

Each record can optionally contain a `context` field, that can be used to restrict the record to a specific subset of nodes. These are specified by the `context_options` configuration option of each node. This field is used for global node provisioning, and not part of any DNS specification.

For example, if you have multiple nodes across many datacentres, and one of them, deployed in a datacenter in Amsterdam, declares the following section in the config:

```erlang
{erldns, [
    {zones, #{
        context_options => #{match_empty => true, allow => [<<"AMS">>]}
    }},
]}
```

You can then declare a JSON entry with `"context": ["AMS"]`, and this specific record will be loaded _only_ in the node that is configured as deployed in Amsterdam, and not in others.

Note that these strings are opaque to `erldns`, and you can use any string you want, as long as there's a sensible matching between the configuration and the values in the JSON entry.

`match_empty` means if a record with an empty context should match by default.

### DNSSEC keys

A zone can also declare a set of keys, as stated in the example below. In such case, records will be
pre-signed during loading with the given keys.

Supported DNSSEC algorithms:

- RSA (algorithm 5, 7, 8)
- ECDSA P-256 (algorithm 13, ECDSAP256SHA256)
- ECDSA P-384 (algorithm 14, ECDSAP384SHA384)
- Ed25519 (algorithm 15)
- Ed448 (algorithm 16)

Private keys must be provided in PEM format. For Ed25519 and Ed448, use `-----BEGIN PRIVATE KEY-----` format.

### Example

The follow is an example of a collection of zones with a single zone in the collection:

```json
[
  {
    "name": "example.com",
    "records": [
      {
        "name": "example.com",
        "type": "SOA",
        "ttl": 3600,
        "data": {
          "mname": "ns1.example.com",
          "rname": "admin.example.com",
          "serial": 1234567,
          "refresh": 1,
          "retry": 1,
          "expire": 1,
          "minimum": 1
        }
      },
      {
        "name": "example.com",
        "type": "A",
        "ttl": 3600,
        "data": {
          "ip": "1.2.3.4"
        }
      },
      {
        "name": "example.com",
        "type": "MX",
        "ttl": 3600,
        "data": {
          "preference": 10,
          "exchange": "mail.example.com"
        }
      }
    ],
    "keys": [
      {
        "ksk": "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCn9Iv82vkFiv8ts8K9jzUzfp3UEZx+76r+X9A4GOFfYbx3USCh\nEW0fLYT/QkAM8/SiTkEXzZPqhrV083mp5VLYNLxic2ii6DrwvyGpENVPJnDQMu+C\nfKMyb9IWcm9MkeHh8t/ovsCQAEJWIPTnzv8rlQcDU44c3qgTpHSU8htjdwICBAEC\ngYEAlpYTHWYrcd0HQXO3F9lPqwwfHUt7VBaSEUYrk3N3ZYCWvmV1qyKbB/kb1SBs\n4GfW1vP966HXCffnX92LDXYxi7It3TJaKmo8aF/leN7w8WLNJXUayEoQKUfKLprj\nN14Jx/tgMu7I/BOoHId8b7e57pBKtDiSF6WWn3K7tNPbfmkCQQDST41m62mC4MAa\nDsUdyM0Vg/tjduGqnygryCDEXDabdg95a3wMk0SQCQzZFHGNYnsXcffTqGs/y+5w\nQWxyOGSNAkEAzHFkDJla30NiiKvhu7dY+0+dGrfMA7pNUh+LGdXe5QFdjwwxqPbF\n7NMGXKMdB8agSCxGZC3bxdvYNF9LULzhEwJABpDYNSoQx+UMvaEN5XTpLmCHuS1r\nsmhfKZPcDx8Z7mAYda3wZEuHQq+cf6i5XhOO9P5QKpKeslHLAMHa7NaNgQJBAI03\nGGacYLwui32fbzb8BYRg82Kga/OW6btY+O6hNs6iSR2gBlQ9j3Tgrzo+N4R/NQSl\nc05wGO2RnBUwlu0XUckCQHfHsWHVrrADTpalbv+FTDyWd0ouHXBmDecVZh3e7/ue\ncdMoblzeasvgp8CjFa9U+uDozY+aL6TNIpG++nn4lNw=\n-----END RSA PRIVATE KEY-----\n",
        "ksk_keytag": 37440,
        "ksk_alg": 8,
        "zsk": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8YnU+YqBxD/EDwVeHZsJillAJ80PCnLU+/rlGrlzgw+eabF8jT\nCaEwnpE74YHCLegKAAn+efeZrT/EBBrzlacCAgIBAkBh9VGFW2SJk1I9SBQaDIA9\nchdrrx+PHibSyozwT4eAPmd6OFoLausc7ls6v9evPeb+Yj3g0JXvTGp6BgNhFqLR\nAiEA1+ievAEBVM6IlOmpiTwlaWe/HV6MokBBq1G/tvJS0M8CIQDPm/DUsoTEv/Jj\n6O3U9hNcPLbvKMMGld2wbf7nrQmzqQIhAJrhwTaFdjnXhmfUB9a33vRIbSaIsLxA\nDyuM+03XP+YhAiEAmJIJz7WX9uPkCIy8wO655Hh4dt4UkBFRE98OqkHIwGkCIFFv\nN8rJojI+oEiJyNjEjWZD4qoUMUp3+YBl0htAJUE2\n-----END RSA PRIVATE KEY-----\n",
        "zsk_keytag": 49016,
        "zsk_alg": 8,
        "inception": "2016-11-14T11:36:58.851612Z",
        "until": "2046-02-12T11:36:58.849384Z"
      }
    ]

  }
]
```
