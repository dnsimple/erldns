# Zones

erldns reads zone files from this folder, and loads them on start. Zones must be formatted as JSON, and stored in `.json` files.

## Default zones

All `.json` files within this folder are default zones, packaged with the default `erldns` distribution. They are used to bootstrap the state when you start the project.

## Custom zones

You can place your custom zones files inside the `priv/zones/local` directory. The content of this folder is not tracked by version control, and you can use it freely to add more zones for any purpose.

## JSON files

A JSON zone file contains an array of 1 or more zones. Each zone has a name and an array of records. Each record has a name, type, ttl and data field. The data field contains a JSON object with one or more attributes that are appropriate for the specific record type.

### Contexts

Each record can optionally contain a `context` field, that can be used to restrict the record to a specific context, as configured by the context options in the node.

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
    ]
  }
]
```
