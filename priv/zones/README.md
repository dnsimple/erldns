# Zones

erldns reads zone files from this folder, and loads them on start. Zones must be formatted as JSON, and stored in `.json` files.

## Default zones

All `.json` files within this folder are default zones, packaged with the default `erldns` distribution. They are used to bootstrap the state when you start the project.

## Custom zones

You can place your custom zones files inside the `priv/zones/local` directory. The content of this folder is not tracked by version control, and you can use it freely to add more zones for any purpose.

## JSON files

A JSON zone file contains an array of 1 or more zones. Each zone has a name and an array of records. Each record has a name, type, ttl and data field. The data field contains a JSON object with one or more attributes that are appropriate for the specific record type.

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
