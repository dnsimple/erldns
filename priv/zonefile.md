erl-dns reads JSON zone files.

A JSON zone file contains an array of 1 or more zones. Each zone has a name and an array of records. Each record has a name, type, ttl and rdata field.

An example:

    [{
      "name": "example.com",
      "records": [
        {
          "name": "example.com",
          "type": "SOA",
          "ttl": 3600,
          "rdata": {
            "mname": "ns1.example.com",
            "rname": "admin.example.com",
            "serial": 1234567,
            "refresh": 1,
            "retry": 1,
            "expire": 1,
            "minimum": 1
          }
        {
          "name": "example.com",
          "type": "A",
          "ttl": 3600,
          "rdata": {
            "ip": "1.2.3.4"
          }
        },
        {
          "name": "example.com",
          "type": "MX",
          "ttl": 3600,
          "rdata": {
            "preference": "10",
            "exchange": "mail.example.com"
          }
        }
      ]
    }]
