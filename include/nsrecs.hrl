-record(header, {
        id        = 0,
        qr        = 0,
        opcode    = 0,
        aa        = 0,
        tc        = 0,
        rd        = 0,
        ra        = 0,
        z         = 0,
        rcode     = 0,
        qdcount   = 0,
        ancount   = 0,
        nscount   = 0,
        arcount   = 0
        }).

-record(question, { 
        qname       = [], 
        qtype       = 0, 
        qclass      = 0 
        }).

-record(message, { 
        header      = [],
        question    = [],
        answer      = [],
        authority   = [],
        additional  = []
        }).


