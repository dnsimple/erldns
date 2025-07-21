# Design Decisions

This document captures key architectural decisions made in the `erldns` project. Each section follows a "what and why" structure, first describing the technical implementation details and then explaining the rationale behind these choices. This approach helps maintain a clear record of our design decisions and their motivations for future reference.

## Resolution algorithm

Once a payload has arrived to the nameserver and after all binary parsing has succeeded (see `m:dns` for details),
the payload is put into a pipeline of transformations over the DNS message. When all pipes have finished resolution, the resulting DNS message will be put back into the socket as the answer and the request will be considered done. See `m:erldns_pipeline` for details.

## UDP Payload Size Handling

DNS over UDP has traditionally been limited to 512 bytes per message. However, with the introduction of EDNS (Extension Mechanisms for DNS), clients can specify larger UDP payload sizes through the OPT RR (Resource Record) in the additional section of the DNS message.

In `erldns`, we've implemented a pipeline handler that allows to ensure compatibility and prevent potential issues,see `m:erldns_edns_max_payload_size` for details.

## Questions

As multiple questions in a single query are generally not well defined, this nameserver only supports a single question per query. If more than one is provided, only the first one will be answered and the remaining will be dropped, raising an event. See `m:erldns_questions` for details.
