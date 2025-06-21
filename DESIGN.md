# Design Decisions

This document captures key architectural decisions made in the `erldns` project. Each section follows a "what and why" structure, first describing the technical implementation details and then explaining the rationale behind these choices. This approach helps maintain a clear record of our design decisions and their motivations for future reference.

## UDP Payload Size Handling

DNS over UDP has traditionally been limited to 512 bytes per message. However, with the introduction of EDNS (Extension Mechanisms for DNS), clients can specify larger UDP payload sizes through the OPT RR (Resource Record) in the additional section of the DNS message.

In Erldns, we've implemented a strict enforcement of UDP payload sizes to ensure compatibility and prevent potential issues:

1. **Minimum Size**: We enforce a minimum UDP payload size of 512 bytes (`?MIN_PACKET_SIZE`), which is the traditional DNS UDP message size limit.
2. **Maximum Size**: We enforce a maximum UDP payload size of 1232 bytes (`?MAX_PACKET_SIZE`), which is the recommended maximum size for DNS over UDP to avoid IP fragmentation.
3. **Payload Size Adjustment**: When a client sends a DNS request with an OPT RR containing an invalid UDP payload size (either too small or too large), we automatically adjust it to the maximum allowed size (1232 bytes) rather than rejecting the request.

This design decision prioritizes graceful degradation by automatically adjusting invalid payload sizes rather than rejecting requests, while simultaneously protecting against potential DoS attacks through oversized packets.
