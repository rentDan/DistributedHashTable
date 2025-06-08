This script implements a peer-to-peer distributed hash table.

Each Node:
- Joins a ring of peers using consistent hashing
- Stores and serves key-value pairs within its hash space
- Routes data requests(get, insert, remove, contains) to the correct peer
- Dynamically updates its routing table(finger table) for efficient lookups
- Handles joining and leaving the network without data loss.

This DHT is not fault-tolerant, as there are no backups for key-value pairs.
