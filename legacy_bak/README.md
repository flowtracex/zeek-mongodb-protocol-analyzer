# Legacy Reference

This directory contains the older pure-Zeek MongoDB analyzer.

It is kept in the repository for:

- reference
- output comparison
- regression validation against the primary Spicy-based analyzer

New users should start with the repository root and load the Spicy analyzer from `scripts/__load__.zeek`.

## What It Does

- no Spicy
- uses Zeek TCP stream reassembly via `tcp_contents`
- focuses on modern MongoDB `OP_MSG`
- writes one custom log: `mongodb.log`

## Example Logs

- `examples/mongodb_insert_find.log`
- `examples/mongodb_live.log`

## Run Offline

```bash
mkdir -p /tmp/mongodb_legacy_run
cd /tmp/mongodb_legacy_run
zeek -Cr /path/to/mongodb_insert_find.pcap /path/to/repo/legacy/main.zeek
cat mongodb.log
```

Example with this repo:

```bash
mkdir -p /tmp/mongodb_legacy_run
cd /tmp/mongodb_legacy_run
zeek -Cr /opt/tools/zeek_mongodb/repo/tests/pcaps/mongodb_insert_find.pcap \
  /opt/tools/zeek_mongodb/repo/legacy/main.zeek
cat mongodb.log
```
