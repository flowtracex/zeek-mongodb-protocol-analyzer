# Zeek MongoDB Analyzer

MongoDB protocol analyzer for Zeek using Spicy.

This repository is organized for normal users first:

- `mongodb.hlto` is the analyzer bundle to install
- `scripts/` contains the Zeek loader and log logic
- `tests/pcaps/` contains small sample pcaps for quick testing
- `legacy_bak/` keeps the older pure-Zeek reference implementation
- `dev/` contains source and build files for developers

## Install

Make sure your Zeek installation has Spicy support available.

Check with:

```bash
zeek -NN | grep Spicy
```

Copy the analyzer bundle into Zeek's Spicy directory:

```bash
cp mongodb.hlto /opt/zeek/lib/zeek/spicy/
```

Adjust the destination if your Zeek installation uses a different prefix.

## Run

Load the included Zeek script when replaying traffic:

```bash
zeek -Cr tests/pcaps/mongodb_insert_find.pcap scripts/__load__.zeek
```

This writes `mongodb.log` in the directory where you run Zeek.

## What It Logs

- `request_id`
- `response_to`
- `opcode`
- `is_request`
- `is_reply`
- `database`
- `collection`
- `command`
- `crud_op`
- `ok`
- `errmsg`
- `n`
- `n_modified`

## Sample Files

Small sample pcaps are included in `tests/pcaps/`:

- `mongodb_hello.pcap`
- `mongodb_insert_find.pcap`
- `mongodb_update_delete_error.pcap`

## Developer Notes

If you want to rebuild the analyzer from source, see `dev/README.md`.
