# Zeek MongoDB Analyzer

MongoDB protocol analyzer for Zeek using Spicy.

This repository is organized for normal users first:

- `mongodb.hlto` is the prebuilt analyzer bundle
- `scripts/` contains the Zeek loader and log logic
- `tests/pcaps/` contains small sample pcaps for quick testing
- `legacy_bak/` keeps the older pure-Zeek reference implementation
- `dev/` contains source and build files for developers
- `zkg.meta` enables installation through Zeek Package Manager

## Requirements

Your Zeek installation must have Spicy support available.

Check with:

```bash
zeek -NN | grep Spicy
```

## Install Option 1: zkg

This is the recommended option because it builds the analyzer on the target machine.

Make sure the machine has `cmake` installed before running `zkg install`.

Install directly from the GitHub repo:

```bash
zkg install https://github.com/flowtracex/zeek-mongodb-protocol-analyzer
```

After installation, load the package with either:

```bash
@load packages
```

or:

```bash
@load mongodb
```

For quick command-line testing after `zkg install`, this also works:

```bash
zeek -Cr tests/pcaps/mongodb_insert_find.pcap mongodb
```

`zkg` uses `zkg.meta` in this repository to:

- install scripts from `scripts/`
- build the analyzer from `dev/`
- install the built plugin from `dev/build/`

## Install Option 2: Prebuilt `mongodb.hlto`

This is the quick path.

Copy the analyzer bundle into Zeek's Spicy directory:

```bash
cp mongodb.hlto /opt/zeek/lib/zeek/spicy/
```

Then load the script manually when running Zeek:

```bash
zeek -Cr tests/pcaps/mongodb_insert_find.pcap scripts/__load__.zeek
```

This writes `mongodb.log` in the directory where you run Zeek.

## Important Note About the Prebuilt Artifact

The included `mongodb.hlto` was built on Ubuntu with the local Zeek/Spicy toolchain used for this repository.

It may work on similar systems, but it is not guaranteed to work on every machine, Zeek version, libc version, or CPU architecture.

If the prebuilt `mongodb.hlto` does not load correctly on your system, use the `zkg` install path instead.

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
