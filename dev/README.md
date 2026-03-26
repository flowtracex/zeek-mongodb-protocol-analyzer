# Developer Notes

This directory contains the source and build files for the MongoDB Spicy analyzer.

## Layout

- `analyzer/` contains the Spicy parser and Zeek event bindings
- `cmake/` contains the CMake helper for Spicy plugin discovery
- `CMakeLists.txt` is the developer build entry point

## Build

From the repository root:

```bash
cmake -S dev -B dev/build
cmake --build dev/build
cp dev/build/mongodb.hlto ./mongodb.hlto
```

Optional install into Zeek:

```bash
cmake --install dev/build
```

## Source Files

- `analyzer/mongodb.spicy`
- `analyzer/mongodb.evt`
- `analyzer/zeek_mongodb.spicy`
