# marty_dasm_web

A client-side WebAssembly interface for `marty_dasm`. Disassembly occurs entirely within the browser using the magic of wasm-compiled Rust.

## Running locally

Install [Trunk](https://trunkrs.dev/), then run from this directory:

```text
trunk serve
```

Open <http://localhost:8080>. Trunk rebuilds and reloads the application when its sources change.

The current disassembly can be shared through URL parameters:

```text
?cpu=intel80386&segment=32&hex=B8+34+12+00+00
```

Appending `raw=1` renders only a `pre#raw-output` element containing space-aligned offsets, bytes, and instructions. 
Raw mode is intended to serve as primitive API endpoint. It ignores LocalStorage so its output depends only on the URL:

```text
?cpu=intel80386&segment=32&hex=B8+34+12+00+00&raw=1
```

## Building 

To produce an optimized static build:

```text
trunk build --release
```

For a compile-only check from the workspace root:

```text
cargo check -p marty_dasm_web --target wasm32-unknown-unknown
```

## Web App Operation

All the parameters used for disassembly are encoded in the query parameters of the URL, allowing you to share disassembly with others, or bookmark it, or programatically fetch disassembly, or whatever other sick ideas you may have.

Inputs shorter than 64 UTF-8 bytes remain readable in the `hex` parameter. For longer inputs, the app uses a Base64URL-encoded `hex_gz` parameter when gzip produces a shorter URL. 

I'm still not sure if this is worth doing since it only saves about 33%. Both forms preserve the exact input text, including whitespace.

Compressed links are limited to 1 MiB after decompression to avoid some kind of url-gzip-bomb shenanigans.

## License

MIT
