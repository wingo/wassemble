# wassemble

`wassemble` is a JavaScript tool to convert WebAssembly standard textual
format (wat) to binary (wasm).  It is a single file of JavaScript with
no dependencies.

Note, [wabt](https://github.com:WebAssembly/wabt) is a more
full-featured toolkit for working with WebAssembly, both in textual and
binary formats, and includes a tool called `wat2wasm`.  However
sometimes you just want a simple JS file to drop into your projects;
that's what `wassemble` is about.  You could think of it as a clone of
wabt's `wat2wasm`, but built in a different way.

## Differences from `wabt`

Unlike `wat2wasm`, `wassemble` does minimal error-checking.  Notably, it
doesn't type-check the module; it assumes the WebAssembly implementation
will signal any validation-time errors when the module is instantiated.
As such, this tool is most useful for compiling known-valid `wat` files,
or for generating known-invalid modules for fuzzing or testing purposes.

## Install

```
npm install wassemble
```

As this project has no dependencies, alternately you can just drop
`wassemble.mjs` anywhere in your project tree.

## Usage

Assuming you installed via NPM, this code compiles a WebAssembly `add`
function, synchronously instantiates it, and adds a couple numbers:

```js
import wassemble from 'wassemble/wassemble.mjs';

let bytes = wassemble(`
  (module
    (func $add (export "add") (param i32 i32) (result i32)
      (i32.add (local.get 0) (local.get 1))))`)

let mod = new WebAssembly.Instance(new WebAssembly.Module(bytes));

console.log(mod.exports.add(10, 32));
```

Of course it's better to use `WebAssembly.instantiate` if possible.

## License

`wassemble` is available under the [Blue Oak Model
License](https://blueoakcouncil.org/license/1.0.0), version 1.0.0.  See
[LICENSE.md](./LICENSE.md) for full details.
