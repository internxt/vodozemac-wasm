# vodozemac-wasm-bindings
A fork of [vodozemac-bindings](https://github.com/matrix-org/vodozemac-bindings) which is no longer maintained.

Offers only the JS bindings.

[vodozemac]: https://github.com/matrix-org/vodozemac

## install

```shell
npm i vodozemac-wasm-bindings
```

## create new bindings

```shell
wasm-pack build --target web
```


## Example usage

- [1-to-1 Olm Session](https://github.com/Mekacher-Anis/vodozemac-wasm-bindings/blob/main/javascript/examples/1-to-1-olm.ts)
- [Megolm group chat](https://github.com/Mekacher-Anis/vodozemac-wasm-bindings/blob/main/javascript/examples/group-chat.ts)