# Capabilities request generator

## Build

```sh
npm i
tsc client.ts
```

## Run

```sh
node client.js | xxd -r -p | nc IP_OF_ESP 9993
```