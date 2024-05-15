# scrypt-mcf - v1.1.1

Scrypt using MCF for both browsers and Node.js

## Table of contents

### Interfaces

- [ScryptMcfOptions](interfaces/ScryptMcfOptions.md)
- [ScryptParams](interfaces/ScryptParams.md)

### Functions

- [hash](API.md#hash)
- [verify](API.md#verify)

## Functions

### hash

▸ **hash**(`password`, `options?`): `Promise`<`string`\>

Computes a MFC string derived using scrypt on input password

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `password` | `string` | the password |
| `options?` | [`ScryptMcfOptions`](interfaces/ScryptMcfOptions.md) | optional 16 bytes/22 characters salt in base64 with no padding (a fresh random one is created if not provided), derivedKeyLength (defaults to 32 bytes), and scrypt parameters (defaults to { logN: 17, r: 8, p: 1 }) |

#### Returns

`Promise`<`string`\>

a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>

#### Defined in

[index.ts:28](https://github.com/juanelas/scrypt-mcf/blob/07d1d9e/src/ts/index.ts#L28)

___

### verify

▸ **verify**(`password`, `mcf`): `Promise`<`boolean`\>

Verify if provided password meets the stored hash (in MCF)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `password` | `string` | the password to test |
| `mcf` | `string` | a MFC string with the format $scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding> |

#### Returns

`Promise`<`boolean`\>

#### Defined in

[index.ts:53](https://github.com/juanelas/scrypt-mcf/blob/07d1d9e/src/ts/index.ts#L53)
