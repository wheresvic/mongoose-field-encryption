# mongoose-field-encryption

![Build Status](https://github.com/wheresvic/mongoose-field-encryption/workflows/ci-test/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/wheresvic/mongoose-field-encryption/badge.svg?branch=master)](https://coveralls.io/github/wheresvic/mongoose-field-encryption?branch=master)

A zero dependency simple symmetric encryption plugin for individual fields. The goal of this plugin is to encrypt data but still allow searching over fields with string values. This plugin relies on the Node `crypto` module. Encryption and decryption happen transparently during save and find.

While this plugin works on individual fields of any type, note that for non-string fields, the original value is set to undefined after encryption. This is because if the schema has defined a field as an array, it would not be possible to replace it with a string value.

As of the stable 2.3.0 release, this plugin requires provision of a custom salt generation function (which would always provide a constant salt given the secret) in order to retain symmetric decryption capability.

Also consider [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) if you are looking to encrypt the entire document.

## How it works

Encryption is performed using `AES-256-CBC`. To encrypt, the relevant fields are encrypted with the provided secret + random salt (or a custom salt via the provided `saltGenerator` function). The generated salt and the resulting encrypted value is concatenated together using a `:` character and the final string is put in place of the actual value for `string` values. An extra `boolean` field with the prefix `__enc_` is added to the document which indicates if the provided field is encrypted or not.

Fields which are either objects or of a different type are converted to strings using `JSON.stringify` and the value stored in an extra marker field of type `string` with a naming scheme of `__enc_` as prefix and `_d` as suffix on the original field name. The original field is then set to `undefined`. Please note that this might break any custom validation and application of this plugin on non-string fields needs to be done with care.

## Requirements

- Node `>=14` (Use `2.3.4` for Node `>=4.4.7 && <6.x.x`, `5.0.3` for Node `>=6.x.x && <=10.x.x`, `6.3.0` for Node `12.x.x`)
- MongoDB `>=4.4`
- Mongoose `>=7.0.0` (use `6.3.0` for Mongoose `<7.0.0`)

## Installation

`npm install mongoose-field-encryption --save-exact`

## Security Notes

- _Always store your keys and secrets outside of version control and separate from your database._ An environment variable on your application server works well for this.
- Additionally, store your encryption key offline somewhere safe. If you lose it, there is no way to retrieve your encrypted data.
- Encrypting passwords is no substitute for appropriately hashing them. `bcrypt` is one great option. You can also encrypt the password afer hashing it although it is not necessary.
- If an attacker gains access to your application server, they likely have access to both the database and the key. At that point, neither encryption nor authentication do you any good.

## Usage

### Basic

For example, given a schema as follows:

```js
const mongoose = require("mongoose");
const mongooseFieldEncryption = require("mongoose-field-encryption").fieldEncryption;
const Schema = mongoose.Schema;

const PostSchema = new Schema({
  title: String,
  message: String,
  references: {
    author: String,
    date: Date,
  },
});

PostSchema.plugin(mongooseFieldEncryption, { 
  fields: ["message", "references"], 
  secret: "some secret key",
  saltGenerator: function (secret) {
    return "1234567890123456"; 
    // should ideally use the secret to return a string of length 16, 
    // default = `const defaultSaltGenerator = secret => crypto.randomBytes(16);`, 
    // see options for more details
  },
});

const Post = mongoose.model("Post", PostSchema);

const post = new Post({ title: "some text", message: "hello all" });

post.save(function (err) {
  console.log(post.title); // some text (only the message field was set to be encrypted via options)
  console.log(post.message); // a9ad74603a91a2e97a803a367ab4e04d:93c64bf4c279d282deeaf738fabebe89
  console.log(post.__enc_message); // true
});
```

The resulting documents will have the following format:

```js
{
  _id: ObjectId,
  title: String,
  message: String, // encrypted salt and hex value as string, e.g. 9d6a0ca4ac2c80fc84df0a06de36b548:cee57185fed78c055ed31ca6a8be9bf20d303283200a280d0f4fc8a92902e0c1
  __enc_message: true, // boolean marking if the field is encrypted or not
  references: undefined, // encrypted object set to undefined
  __enc_references: true, // boolean marking if the field is encrypted or not
  __enc_references_d: String // encrypted salt and hex object value as string, e.g. 6df2171f25fd1d32adc4a4059f867a82:5909152856cf9cdb7dc32c6af321c8fe69390c359c6b19d967eaa6e7a0a97216
}
```

`find` works transparently and you can make new documents as normal, but you should not use the `lean` option on a find if you want the fields of the document to be decrypted. `findOne`, `findById` and `save` also all work as normal. `updateOne` works _only for string fields_ and you would also need to manually set the `__enc_` field value to false if you're updating an encrypted field. Currently `updateMany` is not supported.

From the mongoose package documentation: _Note that findAndUpdate/Remove do not execute any hooks or validation before making the change in the database. If you need hooks and validation, first query for the document and then save it._

Note that as of `1.2.0` release, support for `findOneAndUpdate` has also been added. Note that you would need to specifically set the encryption field marker for it to be encrypted. For example:

```js
Post.findOneAndUpdate({ _id: postId }, { $set: { message: "snoop", __enc_message: false } });
```

The above also works for non-string fields. See changelog for more details.

Also note that if you manually set the value `__enc_` prefix field to true then the encryption is not run on the corresponding field and this may result in the plain value being stored in the db.

### Search over encrypted fields

Note that in order to use this option a _fixed_ salt generator must be provided. See example as follows:

```js
const messageSchema = new Schema({
  title: String,
  message: String,
  name: String,
});

messageSchema.plugin(mongooseFieldEncryption, {
  fields: ["message", "name"],
  secret: "some secret key",
  saltGenerator: function (secret) {
    return "1234567890123456";
    // should ideally use the secret to return a string of length 16, 
    // default = `const defaultSaltGenerator = secret => crypto.randomBytes(16);`, 
    // see options for more details
  },
});

const title = "some text";
const name = "victor";
const message = "hello all";

const Message = mongoose.model("Message", messageSchema);

const messageToSave = new Message({ title, message, name });
await messageToSave.save();

// note that we are only providing the field we would like to search with
const messageToSearchWith = new Message({ name });
messageToSearchWith.encryptFieldsSync();

// `messageToSearchWith.name` contains the encrypted string text
const results = await Message.find({ name: messageToSearchWith.name });

// results is an array of length 1 (assuming that there is only 1 message with the name "victor" in the collection)
// and the message in the results array corresponds to the one saved previously
```

### Options

- `fields` (required): an array list of the required fields
- `secret` (required): a string cipher (or a synchronous factory function which returns a string cipher) which is used to encrypt the data (don't lose this!)
- `useAes256Ctr` (optional, default `false`): a boolean indicating whether the older `aes-256-ctr` algorithm should be used. Note that this is strictly a backwards compatibility feature and for new installations it is recommended to leave this at default.
- `saltGenerator` (optional, default `const defaultSaltGenerator = secret => crypto.randomBytes(16);`): a function that should return either a `utf-8` encoded string that is 16 characters in length or a `Buffer` of length 16. This function is also passed the secret as shown in the default function example.
- `encryptNull` (optional, default `true`): An option to enable or disable encryption of null values.
- `notifyDecryptFails` (optional, default `true`): An option to enable or disable an exception on decryption failures. When disabled, exceptions will be inhibited, and an empty field will be returned.

### Static methods

For performance reasons, once the document has been encrypted, it remains so. The following methods are thus added to the schema:

- `encryptFieldsSync()`: synchronous call that encrypts all fields as given by the plugin options
- `decryptFieldsSync()`: synchronous call that decrypts encrypted fields as given by the plugin options
- `stripEncryptionFieldMarkers()`: synchronous call that removes the encryption field markers (useful for returning documents without letting the user know that something was encrypted)

Multiple calls to the above methods have no effect, i.e. once a field is encrypted and the `__enc_` marker field value is set to true then the ecrypt operation is ignored. Same for the decrypt operation. Of course if the field markers have been removed via the `stripEncryptionFieldMarkers()` call, then the encryption will be executed if invoked.

### Searching

To enable searching over the encrypted fields the `encrypt` and `decrypt` methods have also been exposed (see `test/test-manual-encryption` for detailed usage).

```js
const fieldEncryption = require('mongoose-field-encryption');

const defaultSaltGenerator = (secret) => crypto.randomBytes(16);
const _hash = (secret) => crypto.createHash("sha256").update(secret).digest("hex").substring(0, 32);
const encrypted = fieldEncryption.encrypt('some text', _hash('secret')), defaultSaltGenerator);
const decrypted = fieldEncryption.decrypt(encrypted, _hash('secret'))); // decrypted = 'some text'
```

### encryption of nested fields

Note that while this plugin is designed to encrypt only top level fields, nested fields can be easily encrypted by creating a mongoose schema for the nested objects and adding the plugin to them.

See comment for discussion: [https://github.com/wheresvic/mongoose-field-encryption/issues/34#issuecomment-577383776](https://github.com/wheresvic/mongoose-field-encryption/issues/34#issuecomment-577383776).

_Please also note that this example is provided as a best-effort basis and this plugin does not take responsibility for what quirks mongoose might bring if you use this feature._

See relevant test in `test/test-db.js`:

```js
// subdocument encryption

const UserExtraSchema = new mongoose.Schema({
  city: { type: String },
  country: { type: String },
  address: { type: String },
  postalCode: { type: String },
});

UserExtraSchema.plugin(fieldEncryptionPlugin, {
  fields: ["address"],
  secret: "icanhazcheeseburger",
  saltGenerator: (secret) => secret.slice(0, 16),
});

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    surname: { type: String, required: true },
    email: { type: String, required: true },
    extra: UserExtraSchema,
  },
  { collection: "users" }
);

UserSchema.plugin(fieldEncryptionPlugin, {
  fields: ["name", "surname"],
  secret: "icanhazcheeseburger",
  saltGenerator: (secret) => secret.slice(0, 16),
});

const UserModel = mongoose.model("User", UserSchema);
```

## Development

As of version 3.0.5, one can setup a local development mongodb instance using docker:

- copy `development/docker-compose-dev.yml` to `development/docker-compose.yml`
- copy `development/init-mongo-dev.js` to `development/init-mongo.js`
- run `docker-compose up` in the `development` folder

Feel free to make changes to the default docker configuration as required.

### Testing

1. Install dependencies with `npm install` and [install mongo](http://docs.mongodb.org/manual/installation/) if you don't have it yet.
2. Start mongo via `docker-compose up` under the `development` folder.
3. Run tests with `npm run test:auth`. Additionally you can pass your own mongodb uri as an environment variable if you would like to test against your own database, for e.g. `URI='mongodb://username:password@127.0.0.1:27017/mongoose-field-encryption-test' npm test`

### Publishing

#### release-it

`release-it patch,minor,major`

#### Manual

- `npm version patch,minor,major`
- `npm publish`

## Changelog

### 7.0.1

- Update README
- No functionality affected

### 7.0.0

- _BREAKING:_ Update mongoose peer dependency to 7.0.0 which drops `update` and replaces it with `updateOne`. Use previous version if you are still on monogoose `6.x`.
- _BREAKING:_ Drop node 12 support. Mongoose 7.x requires Node 14.

### 6.3.0

- _FEATURE_ Add an optional `encryptNull` configuration option to handle whether `null` values should be encrypted or not. Defaults to  `true` to maintain backwards compatibility.

### 6.2.0

- _FEATURE_ Add an optional `notifyDecryptFails` configuration option (default: `true`).
- Update dev dependencies

### 6.1.0

- _FEATURE_ Add support for `insertMany` [PR #94](https://github.com/wheresvic/mongoose-field-encryption/pull/94)
- Update dev dependencies

### 6.0.0

- _BREAKING:_ Drop Node 6, Node 8 & Node 10 support. Note that the library should still work for node 6, 8 and 10 however it is not actively tested and supported anymore.

### 5.0.1, 5.0.2, 5.0.3

- Update README
- Add test for manual encryption
- No functionality affected
- Update mongoose peer dependency

### 5.0.0

- _BREAKING:_ support encrypting falsy values, e.g. an empty string field, a field with the `0` number value, a field with the `false` boolean value, etc. See relevant test: [test/test-db.js#L631](https://github.com/wheresvic/mongoose-field-encryption/blob/a1f543c11a43fd62426efefa84255d3f14a8fd6d/test/test-db.js#L631)

  Note that previously falsy values were not encrypted and stored as is. On document retrieval the plugin checks for the existence of encrypted data so this should in theory not break existing documents. Existing documents would need to be re-encrypted to take advantage of falsy encryption however.

  As always, please test thoroughly before upgrading.

### 4.0.4, 4.0.5, 4.0.6, 4.0.7

- Update README
- Update development dependencies
- No functionality affected

### 4.0.3

- Add typescript types
- Update development dependencies

### 4.0.2

- Update documentation for subdocument encryption

### 4.0.1

- Update documentation to add nested field encryption example
- Switch from Travis to Github actions

### 4.0.0

- _FEATURE_: Add support for an optional synchronous secret function instead of a fixed string. Note that while this change should be backwards compatible, care should be taken as an issues with the secret could lead to irrecoverable documents!
- Add support for `updateOne` ([https://mongoosejs.com/docs/api.html#query_Query-updateOne](https://mongoosejs.com/docs/api.html#query_Query-updateOne)).

### 3.1.0

- Do not use

### 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6

- Update development dependencies, fix unit tests, no functionality affected
- Add development db via docker (3.0.5)

### 3.0.0

- _BREAKING:_ Drop Node 4 support

### 2.3.5

- Update development dependencies, no functionality affected

### 2.3.2, 2.3.3, 2.3.4

- Update documentation, no functionality affected

### 2.3.1

- Update documentation, no functionality affected

### 2.3.0

- _FEATURE:_ Add provision for a custom salt generator, [PR #27](https://github.com/wheresvic/mongoose-field-encryption/pull/27). Note that by using a custom salt, _fixed_ search capability is now restored.

### 2.2.0

- Update dependencies, no functionality affected

### 2.1.3

- _FIX:_ Fix bug where decryption fails when the field in question is not retrieved, [PR #26](https://github.com/wheresvic/mongoose-field-encryption/pull/26).

### 2.1.1

- _FIX:_ Fix bug where data was not getting decrypted on a `find()`, [#23](https://github.com/wheresvic/mongoose-field-encryption/issues/23).

### 2.0.0

- _BREAKING:_ Use `cipheriv` instead of plain `cipher`, [#17](https://github.com/wheresvic/mongoose-field-encryption/issues/17).

  Note that this might break any _fixed_ search capability as the encrypted values are now based on a random salt.

  Also note that while this version maintains backward compatibility, i.e. decryption will automatically fall back to using the `aes-256-ctr` algorithm, any further updates will lead to the value being encrypted with the salt. In order to fully maintain backwards compatibilty, an new option `useAes256Ctr` has been introduced (default `false`), which can be set to `true` to continue using the plugin as before. It is highly recommended to start using the newer algorithm however, see issue for more details.

### 1.2.0

- _FEATURE:_ Added support for `findOneAndUpdate` [https://github.com/wheresvic/mongoose-field-encryption/pull/20](https://github.com/wheresvic/mongoose-field-encryption/pull/20)

### 1.1.0

- _FEATURE:_ Added support for mongoose 5 [https://github.com/wheresvic/mongoose-field-encryption/pull/16](https://github.com/wheresvic/mongoose-field-encryption/pull/16).
- _FIX:_ Removed mongoose dependency, moved to `peerDependencies`.
- Formatted source code using prettier.
