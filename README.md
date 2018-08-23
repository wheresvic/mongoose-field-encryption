# mongoose-field-encryption

[![Build Status](https://travis-ci.org/victorparmar/mongoose-field-encryption.svg?branch=master)](https://travis-ci.org/victorparmar/mongoose-field-encryption) [![Coverage Status](https://coveralls.io/repos/github/victorparmar/mongoose-field-encryption/badge.svg?branch=master)](https://coveralls.io/github/victorparmar/mongoose-field-encryption?branch=master)

A simple symmetric encryption plugin for individual fields. The goal of this plugin is to encrypt data but still allow searching over fields with string values. This plugin relies on the Node `crypto` module. Encryption and decryption happen transparently during save and find.

As of the stable 1.0.0 release, this plugin works on individual fields of any type. However, note that for non-string fields, the original value is set to undefined after encryption. This is because if the schema has defined a field as an array, it would not be possible to replace it with a string value.

Also consider [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) if you have other requirements.

## How it works

Encryption is performed using `AES-256-CTR`. To encrypt, the relevant fields are encrypted with the provided secret and the resulting hex string is put in place of the actual value for `string` values. An extra `boolean` field with the prefix `__enc_` is added to the document which indicates if the provided field is encrypted or not.

Fields which are either objects or of a different type are converted to strings using `JSON.stringify` and the value stored in an extra marker field of type `string` with a naming scheme of `__enc_` as prefix and `_d` as suffix on the original field name. The original field is then set to `undefined`. Please note that this might break any custom validation and application of this plugin on non-string fields needs to be done with care.

## Requirements

- Node `>=4.4.7`
- MongoDB `>=2.6.10`
- Mongoose `>=4.0.0`

## Installation

`npm install mongoose-field-encryption`

## Usage

Keep your secret a secret. Ideally it should only live as an environment variable but definitely not stored anywhere in your repository.

### Basic

For example, given a schema as follows:

```js
const mongoose                = require('mongoose');
const mongooseFieldEncryption = require('mongoose-field-encryption').fieldEncryption;
const Schema                  = mongoose.Schema;

const Post = new Schema({
  title: String,
  message: String,
  references: {
    author: String,
    date: Date
  }
});

Post.plugin(mongooseFieldEncyption, {fields: ['message', 'references'], secret: 'some secret key'});
```

The resulting documents will have the following format:

```js
{
  _id: ObjectId,
  title: String,
  message: String, // encrypted hex value as string
  __enc_message: true, // boolean marking if the field is encrypted or not
  references: undefined, // encrypted object set to undefined
  __enc_references: true, // boolean marking if the field is encrypted or not
  __enc_references_d: String // encrypted hex object value as string
}
```

`find` works transparently and you can make new documents as normal, but you should not use the `lean` option on a find if you want the fields of the document to be decrypted. `findOne`, `findById` and `save` also all work as normal. `update` works _only for string fields_ and you would also need to manually set the `__enc_` field value to false if you're updating an encrypted field.

From the mongoose package documentation: _Note that findAndUpdate/Remove do not execute any hooks or validation before making the change in the database. If you need hooks and validation, first query for the document and then save it._

Also note that if you manually set the value `__enc_` prefix field to true then the encryption is not run on the corresponding field and this may result in the plain value being stored in the db.

### Required options

- `fields`: an array list of the required fields
- `secret`: a string cipher which is used to encrypt the data (don't lose this!)

### Static methods

For performance reasons, once the document has been encrypted, it remains so. The following methods are thus added to the schema:

- `encryptFieldsSync()`: synchronous call that encrypts all fields as given by the plugin options
- `decryptFieldsSync()`: synchronous call that decrypts encrypted fields as given by the plugin options
- `stripEncryptionFieldMarkers()`: synchronous call that removes the encryption field markers (useful for returning documents without letting the user know that something was encrypted)

Multiple calls to the above methods have no effect, i.e. once a field is encrypted and the `__enc_` marker field value is set to true then the ecrypt operation is ignored. Same for the decrypt operation. Of course if the field markers have been removed via the `stripEncryptionFieldMarkers()` call, then the encryption will be executed if invoked.

### Searching

To enable searching over the encrypted fields the `encrypt` and `decrypt` methods have also been exposed.

```js
const fieldEncryption = require('mongoose-field-encryption')
const encrypted = fieldEncryption.encrypt('some text', 'secret'));
const decrypted = fieldEncryption.decrypt(encrypted, 'secret')); // decrypted = 'some text'
```

## Testing

1. Install dependencies with `npm install` and [install mongo](http://docs.mongodb.org/manual/installation/) if you don't have it yet.
2. Start mongo with `mongod`.
3. Run tests with `npm test`. Additionally you can pass your own mongodb uri as an environment variable if you would like to test against your own database, for e.g. `URI='mongodb://username:password@127.0.0.1:27017/mongoose-field-encryption-test' npm test`

## Publishing

- `npm version patch,minor,major`
- `npm publish`

## Changelog

### 1.1.0

- Added support for mongoose 5 [https://github.com/victorparmar/mongoose-field-encryption/pull/16](https://github.com/victorparmar/mongoose-field-encryption/pull/16).
- Removed mongoose dependency, moved to `peerDependencies`.
- Formatted source code using prettier.
