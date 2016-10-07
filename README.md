# mongoose-field-encryption

[![Build Status](https://travis-ci.org/victorparmar/mongoose-field-encryption.svg?branch=master)](https://travis-ci.org/victorparmar/mongoose-field-encryption)

A simple symmetric encryption plugin for individual fields. The goal of this plugin is to encrypt data but still allow searching over the fields. This plugin relies on the Node `crypto` module. Encryption and decryption happen transparently during save and find. 

At present this plugin only works on fields with string values. Also consider [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) if you have other requirements.

## How it works

Encryption is performed using `AES-256-CTR`. To encrypt, the relevant fields are encrypted with the provided secret and the resulting hex string is put in place of the actual value. An extra `boolean` field with the prefix `__enc_` is added to the document which indicates if the provided field is encrypted or not.

## Requirements

- Node `>=4.4.7`
- MongoDB `>=2.6.10`

## Installation

`npm install mongoose-field-encryption`

## Usage

Keep your secret a secret. Ideally it should only live as an environment variable but definitely not stored anywhere in your repository.

For example, given a schema as follows:
```javascript
let mongoose                = require('mongoose');
let mongooseFieldEncryption = require('mongoose-field-encryption');
let Schema                  = mongoose.Schema;

let Post = new Schema({
  title: String, 
  message: String
});

Post.plugin(mongooseFieldEncyption, {fields: ['message'], secret: 'some secret key'});
```

The resulting documents will have the following format:
```javascript
{
  _id: ObjectId,
  title: String,
  message: String, // encrypted hex value as string
  __enc_message: true // boolean marking if the field is encrypted or not
}
```

`find` works transparently and you can make new documents as normal, but you should not use the `lean` option on a find if you want the fields of the document to be decrypted. `findOne`, `findById` and `save` also all work as normal. `update` works, but you would also need to manually set the `__enc_` field value to false if you're updating an encrypted field. 

From the mongoose documentation: _Note that findAndUpdate/Remove do not execute any hooks or validation before making the change in the database. If you need hooks and validation, first query for the document and then save it._

Also note that if you manually set the value `__enc_` prefix field to true then the encryption is not run on the corresponding field and this may result in the plaintext value being stored in the db.

### Static methods

For performance reasons, once the document has been encrypted, it remains so. The following methods are thus added to the schema:
- `encryptFieldsSync()`: synchronous call that encrypts all fields as given by the plugin options
- `decryptFieldsSync()`: synchronous call that decrypts encrypted fields as given by the plugin options

## Testing

0. Install dependencies with `npm install` and [install mongo](http://docs.mongodb.org/manual/installation/) if you don't have it yet.
1. Start mongo with `mongod`.
2. Run tests with `npm test`. Additionally you can pass your own mongodb uri as an environment variable if you would like to test against your own database, for e.g. `URI='mongodb://username:password@localhost/mongoose-field-encryption-test' npm test`


## TODO

- add support for nested fields

