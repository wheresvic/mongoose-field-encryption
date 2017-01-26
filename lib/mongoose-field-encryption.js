'use strict';

const crypto = require('crypto');

const algorithm = 'aes-256-ctr';
const encryptedFieldNamePrefix = '__enc_';

const encrypt = function(text, secret) {
  let cipher = crypto.createCipher(algorithm, secret)
  let crypted = cipher.update(text, 'utf8', 'hex')
  crypted += cipher.final('hex');
  return crypted;
};

const decrypt = function(text, secret) {
  var decipher = crypto.createDecipher(algorithm, secret)
  var dec = decipher.update(text, 'hex', 'utf8')
  dec += decipher.final('utf8');
  return dec;
};

const fieldEncryption = function(schema, options) {

  if (!options || !options.secret) {
    throw new Error('missing required secret');
  }

  const fieldsToEncrypt = options.fields || [];
  const secret = options.secret;

  // add marker fields to schema
  for (let field of fieldsToEncrypt) {
    let encryptedFieldName = encryptedFieldNamePrefix + field;
    let schemaField = {};
    schemaField[encryptedFieldName] = { type: Boolean };
    schema.add(schemaField);
  }

  function encryptFields(obj, fields, secret) {
    for (let field of fields) {
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      let plainValue = obj[field];

      if (!obj[encryptedFieldName] && plainValue) {
        if (typeof plainValue === 'string') {
          //String
          let value = encrypt(plainValue, secret);

          obj[field] = value;
          obj[encryptedFieldName] = true;
        } else if (typeof plainValue === 'object') {
          //Object
          let value = encrypt(JSON.stringify(plainValue), secret);

          obj[field] = value;
          obj[encryptedFieldName] = true;
        } else {
          throw new Error('Cannot encrypt non string field');
        }
      }
    }
  };

  function decryptFields(obj, fields, secret) {
    for (let field of fields) {
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedValue = obj[field];

      if (obj[encryptedFieldName]) {
        if (typeof encryptedValue === 'string') {
          //String
          obj[field] = decrypt(encryptedValue, secret);
          obj[encryptedFieldName] = false;
        } else if (typeof encryptedValue === 'object') {
          //Object
          obj[field] = JSON.parse(decrypt(encryptedValue, secret));
          obj[encryptedFieldName] = false;
        } else {
          throw new Error('Cannot decrypt non string field');
        }
      }
    }
  };

  schema.pre('init', function(next, data) {
    try {
      decryptFields(data, fieldsToEncrypt, secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre('save', function(next) {
    try {
      encryptFields(this, fieldsToEncrypt, secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre('update', function(next) {

    for (let field of fieldsToEncrypt) {

      let encryptedFieldName = encryptedFieldNamePrefix + field;
      let encryptedFieldValue = this._update.$set[encryptedFieldName];
      let plainTextValue = this._update.$set[field];

      if (encryptedFieldValue === false && plainTextValue) {
        if (typeof plainTextValue === 'string' || plainTextValue instanceof String) {
          let updateObj = { $set: {} };
          updateObj.$set[field] = encrypt(plainTextValue, secret);
          updateObj.$set[encryptedFieldName] = true;
          this.update({}, updateObj);
        } else {
          return next(new Error('Cannot encrypt non string field'));
        }
      }
    }

    next();
  });

  schema.methods.stripEncryptionFieldMarkers = function() {
    for (let field of fieldsToEncrypt) {
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      this.set(encryptedFieldName, undefined);
    }
  };

  schema.methods.decryptFieldsSync = function() {
    decryptFields(this, fieldsToEncrypt, secret);
  };

  schema.methods.encryptFieldsSync = function() {
    encryptFields(this, fieldsToEncrypt, secret);
  };

};

module.exports.fieldEncryption = fieldEncryption;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
