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

module.exports = function fieldEncryption(schema, options) {

  // add marker fields to schema
  for (let field of options.fields) {
    let encryptedFieldName = encryptedFieldNamePrefix + field;
    let schemaField = {};
    schemaField[encryptedFieldName] = { type: Boolean };
    schema.add(schemaField);
  }

  function encryptFields(obj, fields, secret) {
    for (let field of fields) {
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      let plainTextValue = obj[field];

      if (!obj[encryptedFieldName] && plainTextValue) {
        if (typeof plainTextValue === 'string' || plainTextValue instanceof String) {
          let value = encrypt(obj[field], secret);
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

      if (obj[encryptedFieldName]) {
        obj[field] = decrypt(obj[field], secret);
        obj[encryptedFieldName] = false;
      }
    }
  };

  schema.pre('init', function(next, data) {
    try {
      decryptFields(data, options.fields, options.secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre('save', function(next) {
    try {
      encryptFields(this, options.fields, options.secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre('update', function(next) {
    
    for (let field of options.fields) {
      
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      let encryptedFieldValue = this._update.$set[encryptedFieldName];
      let plainTextValue = this._update.$set[field];

      if (encryptedFieldValue === false && plainTextValue) {
        if (typeof plainTextValue === 'string' || plainTextValue instanceof String) {
          let updateObj = { $set: {} };
          updateObj.$set[field] = encrypt(plainTextValue, options.secret);
          updateObj.$set[encryptedFieldName] = true;
          this.update({}, updateObj);
        } else {
          return next(new Error('Cannot encrypt non string field'));
        }
      }
    }

    next();
  });

  schema.methods.decryptFieldsSync = function() {
    decryptFields(this, options.fields, options.secret);
  };

  schema.methods.encryptFieldsSync = function() {
    encryptFields(this, options.fields, options.secret);
  };

};
