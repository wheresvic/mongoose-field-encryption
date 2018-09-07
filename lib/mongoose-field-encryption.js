"use strict";

const crypto = require("crypto");

const algorithm = "aes-256-ctr";
const encryptedFieldNamePrefix = "__enc_";
const encryptedFieldDataSuffix = "_d";

const encrypt = function(text, secret) {
  let cipher = crypto.createCipher(algorithm, secret);
  let crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};

const decrypt = function(text, secret) {
  var decipher = crypto.createDecipher(algorithm, secret);
  var dec = decipher.update(text, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
};

const fieldEncryption = function(schema, options) {
  if (!options || !options.secret) {
    throw new Error("missing required secret");
  }

  const fieldsToEncrypt = options.fields || [];
  const secret = options.secret;

  // for mongoose 4/5 compatibility
  const defaultNext = function defaultNext(err) {
    if (err) {
      throw err;
    }
  };
  function getCompatitibleNextFunc(next) {
    if (typeof next !== "function") {
      return defaultNext;
    }
    return next;
  }
  function getCompatibleData(next, data) {
    // in mongoose5, 'data' field is undefined
    if (!data) {
      return next;
    }
    return data;
  }

  // add marker fields to schema
  for (let field of fieldsToEncrypt) {
    const encryptedFieldName = encryptedFieldNamePrefix + field;
    const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
    const schemaField = {};

    schemaField[encryptedFieldName] = { type: Boolean };
    schemaField[encryptedFieldData] = { type: String };
    schema.add(schemaField);
  }

  function encryptFields(obj, fields, secret) {
    for (let field of fields) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
      const fieldValue = obj[field];

      if (!obj[encryptedFieldName] && fieldValue) {
        if (typeof fieldValue === "string") {
          // handle strings separately to maintain searchability
          const value = encrypt(fieldValue, secret);
          obj[field] = value;
        } else {
          const value = encrypt(JSON.stringify(fieldValue), secret);
          obj[field] = undefined;
          obj[encryptedFieldData] = value;
        }

        obj[encryptedFieldName] = true;
      }
    }
  }

  function decryptFields(obj, fields, secret) {
    for (let field of fields) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

      if (obj[encryptedFieldData]) {
        const encryptedValue = obj[encryptedFieldData];

        obj[field] = JSON.parse(decrypt(encryptedValue, secret));
        obj[encryptedFieldName] = false;
        obj[encryptedFieldData] = "";
      } else if (obj[encryptedFieldName]) {
        // handle strings separately to maintain searchability
        const encryptedValue = obj[field];

        obj[field] = decrypt(encryptedValue, secret);
        obj[encryptedFieldName] = false;
      }
    }
  }

  schema.pre("init", function(_next, _data) {
    const next = getCompatitibleNextFunc(_next);
    const data = getCompatibleData(_next, _data);
    try {
      decryptFields(data, fieldsToEncrypt, secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  schema.pre("save", function(_next) {
    const next = getCompatitibleNextFunc(_next);

    try {
      encryptFields(this, fieldsToEncrypt, secret);
      next();
    } catch (err) {
      next(err);
    }
  });

  function updateHook(_next) {
    const next = getCompatitibleNextFunc(_next);
    for (let field of fieldsToEncrypt) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      this._update.$set = this._update.$set || {};
      const plainTextValue = this._update.$set[field] || this._update[field];
      const encryptedFieldValue = this._update.$set[encryptedFieldName] || this._update[encryptedFieldName];

      if (!encryptedFieldValue && plainTextValue) {
        let updateObj = {};
        if (typeof plainTextValue === "string" || plainTextValue instanceof String) {
          const encryptedData = encrypt(plainTextValue, secret);

          updateObj[field] = encryptedData;
          updateObj[encryptedFieldName] = true;
        } else {
          const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

          updateObj[field] = undefined;
          updateObj[encryptedFieldData] = encrypt(JSON.stringify(plainTextValue), secret);
          updateObj[encryptedFieldName] = true;
        }
        this.update({}, Object.keys(this._update.$set) > 0 ? { $set: updateObj } : updateObj);
      }
    }

    next();
  }

  schema.pre("findOneAndUpdate", updateHook);

  schema.pre("update", updateHook);

  schema.methods.stripEncryptionFieldMarkers = function() {
    for (let field of fieldsToEncrypt) {
      let encryptedFieldName = encryptedFieldNamePrefix + field;
      let encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

      this.set(encryptedFieldName, undefined);
      this.set(encryptedFieldData, undefined);
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
