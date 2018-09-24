"use strict";

const crypto = require("crypto");

const algorithm = "aes-256-cbc";
const deprecatedAlgorithm = "aes-256-ctr";
const encryptedFieldNamePrefix = "__enc_";
const encryptedFieldDataSuffix = "_d";

const encryptAes256Ctr = function(text, secret) {
  const cipher = crypto.createCipher(deprecatedAlgorithm, secret);
  let crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};

const decryptAes256Ctr = function(encryptedHex, secret) {
  const decipher = crypto.createDecipher(deprecatedAlgorithm, secret);
  let dec = decipher.update(encryptedHex, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
};

const encrypt = function(clearText, secret) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, secret, iv);
  const encrypted = cipher.update(clearText);
  const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
  const encryptedHex = iv.toString("hex") + ":" + finalBuffer.toString("hex");
  return encryptedHex;
};

/**
 * Decryption has a default fallback for the deprecated algorithm
 *
 * @param {*} encryptedHex
 * @param {*} secret
 */
const decrypt = function(encryptedHex, secret) {
  const encryptedArray = encryptedHex.split(":");

  // maintain backwards compatibility
  if (encryptedArray.length === 1) {
    return decryptAes256Ctr(encryptedArray[0], secret);
  }

  const iv = new Buffer.from(encryptedArray[0], "hex");
  const encrypted = new Buffer.from(encryptedArray[1], "hex");
  const decipher = crypto.createDecipheriv(algorithm, secret, iv);
  const decrypted = decipher.update(encrypted);
  const clearText = Buffer.concat([decrypted, decipher.final()]).toString();
  return clearText;
};

const fieldEncryption = function(schema, options) {
  if (!options || !options.secret) {
    throw new Error("missing required secret");
  }

  const useAes256Ctr = options.useAes256Ctr || false;
  const fieldsToEncrypt = options.fields || [];

  const hash = crypto.createHash("sha256");
  hash.update(options.secret);

  const secret = useAes256Ctr ? options.secret : hash.digest("hex").substring(0, 32);
  const encryptionStrategy = useAes256Ctr ? encryptAes256Ctr : encrypt;

  // add marker fields to schema
  for (let field of fieldsToEncrypt) {
    const encryptedFieldName = encryptedFieldNamePrefix + field;
    const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
    const schemaField = {};

    schemaField[encryptedFieldName] = { type: Boolean };
    schemaField[encryptedFieldData] = { type: String };
    schema.add(schemaField);
  }

  //
  // local methods
  //

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

  function encryptFields(obj, fields, secret) {
    for (let field of fields) {
      const encryptedFieldName = encryptedFieldNamePrefix + field;
      const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;
      const fieldValue = obj[field];

      if (!obj[encryptedFieldName] && fieldValue) {
        if (typeof fieldValue === "string") {
          // handle strings separately to maintain searchability
          const value = encryptionStrategy(fieldValue, secret);
          obj[field] = value;
        } else {
          const value = encryptionStrategy(JSON.stringify(fieldValue), secret);
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

      if (obj[encryptedFieldName]) {
        if (obj[encryptedFieldData]) {
          const encryptedValue = obj[encryptedFieldData];

          obj[field] = JSON.parse(decrypt(encryptedValue, secret));
          obj[encryptedFieldName] = false;
          obj[encryptedFieldData] = "";
        } else {
          // handle strings separately to maintain searchability
          const encryptedValue = obj[field];

          obj[field] = decrypt(encryptedValue, secret);
          obj[encryptedFieldName] = false;
        }
      }
    }
  }

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
          const encryptedData = encryptionStrategy(plainTextValue, secret);

          updateObj[field] = encryptedData;
          updateObj[encryptedFieldName] = true;
        } else {
          const encryptedFieldData = encryptedFieldName + encryptedFieldDataSuffix;

          updateObj[field] = undefined;
          updateObj[encryptedFieldData] = encryptionStrategy(JSON.stringify(plainTextValue), secret);
          updateObj[encryptedFieldName] = true;
        }
        this.update({}, Object.keys(this._update.$set).length > 0 ? { $set: updateObj } : updateObj);
      }
    }

    next();
  }

  //
  // static methods
  //

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

  //
  // hooks
  //

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

  schema.pre("findOneAndUpdate", updateHook);

  schema.pre("update", updateHook);
};

module.exports.fieldEncryption = fieldEncryption;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
module.exports.encryptAes256Ctr = encryptAes256Ctr;
