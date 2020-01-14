"use strict";

const sinon = require("sinon");
const crypto = require("crypto");
const expect = require("chai").expect;

const Promise = require("bluebird");
const mongoose = require("mongoose");
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("mongoose-field-encryption plugin static methods", function() {
  describe("aes-256-cbc", function() {
    const FieldEncryptionSchema = new mongoose.Schema({
      noEncrypt: { type: String, required: true },
      toEncrypt1: { type: String, required: true },
      toEncrypt2: { type: String, required: true },
      toEncryptObject: {
        nested: { type: String }
      }
    });

    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
      fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
      secret: "letsdothis" // should ideally be process.env.SECRET
    });

    const FieldEncryptionStaticsTest = mongoose.model("FieldEncryptionStaticsTest", FieldEncryptionSchema);

    it("should encrypt fields", function() {
      // given
      const sut = new FieldEncryptionStaticsTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      sut.encryptFieldsSync();

      // then
      expect(sut.noEncrypt).to.equal("clear");
      expect(sut.__enc_noEncrypt).to.be.undefined;

      expect(sut.__enc_toEncrypt1).to.be.true;
      expect(sut.toEncrypt1).to.not.eql("some stuff");

      expect(sut.__enc_toEncrypt2).to.be.true;
      expect(sut.toEncrypt2).to.not.eql("should be hidden");

      expect(sut.__enc_toEncryptObject).to.be.true;
      expect(sut.toObject().toEncryptObject).to.be.undefined;

      sut.decryptFieldsSync();
      expect(sut.__enc_toEncrypt1).to.be.false;
      expect(sut.noEncrypt).to.eql("clear");
      expect(sut.toEncrypt1).to.eql("some stuff");
      expect(sut.toEncrypt2).to.eql("should be hidden");
      expect(sut.toEncryptObject.nested).to.eql("nested");
    });

    it("should not encrypt already encrypted fields", function() {
      // given
      const sut = new FieldEncryptionStaticsTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      const createCipherivSpy = sinon.spy(crypto, "createCipheriv");

      // when
      sut.encryptFieldsSync();
      const encryptedFieldCount = createCipherivSpy.callCount;
      sut.encryptFieldsSync();
      const encryptedFieldCountAfterTwoEncryptFieldCalls = createCipherivSpy.callCount;

      // then
      expect(encryptedFieldCount).to.eql(3);
      expect(encryptedFieldCountAfterTwoEncryptFieldCalls).to.eql(3);
      createCipherivSpy.restore();
    });

    it("should decrypt fields", function() {
      // given
      const sut = new FieldEncryptionStaticsTest({
        noEncrypt: "clear",
        toEncrypt1: "test",
        toEncrypt2: "test2",
        toEncryptObject: {
          nested: "test3"
        }
      });
      
      sut.encryptFieldsSync();
      expect(sut.toEncrypt1).not.to.eql("test");
      expect(sut.toEncrypt2).not.to.eql("test2");

      // when
      sut.decryptFieldsSync();

      // then
      expect(sut.__enc_toEncrypt1).to.be.false;
      expect(sut.toEncrypt1).to.equal("test");

      expect(sut.__enc_toEncrypt2).to.be.false;
      expect(sut.toEncrypt2).to.equal("test2");

      expect(sut.__enc_toEncryptObject).to.be.false;
      expect(sut.__enc_toEncryptObject_d).to.equal("");
      expect(sut.toEncryptObject.nested).to.equal("test3");
    });

    it("should ignore multiple decrypt field calls", function() {
      // given
      const sut = new FieldEncryptionStaticsTest({
        noEncrypt: "clear",
        toEncrypt1: "test",
        toEncrypt2: "test2",
        toEncryptObject: {
          nested: "test3"
        }
      });

      sut.encryptFieldsSync();
      const createDecipherivSpy = sinon.spy(crypto, "createDecipheriv");

      // when
      sut.decryptFieldsSync();
      const decryptionCount = createDecipherivSpy.callCount;
      sut.decryptFieldsSync();
      const decryptionCountAfterTwoDecryptFieldCalls = createDecipherivSpy.callCount;

      // then
      expect(decryptionCount).to.eql(3);
      expect(decryptionCountAfterTwoDecryptFieldCalls);
    });

    it("should strip encryption field markers", function() {
      // given
      const sut = new FieldEncryptionStaticsTest({
        noEncrypt: "clear",
        toEncrypt1: "blah",
        __enc_toEncrypt1: false,
        toEncrypt2: "yo",
        __enc_toEncrypt2: false,
        toEncryptObject: {
          nested: "nested"
        },
        __enc_toEncryptObject: false,
        __enc_toEncryptObject_d: ""
      });

      // when
      sut.stripEncryptionFieldMarkers();

      // then
      expect(sut.__enc_toEncrypt1).to.be.undefined;
      expect(sut.toEncrypt1).to.equal("blah");

      expect(sut.__enc_toEncrypt2).to.be.undefined;
      expect(sut.toEncrypt2).to.equal("yo");

      expect(sut.__enc_toEncryptObject).to.be.undefined;
      expect(sut.__enc_toEncryptObject_d).to.be.undefined;
      expect(JSON.stringify(sut.toEncryptObject)).to.equal('{"nested":"nested"}');
    });
  });

  describe("aes-256-cbc with custom salt", function() {
    it("should encrypt with a custom string salt", function() {
      // given
      const FieldEncryptionEncryptCustomSaltStringSchema = new mongoose.Schema({
        noEncrypt: { type: String, required: true },
        toEncrypt1: { type: String, required: true },
        toEncrypt2: { type: String, required: true },
        toEncryptObject: {
          nested: { type: String }
        }
      });

      FieldEncryptionEncryptCustomSaltStringSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
        secret: "letsdothis", // should ideally be process.env.SECRET
        saltGenerator: function(secret) {
          return "1234567890123456";
        }
      });

      const FieldEncryptionEncryptCustomSaltStringTest = mongoose.model(
        "FieldEncryptionEncryptCustomSaltStringTest",
        FieldEncryptionEncryptCustomSaltStringSchema
      );

      const sut = new FieldEncryptionEncryptCustomSaltStringTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      sut.encryptFieldsSync();

      // then
      expect(sut.noEncrypt).to.equal("clear");
      expect(sut.__enc_noEncrypt).to.be.undefined;

      expect(sut.__enc_toEncrypt1).to.be.true;
      expect(sut.toEncrypt1).to.equal("31323334353637383930313233343536:5c568b1a61b7d1c61d93ce7523d29007");

      expect(sut.__enc_toEncrypt2).to.be.true;
      expect(sut.toEncrypt2).to.equal(
        "31323334353637383930313233343536:2c81e40fc9c00edc33c857a0720fb9c50b5865f803dad888f251478ffa60135d"
      );

      expect(sut.__enc_toEncryptObject).to.be.true;
      expect(sut.__enc_toEncryptObject_d).to.equal(
        "31323334353637383930313233343536:d95f119990acab8c08f82a6b1c49ff856e6049d29ca1f96a794923c28d8e5baa"
      );

      sut.decryptFieldsSync();
      expect(sut.__enc_toEncrypt1).to.be.false;
      expect(sut.noEncrypt).to.eql("clear");
      expect(sut.toEncrypt1).to.eql("some stuff");
      expect(sut.toEncrypt2).to.eql("should be hidden");
      expect(sut.toEncryptObject.nested).to.eql("nested");
    });

    it("should decrypt with a custom string salt", function() {
      // given
      const FieldEncryptionDecryptCustomSaltStringSchema = new mongoose.Schema({
        noEncrypt: { type: String, required: true },
        toEncrypt1: { type: String, required: true },
        toEncrypt2: { type: String, required: true },
        toEncryptObject: {
          nested: { type: String }
        }
      });

      FieldEncryptionDecryptCustomSaltStringSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
        secret: "letsdothis", // should ideally be process.env.SECRET
        saltGenerator: function(secret) {
          return "1234567890123456";
        }
      });

      const FieldEncryptionDecryptCustomSaltStringTest = mongoose.model(
        "FieldEncryptionDecryptCustomSaltStringTest",
        FieldEncryptionDecryptCustomSaltStringSchema
      );

      const sut = new FieldEncryptionDecryptCustomSaltStringTest({
        _id: "5c73c4f17841f3557c130bab",
        noEncrypt: "clear",
        toEncrypt1: "31323334353637383930313233343536:5c568b1a61b7d1c61d93ce7523d29007",
        toEncrypt2: "31323334353637383930313233343536:2c81e40fc9c00edc33c857a0720fb9c50b5865f803dad888f251478ffa60135d",
        __enc_toEncrypt1: true,
        __enc_toEncrypt2: true,
        __enc_toEncryptObject_d:
          "31323334353637383930313233343536:d95f119990acab8c08f82a6b1c49ff856e6049d29ca1f96a794923c28d8e5baa",
        __enc_toEncryptObject: true
      });

      // when
      sut.decryptFieldsSync();

      // then
      expect(sut.__enc_toEncrypt1).to.be.false;
      expect(sut.noEncrypt).to.eql("clear");
      expect(sut.toEncrypt1).to.eql("some stuff");
      expect(sut.toEncrypt2).to.eql("should be hidden");
      expect(sut.toEncryptObject.nested).to.eql("nested");
    });

    it("should throw an error when encrypting fields with an invalid custom string salt", function() {
      // given
      const FieldEncryptionCustomSaltBadStringSchema = new mongoose.Schema({
        noEncrypt: { type: String, required: true },
        toEncrypt1: { type: String, required: true },
        toEncrypt2: { type: String, required: true },
        toEncryptObject: {
          nested: { type: String }
        }
      });

      FieldEncryptionCustomSaltBadStringSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
        secret: "letsdothis", // should ideally be process.env.SECRET
        saltGenerator: function(secret) {
          return "123456789012345"; // only 15 chars
        }
      });

      const FieldEncryptionCustomSaltBadStringTest = mongoose.model(
        "FieldEncryptionCustomSaltBadStringTest",
        FieldEncryptionCustomSaltBadStringSchema
      );

      const sut = new FieldEncryptionCustomSaltBadStringTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      try {
        sut.encryptFieldsSync();
      } catch (err) {
        // then
        if (err.message && err.message === "Invalid salt, please ensure that the salt is a string of length 16") {
          return;
        }
      }

      throw new Error("Should not have encrypted using a bad iv");
    });

    it("should throw an error when encrypting fields with an invalid custom buffer salt", function() {
      // given
      const FieldEncryptionCustomSaltBadBufferSchema = new mongoose.Schema({
        noEncrypt: { type: String, required: true },
        toEncrypt1: { type: String, required: true },
        toEncrypt2: { type: String, required: true },
        toEncryptObject: {
          nested: { type: String }
        }
      });

      FieldEncryptionCustomSaltBadBufferSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
        secret: "letsdothis", // should ideally be process.env.SECRET
        saltGenerator: function(secret) {
          return crypto.randomBytes(200);
        }
      });

      const FieldEncryptionCustomSaltBadBufferTest = mongoose.model(
        "FieldEncryptionCustomSaltBadBufferTest",
        FieldEncryptionCustomSaltBadBufferSchema
      );

      const sut = new FieldEncryptionCustomSaltBadBufferTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      try {
        sut.encryptFieldsSync();
      } catch (err) {
        // then
        if (
          err.message &&
          err.message === "Invalid salt provided, please ensure that the salt is a Buffer of length 16"
        ) {
          return;
        }
      }

      throw new Error("Should not have encrypted using a bad iv");
    });

    it("should throw an error when encrypting fields with an invalid custom salt", function() {
      // given
      const FieldEncryptionCustomBadSaltSchema = new mongoose.Schema({
        noEncrypt: { type: String, required: true },
        toEncrypt1: { type: String, required: true },
        toEncrypt2: { type: String, required: true },
        toEncryptObject: {
          nested: { type: String }
        }
      });

      FieldEncryptionCustomBadSaltSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
        secret: "letsdothis", // should ideally be process.env.SECRET
        saltGenerator: function(secret) {
          return { salt: secret };
        }
      });

      const FieldEncryptionCustomBadSaltTest = mongoose.model(
        "FieldEncryptionCustomBadSaltTest",
        FieldEncryptionCustomBadSaltSchema
      );

      const sut = new FieldEncryptionCustomBadSaltTest({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      try {
        sut.encryptFieldsSync();
      } catch (err) {
        // then
        if (
          err.message &&
          err.message === "Invalid salt, please ensure that the salt is either a string or a Buffer of length 16"
        ) {
          return;
        }
      }

      throw new Error("Should not have encrypted using a bad iv");
    });
  });

  describe("aes-256-ctr (deprecated)", function() {
    const FieldEncryptionSchemaDeprecated = new mongoose.Schema({
      noEncrypt: { type: String, required: true },
      toEncrypt1: { type: String, required: true },
      toEncrypt2: { type: String, required: true },
      toEncryptObject: {
        nested: { type: String }
      }
    });

    FieldEncryptionSchemaDeprecated.plugin(fieldEncryptionPlugin, {
      fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
      secret: "letsdothis", // should ideally be process.env.SECRET
      useAes256Ctr: true
    });

    const FieldEncryptionStaticsTestDeprecated = mongoose.model(
      "FieldEncryptionStaticsTestDeprecated",
      FieldEncryptionSchemaDeprecated
    );

    it("should encrypt and decrypt fields", function() {
      // given
      const sut = new FieldEncryptionStaticsTestDeprecated({
        noEncrypt: "clear",
        toEncrypt1: "some stuff",
        toEncrypt2: "should be hidden",
        toEncryptObject: {
          nested: "nested"
        }
      });

      // when
      sut.encryptFieldsSync();

      // then
      expect(sut.noEncrypt).to.equal("clear");
      expect(sut.__enc_noEncrypt).to.be.undefined;

      expect(sut.__enc_toEncrypt1).to.be.true;
      expect(sut.toEncrypt1).to.eql("b27d5768b82263ece8bd");

      expect(sut.__enc_toEncrypt2).to.be.true;
      expect(sut.toEncrypt2).to.eql("b27a5578f43537fbebfb2e365ab13977");

      expect(sut.__enc_toEncryptObject).to.be.true;
      expect(sut.__enc_toEncryptObject_d).to.eql("ba305468eb2572fdace164315ba6287c6f4181");

      sut.decryptFieldsSync();
      expect(sut.__enc_toEncrypt1).to.be.false;
      expect(sut.noEncrypt).to.eql("clear");
      expect(sut.toEncrypt1).to.eql("some stuff");
      expect(sut.toEncrypt2).to.eql("should be hidden");
      expect(sut.toEncryptObject.nested).to.eql("nested");
    });
  });
});
