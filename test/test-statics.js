"use strict";

const sinon = require('sinon');
const crypto = require('crypto');
const expect = require("chai").expect;

const Promise = require("bluebird");
const mongoose = require("mongoose");
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("mongoose-field-encryption plugin static methods", () => {
  let FieldEncryptionSchema = new mongoose.Schema({
    noEncrypt: { type: String, required: true },
    toEncrypt1: { type: String, required: true },
    toEncrypt2: { type: String, required: true },
    toEncryptObject: {
      nested: { type: String }
    }
  });

  FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
    fields: ["toEncrypt1", "toEncrypt2", "toEncryptObject"],
    secret: "icanhazcheezburger" // should ideally be process.env.SECRET
  });

  let FieldEncryptionStaticsTest = mongoose.model("FieldEncryptionStaticsTest", FieldEncryptionSchema);

  it("should encrypt fields", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
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
  });

  it("should not encrypt already encrypted fields", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
      noEncrypt: "clear",
      toEncrypt1: "some stuff",
      toEncrypt2: "should be hidden",
      toEncryptObject: {
        nested: "nested"
      }
    });
    const createCipherivSpy = sinon.spy(crypto, 'createCipheriv');

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

  it("should decrypt fields", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
      noEncrypt: "clear",
      toEncrypt1: "test",
      toEncrypt2: "test2",
      toEncryptObject: {
        nested: "test3"
      }
    });
    sut.encryptFieldsSync();
    expect(sut.toEncrypt1).not.to.eql('test');
    expect(sut.toEncrypt2).not.to.eql('test2');

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

  it("should ignore multiple decrypt field calls", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
      noEncrypt: "clear",
      toEncrypt1: "test",
      toEncrypt2: "test2",
      toEncryptObject: {
        nested: "test3"
      }
    });
    sut.encryptFieldsSync();
    const createDecipherivSpy = sinon.spy(crypto, 'createDecipheriv');

    // when
    sut.decryptFieldsSync();
    const decryptionCount = createDecipherivSpy.callCount;
    sut.decryptFieldsSync();
    const decryptionCountAfterTwoDecryptFieldCalls = createDecipherivSpy.callCount;

    // then
    expect(decryptionCount).to.eql(3);
    expect(decryptionCountAfterTwoDecryptFieldCalls)
  });

  it("should strip encryption field markers", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
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
