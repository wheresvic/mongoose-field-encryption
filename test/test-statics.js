"use strict";

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
    secret: "letsdothis" // should ideally be process.env.SECRET
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
    expect(sut.toEncrypt1).to.equal("b27d5768b82263ece8bd");

    expect(sut.__enc_toEncrypt2).to.be.true;
    expect(sut.toEncrypt2).to.equal("b27a5578f43537fbebfb2e365ab13977");

    expect(sut.__enc_toEncryptObject).to.be.true;
    expect(sut.__enc_toEncryptObject_d).to.equal("ba305468eb2572fdace164315ba6287c6f4181");
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

    // when
    sut.encryptFieldsSync();
    sut.encryptFieldsSync();

    // then
    expect(sut.noEncrypt).to.equal("clear");
    expect(sut.__enc_noEncrypt).to.be.undefined;

    expect(sut.__enc_toEncrypt1).to.be.true;
    expect(sut.toEncrypt1).to.equal("b27d5768b82263ece8bd");

    expect(sut.__enc_toEncrypt2).to.be.true;
    expect(sut.toEncrypt2).to.equal("b27a5578f43537fbebfb2e365ab13977");

    expect(sut.__enc_toEncryptObject).to.be.true;
    expect(sut.__enc_toEncryptObject_d).to.equal("ba305468eb2572fdace164315ba6287c6f4181");
    expect(sut.toObject().toEncryptObject).to.be.undefined;
  });

  it("should decrypt fields", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
      noEncrypt: "clear",
      toEncrypt1: "b27d5768b82263ece8bd",
      __enc_toEncrypt1: true,
      toEncrypt2: "b27a5578f43537fbebfb2e365ab13977",
      __enc_toEncrypt2: true,
      __enc_toEncryptObject: true,
      __enc_toEncryptObject_d: "ba305468eb2572fdace164315ba6287c6f4181"
    });

    // when
    sut.decryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.false;
    expect(sut.toEncrypt1).to.equal("some stuff");

    expect(sut.__enc_toEncrypt2).to.be.false;
    expect(sut.toEncrypt2).to.equal("should be hidden");

    expect(sut.__enc_toEncryptObject).to.be.false;
    expect(sut.__enc_toEncryptObject_d).to.equal("");
    expect(JSON.stringify(sut.toEncryptObject)).to.equal('{"nested":"nested"}');
  });

  it("should ignore multiple decrypt field calls", () => {
    // given
    let sut = new FieldEncryptionStaticsTest({
      noEncrypt: "clear",
      toEncrypt1: "b27d5768b82263ece8bd",
      __enc_toEncrypt1: true,
      toEncrypt2: "b27a5578f43537fbebfb2e365ab13977",
      __enc_toEncrypt2: true,
      __enc_toEncryptObject: true,
      __enc_toEncryptObject_d: "ba305468eb2572fdace164315ba6287c6f4181"
    });

    // when
    sut.decryptFieldsSync();
    sut.decryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.false;
    expect(sut.toEncrypt1).to.equal("some stuff");

    expect(sut.__enc_toEncrypt2).to.be.false;
    expect(sut.toEncrypt2).to.equal("should be hidden");

    expect(sut.__enc_toEncryptObject).to.be.false;
    expect(sut.__enc_toEncryptObject_d).to.equal("");
    expect(JSON.stringify(sut.toEncryptObject)).to.equal('{"nested":"nested"}');
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
