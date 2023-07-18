"use strict";
const expect = require("chai").expect;
const mongoose = require("mongoose");
const Promise = require("bluebird");

mongoose.Promise = Promise;
mongoose.set("bufferCommands", false);

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("Test fieldEncryption options behaviour", function () {
  before(function (done) {

    done();
  });

  it("Demonstrate notifyDecryptFails: false - inhibit error, and return empty value", function (done) {
    const FieldEncryptionSchema = new mongoose.Schema({
      noEncrypt: { type: String },
      toEncrypt1: { type: String },
      toEncrypt2: { type: String },
    });

    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
      fields: ["toEncrypt1", "toEncrypt2"],
      secret: "letsdothis",
      notifyDecryptFails: false,
    });

    const FieldEncryptionOptionsTest1 = mongoose.model("FieldEncryptionOptionsTest1", FieldEncryptionSchema);
    // given
    const sut = new FieldEncryptionOptionsTest1({
      noEncrypt: "clear",
      toEncrypt1: "some stuff",
      toEncrypt2: "after exception",
    });

    // when
    sut.encryptFieldsSync();
    sut.toEncrypt1 = sut.toEncrypt1.substring(0, sut.toEncrypt1.length - 1);

    // then
    sut.decryptFieldsSync();
    expect(sut.noEncrypt).to.equal("clear");
    expect(sut.__enc_noEncrypt).to.be.undefined;

    expect(sut.__enc_toEncrypt1).to.be.false;
    expect(sut.toEncrypt1).to.eql("");

    expect(sut.__enc_toEncrypt2).to.be.false;
    expect(sut.toEncrypt2).to.eql("after exception");
    done();
  });
  
  it("Demonstrate notifyDecryptFails: true (default) - throw error", function (done) {
    const FieldEncryptionSchema = new mongoose.Schema({
      noEncrypt: { type: String },
      toEncrypt1: { type: String },
      toEncrypt2: { type: String },
    });

    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
      fields: ["toEncrypt1", "toEncrypt2"],
      secret: "letsdothis",
    });

    const FieldEncryptionOptionsTest2 = mongoose.model("FieldEncryptionOptionsTest2", FieldEncryptionSchema);
    // given
    const sut = new FieldEncryptionOptionsTest2({
      noEncrypt: "clear",
      toEncrypt1: "some stuff",
      toEncrypt2: "after exception",
    });

    // when
    sut.encryptFieldsSync();
    sut.toEncrypt1 = sut.toEncrypt1.substring(0, sut.toEncrypt1.length - 1);

    // then
    try {
    sut.decryptFieldsSync();
    } catch (err) {
      console.log(err);
      expect(err.reason).to.equal("wrong final block length");
      done();
      return;
    }

    done(new Error("should have thrown an exception"));
  });
});
