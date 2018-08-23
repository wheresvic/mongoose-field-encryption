"use strict";

const expect = require("chai").expect;

const Promise = require("bluebird");
const mongoose = require("mongoose");
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("mongoose-field-encryption plugin setup", () => {
  let FieldEncryptionSchema = new mongoose.Schema({
    a: { type: String, required: true }
  });

  it("should not initialize plugin without a secret", done => {
    try {
      // when
      FieldEncryptionSchema.plugin(fieldEncryptionPlugin);
    } catch (err) {
      // then
      expect(err.message).to.equal("missing required secret");
      return done();
    }

    expect.fail("Should not have initialized plugin");
    done();
  });

  it("should initialize plugin without any fields", done => {
    // when
    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, { secret: "blah" });

    // then
    done();
  });
});
