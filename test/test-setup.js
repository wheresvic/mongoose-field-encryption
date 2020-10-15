"use strict";

const expect = require("chai").expect;

const Promise = require("bluebird");
const mongoose = require("mongoose");
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("mongoose-field-encryption plugin setup", function() {
  const FieldEncryptionSchema = new mongoose.Schema({
    a: { type: String, required: true }
  });

  it("should not initialize plugin without a secret", function(done) {
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

  it("should initialize plugin without any fields", function(done) {
    // when
    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
      secret: "icanhazcheezburger"
    });

    // then
    done();
  });

  it("should initialize plugin with secret factory function", function(done) {
    // when
    FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
      secret: () => "icanhazcheezburger"
    });

    // then
    done();
  });
});
