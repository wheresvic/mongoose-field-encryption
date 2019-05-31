"use strict";

const crypto = require("crypto");
const expect = require("chai").expect;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

mongoose.set("bufferCommands", false);

const mongooseFieldEncryption = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("basic usage", function() {
  this.timeout(5000);

  before(() => {
    return mongoose.connect("mongodb://localhost:27017/mongoose-field-encryption-test", { useNewUrlParser: true });
  });

  after(() => {
    mongoose.connection.close();
  });

  it("should save a document", function(done) {
    // given
    const postSchema = new Schema({
      title: String,
      message: String
    });

    postSchema.plugin(mongooseFieldEncryption, { fields: ["message"], secret: "some secret key" });

    const Post = mongoose.model("Post", postSchema);
    const post = new Post({ title: "some text", message: "hello all" });

    // when
    post.save(function(err) {
      // then
      if (err) {
        return done(err);
      }

      expect(post.title).to.equal("some text");
      expect(post.message).to.not.be.undefined;
      const split = post.message.split(":");
      expect(split.length).to.equal(2);
      expect(post.__enc_message).to.be.true;

      console.dir(post.toObject());

      done();
    });
  });

  it("should search for a document on an encrypted field", async function() {
    // given
    const messageSchema = new Schema({
      title: String,
      message: String,
      name: String
    });

    messageSchema.plugin(mongooseFieldEncryption, {
      fields: ["message", "name"],
      secret: "some secret key",
      saltGenerator: function(secret) {
        return "1234567890123456";
      }
    });

    const title = "some text";
    const name = random(10);
    const message = "hello all";

    const Message = mongoose.model("Message", messageSchema);

    const messageToSave = new Message({ title, message, name });
    await messageToSave.save();

    const messageToSearchWith = new Message({ title: "", message: "", name });
    messageToSearchWith.encryptFieldsSync();

    // when
    const results = await Message.find({ name: messageToSearchWith.name });

    // then
    expect(results.length).to.equal(1);
    const ret = results[0].toObject();

    expect(ret.title).to.equal(title);
    expect(ret.message).to.equal(message);
    expect(ret.name).to.equal(name);
  });
});

function random(howMany, chars) {
  chars = chars || "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
  const rnd = crypto.randomBytes(howMany);
  const value = new Array(howMany);
  const len = Math.min(256, chars.length);
  const d = 256 / len;

  for (var i = 0; i < howMany; i++) {
    value[i] = chars[Math.floor(rnd[i] / d)];
  }

  return value.join("");
}
