"use strict";

const crypto = require("crypto");
const expect = require("chai").expect;
const mongoose = require("mongoose");
const Promise = require("bluebird");
const { setupMongoose } = require("./setup");
const Schema = mongoose.Schema;

mongoose.Promise = Promise;
mongoose.set("bufferCommands", false);

const mongooseFieldEncryption = require("../lib/mongoose-field-encryption").fieldEncryption;

const uri = process.env.URI || "mongodb://127.0.0.1:27017/mongoose-field-encryption-test";

const postSchema = new Schema({
  title: String,
  message: String,
});

postSchema.plugin(mongooseFieldEncryption, { fields: ["message"], secret: "some secret key" });

const Post = mongoose.model("Post", postSchema);

describe("basic usage", function () {
  this.timeout(5000);

  before(async function () {
    await mongoose.connect(uri, { useNewUrlParser: true, autoIndex: false, useUnifiedTopology: true });

    setupMongoose(mongoose);
  });

  after(async function () {
    await mongoose.disconnect();
  });

  beforeEach(async function () {
    await Post.deleteMany({});
  });

  it("should save a document", async function () {
    const post = new Post({ title: "some text", message: "hello all" });

    // when
    await post.save();

    expect(post.title).to.equal("some text");
    expect(post.message).to.not.be.undefined;
    const split = post.message.split(":");
    expect(split.length).to.equal(2);
    expect(post.__enc_message).to.be.true;

    console.dir(post.toObject());
  });

  it("should save many documents", async function () {
    const posts = [
      new Post({ title: "some text 0", message: "hello all" }),
      new Post({ title: "some text 1", message: "hello many" }),
      new Post({ title: "some text 2", message: "hello aloha!" }),
    ];

    // when
    await Post.insertMany(posts);

    let i = 0;
    for (const post of posts) {
      expect(post.title).to.equal(`some text ${i}`);
      expect(post.message).to.not.be.undefined;
      const split = post.message.split(":");
      expect(split.length).to.equal(2);
      expect(post.__enc_message).to.be.true;
      i++;
    }

    {
      const posts = await Post.find({});

      console.log(posts);
      expect(posts).to.not.be.null;
      expect(posts.length).to.equal(3);

      let i = 0;
      for (const post of posts) {
        expect(post.title).to.equal(`some text ${i}`);
        expect(post.message).to.not.be.undefined;
        expect(post.message.startsWith("hello")).to.be.true;
        expect(post.__enc_message).to.be.false;
        i++;
      }
    }
  });

  it("should search for a document on an encrypted field", function (done) {
    // given
    const messageSchema = new Schema({
      title: String,
      message: String,
      name: String,
    });

    messageSchema.plugin(mongooseFieldEncryption, {
      fields: ["message", "name"],
      secret: "some secret key",
      saltGenerator: function (secret) {
        return "1234567890123456";
      },
    });

    const title = "some text";
    const name = random(10);
    const message = "hello all";

    const Message = mongoose.model("Message", messageSchema);

    const messageToSave = new Message({ title: title, message: message, name: name });

    messageToSave
      .save()
      .then(function (savedMessage) {
        const messageToSearchWith = new Message({ name: name });
        messageToSearchWith.encryptFieldsSync();

        // when
        return Message.find({ name: messageToSearchWith.name });
      })
      .then(function (results) {
        // then
        expect(results.length).to.equal(1);
        const ret = results[0].toObject();

        expect(ret.title).to.equal(title);
        expect(ret.message).to.equal(message);
        expect(ret.name).to.equal(name);

        done();
      });
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
