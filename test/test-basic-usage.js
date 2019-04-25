"use strict";

const expect = require("chai").expect;
const mongoose = require("mongoose");
mongoose.set("bufferCommands", false);

const mongooseFieldEncryption = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("basic usage", function() {
  this.timeout(5000);

  before(() => {
    return mongoose.connect("mongodb://localhost:27017/csvfilereader", { useNewUrlParser: true });
  });

  after(() => {
    mongoose.connection.close();
  });

  it("should save a document", function(done) {
    // var conn = mongoose.connection;

    const Schema = mongoose.Schema;

    const postSchema = new Schema({
      title: String,
      message: String
    });

    postSchema.plugin(mongooseFieldEncryption, { fields: ["message"], secret: "some secret key" });

    const Post = mongoose.model("Post", postSchema);
    const post = new Post({ title: "some text", message: "hello all" });
    post.save(function(err) {
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
});
