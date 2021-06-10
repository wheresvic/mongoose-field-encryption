"use strict";

const crypto = require("crypto");
const expect = require("chai").expect;
const mongoose = require("mongoose");
const Promise = require("bluebird");
const Schema = mongoose.Schema;

mongoose.Promise = Promise;
mongoose.set("bufferCommands", false);

const mongooseFieldEncryption = require("../lib/mongoose-field-encryption").fieldEncryption;

const uri = process.env.URI || "mongodb://127.0.0.1:27017/mongoose-field-encryption-test";

describe("nested fields", function () {
  this.timeout(5000);

  before(function (done) {
    mongoose
      .connect(uri, { useNewUrlParser: true, promiseLibrary: Promise, autoIndex: false, useUnifiedTopology: true })
      .then(function () {
        done();
      });

    mongoose.set("useFindAndModify", false);
  });

  after(function (done) {
    mongoose.disconnect().then(function () {
      done();
    });
  });

  it("should save a document with a nested schema", function (done) {
    // given
    const nestedAuthorSchema = new Schema({
      name: String,
      password: String,
    });
    nestedAuthorSchema.plugin(mongooseFieldEncryption, { fields: ["password"], secret: "some secret key" });
    const postSchema = new Schema({
      title: String,
      message: String,
      author: nestedAuthorSchema,
    });

    const Post = mongoose.model("Post1", postSchema);
    const post = new Post({
      title: "some text",
      message: "hello all",
      author: { name: "some name", password: "some password" },
    });

    // when
    post.save(function (err) {
      // then
      if (err) {
        return done(err);
      }

      expect(post.author.name).to.equal("some name");
      expect(post.author.password).to.not.be.undefined;
      const split = post.author.password.split(":");
      expect(split.length).to.equal(2);
      expect(post.author.__enc_password).to.be.true;

      console.dir(post.toObject());

      done();
    });
  });

  it("should update a document with a nested schema", function (done) {
    // given
    const nestedAuthorSchema = new Schema({
      name: String,
      password: String,
    });
    nestedAuthorSchema.plugin(mongooseFieldEncryption, { fields: ["password"], secret: "some secret key" });
    const postSchema = new Schema({
      title: String,
      message: String,
      author: nestedAuthorSchema,
    });

    const Post = mongoose.model("Post2", postSchema);
    const post = new Post({
      title: "some text",
      message: "hello all",
      author: { name: "some name", password: "some password" },
    });

    post.save(function (err) {
      if (err) {
        return done(err);
      }

      Post.findOne({ _id: post._id }, function (err, post) {
        if (err) {
          return done(err);
        }

        post.author.name = "something else";

        // when
        post.save(function (err) {
          // then
          if (err) {
            return done(err);
          }

          expect(post.author.name).to.equal("something else");
          console.dir(post.toObject());
          done();
        });
      });
    });
  });

  // Failing test:
  it("should update a document with a nested schema-array", function (done) {
    // given
    const nestedAuthorSchema = new Schema({
      name: String,
      password: String,
    });
    nestedAuthorSchema.plugin(mongooseFieldEncryption, { fields: ["password"], secret: "some secret key" });
    const postSchema = new Schema({
      title: String,
      message: String,
      authors: [nestedAuthorSchema],
    });

    const Post = mongoose.model("Post3", postSchema);
    const post = new Post({
      title: "some text",
      message: "hello all",
      authors: [{ name: "some name", password: "some password" }],
    });

    post.save(function (err) {
      if (err) {
        return done(err);
      }

      Post.findOne({ _id: post._id }, function (err, post) {
        if (err) {
          return done(err);
        }

        post.title = "something else";

        // when
        post.save(function (err) {
          // then
          if (err) {
            return done(err);
          }

          expect(post.title).to.equal("something else");
          done();
        });
      });
    });
  });
});
