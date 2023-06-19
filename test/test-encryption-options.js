"use strict";
const crypto = require("crypto");
const expect = require("chai").expect;
const mongoose = require("mongoose");
const Promise = require("bluebird");
const { setupMongoose } = require("./setup");
const Schema = mongoose.Schema;

mongoose.Promise = Promise;
mongoose.set("bufferCommands", false);

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

describe("Test fieldEncryption options behaviour", function() {
    it("Demonstrate encryptNull: false option", function (done) {
        const FieldEncryptionSchema = new mongoose.Schema({
            noEncrypt: { type: String },
            toEncrypt1: { type: String },
            toEncrypt2: { type: String },
        });
    
        FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
            fields: ["toEncrypt1", "toEncrypt2"],
            secret: "letsdothis",
            encryptNull: false, 
        });

        const FieldEncryptionOptionsTest1 = mongoose.model("FieldEncryptionOptionsTest1", FieldEncryptionSchema);
        const sut = new FieldEncryptionOptionsTest1({
            noEncrypt: "clear",
            toEncrypt1: "some stuff",
            toEncrypt2: null
        });
    
        // when
        sut.encryptFieldsSync();

        // then
        expect(sut.noEncrypt).to.equal("clear");
        expect(sut.__enc_noEncrypt).to.be.undefined;

        expect(sut.__enc_toEncrypt1).to.be.true;
        expect(sut.toEncrypt1).to.not.eql("some stuff");

        expect(sut.__enc_toEncrypt2).to.be.undefined;
        expect(sut.toEncrypt2).to.eql(null);
        done();
    });

    it("Demonstrate encryptNull: true option (Default behaviour)", function (done) {
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
        const sut = new FieldEncryptionOptionsTest2({
            noEncrypt: "clear",
            toEncrypt1: "some stuff",
            toEncrypt2: null
        });
    
        // when
        sut.encryptFieldsSync();

        // then
        expect(sut.noEncrypt).to.equal("clear");
        expect(sut.__enc_noEncrypt).to.be.undefined;

        expect(sut.__enc_toEncrypt1).to.be.true;
        expect(sut.toEncrypt1).to.not.eql("some stuff");

        expect(sut.__enc_toEncrypt2).to.be.true;
        expect(sut.toEncrypt2).to.be.undefined;
        expect(sut.__enc_toEncrypt2_d).to.exist;
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
            encryptNull: false,
            notifyDecryptFails: false
        });
  
        const FieldEncryptionStaticsTest3 = mongoose.model("FieldEncryptionStaticsTest3", FieldEncryptionSchema);
        // given
        const sut = new FieldEncryptionStaticsTest3({
            noEncrypt: "clear",
            toEncrypt1: "some stuff",
            toEncrypt2: "after exception"
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

    it("Demonstrate encryptEachArrayItem: true - encrypts each item in an array", function (done) {
        const FieldEncryptionSchema = new mongoose.Schema({
            noEncrypt: { type: String },
            toEncrypt1: { type: String },
            toEncryptArray: { type: [String] },
        });
    
        FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
            fields: ["toEncrypt1", "toEncryptArray"],
            secret: "letsdothis",
            encryptNull: false,
            encryptEachArrayItem: true
        });
  
        const FieldEncryptionStaticsTest4 = mongoose.model("FieldEncryptionStaticsTest4", FieldEncryptionSchema);
        // given
        const sut = new FieldEncryptionStaticsTest4({
            noEncrypt: "clear",
            toEncrypt1: "some stuff",
            toEncryptArray: ["item1", "item2", "item3"]
        });

        // when
        sut.encryptFieldsSync();
        expect(sut.__enc_toEncryptArray_d.length).to.eql(3);

        // then
        sut.decryptFieldsSync();
        expect(sut.noEncrypt).to.equal("clear");
        expect(sut.__enc_noEncrypt).to.be.undefined;

        expect(sut.__enc_toEncrypt1).to.be.false;
        expect(sut.toEncrypt1).to.eql("some stuff");

        expect(sut.__enc_toEncryptArray).to.be.false;
        expect(sut.toEncryptArray.length).to.eql(3);
        expect(sut.toEncryptArray[0]).to.eql("item1");
        expect(sut.toEncryptArray[1]).to.eql("item2");
        expect(sut.toEncryptArray[2]).to.eql("item3");
        
        done();
    });

    it("Demonstrate encryptEachArrayItem: false - default behaviour (stringify the array)", function (done) {
        const FieldEncryptionSchema = new mongoose.Schema({
            noEncrypt: { type: String },
            toEncrypt1: { type: String },
            toEncryptArray: { type: [String] },
        });
    
        FieldEncryptionSchema.plugin(fieldEncryptionPlugin, {
            fields: ["toEncrypt1", "toEncryptArray"],
            secret: "letsdothis",
            encryptNull: false,
            encryptEachArrayItem: false
        });
  
        const FieldEncryptionStaticsTest5 = mongoose.model("FieldEncryptionStaticsTest5", FieldEncryptionSchema);
        // given
        const sut = new FieldEncryptionStaticsTest5({
            noEncrypt: "clear",
            toEncrypt1: "some stuff",
            toEncryptArray: ["item1", "item2", "item3"]
        });

        // when
        sut.encryptFieldsSync();
        expect(sut.__enc_toEncryptArray_d).to.be.string;

        // then
        sut.decryptFieldsSync();
        expect(sut.noEncrypt).to.equal("clear");
        expect(sut.__enc_noEncrypt).to.be.undefined;

        expect(sut.__enc_toEncrypt1).to.be.false;
        expect(sut.toEncrypt1).to.eql("some stuff");

        expect(sut.__enc_toEncryptArray).to.be.false;
        expect(sut.toEncryptArray.length).to.eql(3);
        expect(sut.toEncryptArray[0]).to.eql("item1");
        expect(sut.toEncryptArray[1]).to.eql("item2");
        expect(sut.toEncryptArray[2]).to.eql("item3");
        done();
    });

  /*it("Should throw a message when decrypting null value", function (done) {*/
    
});

