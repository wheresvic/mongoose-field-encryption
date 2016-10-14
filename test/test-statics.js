'use strict';

const expect = require('chai').expect;

const Promise = require('bluebird');
const mongoose = require('mongoose');
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require('../lib/mongoose-field-encryption').fieldEncryption;

describe('mongoose-field-encryption plugin static methods', () => {

  let FieldEncryptionSchema = new mongoose.Schema({
    toEncrypt1: { type: String, required: true },
    toEncrypt2: { type: String, required: true }
  });

  FieldEncryptionSchema.plugin(
    fieldEncryptionPlugin, {
      fields: ['toEncrypt1', 'toEncrypt2'],
      secret: 'letsdothis' // should ideally be process.env.SECRET
    }
  );

  let FieldEncryptionStaticsTest = mongoose.model('FieldEncryptionStaticsTest', FieldEncryptionSchema);


  it('should encrypt fields', () => {

    // given
    let sut = new FieldEncryptionStaticsTest({
      toEncrypt1: 'some stuff',
      toEncrypt2: 'should be hidden'
    });

    // when
    sut.encryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.true;
    expect(sut.toEncrypt1).to.equal('b27d5768b82263ece8bd');
    expect(sut.__enc_toEncrypt2).to.be.true;
    expect(sut.toEncrypt2).to.equal('b27a5578f43537fbebfb2e365ab13977');

  });

  it('should not encrypt already encrypted fields', () => {

    // given
    let sut = new FieldEncryptionStaticsTest({
      toEncrypt1: 'some stuff',
      toEncrypt2: 'should be hidden'
    });

    // when
    sut.encryptFieldsSync();
    sut.encryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.true;
    expect(sut.toEncrypt1).to.equal('b27d5768b82263ece8bd');
    expect(sut.__enc_toEncrypt2).to.be.true;
    expect(sut.toEncrypt2).to.equal('b27a5578f43537fbebfb2e365ab13977');

  });

  it('should decrypt fields', () => {

    // given
    let sut = new FieldEncryptionStaticsTest({
      toEncrypt1: 'b27d5768b82263ece8bd',
      __enc_toEncrypt1: true,
      toEncrypt2: 'b27a5578f43537fbebfb2e365ab13977',
      __enc_toEncrypt2: true
    });

    // when
    sut.decryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.false;
    expect(sut.toEncrypt1).to.equal('some stuff');
    expect(sut.__enc_toEncrypt2).to.be.false;
    expect(sut.toEncrypt2).to.equal('should be hidden');

  });

  it('should ignore multiple decrypt field calls', () => {

    // given
    let sut = new FieldEncryptionStaticsTest({
      toEncrypt1: 'b27d5768b82263ece8bd',
      __enc_toEncrypt1: true,
      toEncrypt2: 'b27a5578f43537fbebfb2e365ab13977',
      __enc_toEncrypt2: true
    });

    // when
    sut.decryptFieldsSync();
    sut.decryptFieldsSync();

    // then
    expect(sut.__enc_toEncrypt1).to.be.false;
    expect(sut.toEncrypt1).to.equal('some stuff');
    expect(sut.__enc_toEncrypt2).to.be.false;
    expect(sut.toEncrypt2).to.equal('should be hidden');

  });


});
