'use strict';

const expect = require('chai').expect;

const Promise = require('bluebird');
const mongoose = require('mongoose');
mongoose.Promise = Promise;

const fieldEncryptionPlugin = require('../lib/mongoose-field-encryption').fieldEncryption;

const uri = process.env.URI || 'mongodb://localhost/mongoose-field-encryption-test';

describe('mongoose-field-encryption plugin db', () => {

  let NestedFieldEncryptionSchema = new mongoose.Schema({
    toEncryptString: { type: String, required: true },
    toEncryptObject: {
      nested: String,
    },
    toEncryptArray: [],
    toEncryptDate: Date
  });

  NestedFieldEncryptionSchema.plugin(
    fieldEncryptionPlugin, {
      fields: ['toEncryptString', 'toEncryptObject', 'toEncryptArray', 'toEncryptDate'],
      secret: 'icanhazcheezburger' // should ideally be process.env.SECRET
    }
  );

  let NestedFieldEncryption = mongoose.model('NestedFieldEncryption', NestedFieldEncryptionSchema);

  before(() => {
    return mongoose.connect(uri)
      .then(() => {
        return mongoose.connection.db.dropDatabase();
      });
  });

  after(() => {
    mongoose.connection.close()
  });

  function getSut() {
    let sut = new NestedFieldEncryption({
      toEncryptString: 'hide me!',
      toEncryptObject: {
        nested: 'some stuff to encrypt'
      },
      toEncryptArray: [1, 2, 3],
      toEncryptDate: new Date(1970, 1, 1)
    });

    return sut;
  }

  function expectEncryptionValues(sut) {
    expect(sut.toEncryptString).to.equal('2dc9eb06e3efa172');
    expect(sut.__enc_toEncryptString).to.be.true;

    expect(sut.toObject().toEncryptObject).to.be.undefined;
    expect(sut.__enc_toEncryptObject).to.be.true;
    expect(sut.__enc_toEncryptObject_d).to.equal('3e82e106b0f6a137e710374b8b3be61816e5e48dcaaeb16b57016f58ccb28a0967e4');

    expect(sut.toObject().toEncryptArray).to.be.undefined;
    expect(sut.__enc_toEncryptArray).to.be.true;
    expect(sut.__enc_toEncryptArray_d).to.equal('1e91a351efb199');

    expect(sut.toObject().toEncryptDate).to.be.undefined;
    expect(sut.__enc_toEncryptDate).to.be.true;
    expect(sut.__enc_toEncryptDate_d).to.equal('6791b654f3aff462e819246cd665b90855aba1db82bef5342d46');

  }

  function expectDecryptionValues(found) {
    expect(found.toEncryptString).to.equal('hide me!');
    expect(found.__enc_toEncryptString).to.be.false;

    expect(JSON.stringify(found.toEncryptObject)).to.equal('{"nested":"some stuff to encrypt"}');
    expect(found.__enc_toEncryptObject).to.be.false;
    expect(found.__enc_toEncryptObject_d).to.equal('');

    expect(JSON.stringify(found.toEncryptArray)).to.equal('[1,2,3]');
    expect(found.__enc_toEncryptArray).to.be.false;
    expect(found.__enc_toEncryptArray_d).to.equal('');

    expect(JSON.stringify(found.toEncryptDate)).to.equal('"1970-01-31T23:00:00.000Z"');
    expect(found.__enc_toEncryptDate).to.be.false;
    expect(found.__enc_toEncryptDate_d).to.equal('');
  }

  it('should encrypt fields on save and decrypt fields on findById', () => {

    // given
    let sut = getSut();

    // when
    return sut.save()
      .then(() => {
        // then
        expectEncryptionValues(sut);

        return NestedFieldEncryption.findById(sut._id);
      })
      .then(found => {
        expectDecryptionValues(found);
      });
  });

  it('should encrypt fields on save and decrypt fields on findOne', () => {

    // given
    let sut = getSut()

    // when
    return sut.save()
      .then(() => {
        expectEncryptionValues(sut);
        return NestedFieldEncryption.findOne({ _id: sut._id });
      })
      .then(found => {
        expectDecryptionValues(found);
      });
  });

  it('should store encrypted fields as plaintext on findOneAndUpdate', () => {

    // given
    let sut = getSut();

    // when
    return sut.save()
      .then(() => {
        expectEncryptionValues(sut);

        return NestedFieldEncryption.findOneAndUpdate({ _id: sut._id }, {
          $set: { toEncryptString: 'snoop', __enc_toEncryptString: false }
        }, { new: true });
      })
      .then(found => {
        // then
        expect(found.__enc_toEncryptString).to.be.false;
        expect(found.toEncryptString).to.equal('snoop');
      });
  });

  it('should encrypt string fields on update', () => {

    // given
    let sut = getSut();

    // when
    return sut.save()
      .then(() => {
        expectEncryptionValues(sut);

        return NestedFieldEncryption.update({ _id: sut._id }, { $set: { toEncryptString: 'snoop', __enc_toEncryptString: false } });
      })
      .then(() => {
        return NestedFieldEncryption.findById(sut._id);
      })
      .then(found => {
        // then
        expect(found.__enc_toEncryptString).to.be.false;
        expect(found.toEncryptString).to.equal('snoop');
      });
  });

  it('should not encrypt non string fields on update', () => {

    // given
    let sut = getSut();

    // when
    return sut.save()
      .then(() => {
        expectEncryptionValues(sut);

        return NestedFieldEncryption.update({
          _id: sut._id
        }, {
          $set: {
            toEncryptObject: { nested: 'snoop' },
            __enc_toEncryptObject: false
          }
        });
      })
      .then(() => {
        expect.fail('should not have updated');
      })
      .catch(err => {
        // then
        // TODO: this is a mongoose cast error
        expect(err).to.not.be.null;
      });
  });

});
