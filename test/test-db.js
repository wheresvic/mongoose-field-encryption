const expect = require("chai").expect;

const mongoose = require("mongoose");
const { setupMongoose } = require("./setup");
mongoose.set("bufferCommands", false);

const fieldEncryptionPlugin = require("../lib/mongoose-field-encryption").fieldEncryption;

const uri = process.env.URI || "mongodb://127.0.0.1:27017/mongoose-field-encryption-test";

describe("mongoose-field-encryption plugin db", function () {
  this.timeout(5000);

  before(function (done) {
    mongoose
      .connect(uri, {
        useNewUrlParser: true,
        autoIndex: false,
        useUnifiedTopology: true,
      })
      .then(function () {
        done();
      });

    setupMongoose(mongoose);
  });

  after(function (done) {
    mongoose.disconnect().then(function () {
      done();
    });
  });

  const MongooseSchema = {
    toEncryptString: { type: String, required: true },
    toEncryptStringNotRetrieved: { type: String, select: false },
    toEncryptObject: {
      nested: String,
    },
    toEncryptArray: [],
    toEncryptDate: Date,
  };

  function getSut(MongooseModel) {
    const sut = new MongooseModel({
      toEncryptString: "hide me!",
      toEncryptObject: {
        nested: "some stuff to encrypt",
      },
      toEncryptArray: [1, 2, 3],
      toEncryptDate: new Date(1485641048338),
    });

    return sut;
  }

  const fieldEncryptionPluginOptions = {
    fields: ["toEncryptString", "toEncryptObject", "toEncryptArray", "toEncryptDate", "toEncryptStringNotRetrieved"],
    secret: "icanhazcheezburger", // should ideally be process.env.SECRET
  };

  describe("simple setup", function () {
    const NestedFieldEncryptionSchema = new mongoose.Schema(MongooseSchema);

    NestedFieldEncryptionSchema.plugin(fieldEncryptionPlugin, fieldEncryptionPluginOptions);

    const NestedFieldEncryption = mongoose.model("NestedFieldEncryption", NestedFieldEncryptionSchema);

    function expectEncryptionValues(sut) {
      expect(sut.__enc_toEncryptString).to.be.true;

      expect(sut.toObject().toEncryptObject).to.be.undefined;
      expect(sut.__enc_toEncryptObject).to.be.true;

      expect(sut.toObject().toEncryptArray).to.be.undefined;
      expect(sut.__enc_toEncryptArray).to.be.true;

      expect(sut.toObject().toEncryptDate).to.be.undefined;
      expect(sut.__enc_toEncryptDate).to.be.true;
    }

    function expectDecryptionValues(found) {
      expect(found.toEncryptString).to.equal("hide me!");
      expect(found.__enc_toEncryptString).to.be.false;

      expect(JSON.stringify(found.toEncryptObject)).to.equal('{"nested":"some stuff to encrypt"}');
      expect(found.__enc_toEncryptObject).to.be.false;
      expect(found.__enc_toEncryptObject_d).to.equal("");

      expect(JSON.stringify(found.toEncryptArray)).to.equal("[1,2,3]");
      expect(found.__enc_toEncryptArray).to.be.false;
      expect(found.__enc_toEncryptArray_d).to.equal("");

      expect(JSON.stringify(found.toEncryptDate)).to.equal('"2017-01-28T22:04:08.338Z"');
      expect(found.__enc_toEncryptDate).to.be.false;
      expect(found.__enc_toEncryptDate_d).to.equal("");
    }

    runTests(NestedFieldEncryption, getSut, expectEncryptionValues, expectDecryptionValues);
  });

  describe("simple setup with salt factory", function () {
    const NestedFieldEncryptionSaltFactorySchema = new mongoose.Schema(MongooseSchema);

    const options = {};
    const optionsWithSecret = Object.assign(options, fieldEncryptionPluginOptions);
    optionsWithSecret.secret = function () {
      return fieldEncryptionPluginOptions.secret;
    };

    NestedFieldEncryptionSaltFactorySchema.plugin(fieldEncryptionPlugin, optionsWithSecret);

    const NestedFieldEncryptionSaltFactory = mongoose.model(
      "NestedFieldEncryptionSaltFactory",
      NestedFieldEncryptionSaltFactorySchema
    );

    function expectEncryptionValues(sut) {
      expect(sut.__enc_toEncryptString).to.be.true;

      expect(sut.toObject().toEncryptObject).to.be.undefined;
      expect(sut.__enc_toEncryptObject).to.be.true;

      expect(sut.toObject().toEncryptArray).to.be.undefined;
      expect(sut.__enc_toEncryptArray).to.be.true;

      expect(sut.toObject().toEncryptDate).to.be.undefined;
      expect(sut.__enc_toEncryptDate).to.be.true;
    }

    function expectDecryptionValues(found) {
      expect(found.toEncryptString).to.equal("hide me!");
      expect(found.__enc_toEncryptString).to.be.false;

      expect(JSON.stringify(found.toEncryptObject)).to.equal('{"nested":"some stuff to encrypt"}');
      expect(found.__enc_toEncryptObject).to.be.false;
      expect(found.__enc_toEncryptObject_d).to.equal("");

      expect(JSON.stringify(found.toEncryptArray)).to.equal("[1,2,3]");
      expect(found.__enc_toEncryptArray).to.be.false;
      expect(found.__enc_toEncryptArray_d).to.equal("");

      expect(JSON.stringify(found.toEncryptDate)).to.equal('"2017-01-28T22:04:08.338Z"');
      expect(found.__enc_toEncryptDate).to.be.false;
      expect(found.__enc_toEncryptDate_d).to.equal("");
    }

    runTests(NestedFieldEncryptionSaltFactory, getSut, expectEncryptionValues, expectDecryptionValues);
  });

  describe("custom salt", function () {
    const NestedFieldEncryptionCustomSaltSchema = new mongoose.Schema(MongooseSchema);

    NestedFieldEncryptionCustomSaltSchema.plugin(
      fieldEncryptionPlugin,
      Object.assign({ saltGenerator: (secret) => secret.slice(0, 16) }, fieldEncryptionPluginOptions)
    );

    const NestedFieldEncryptionCustomSalt = mongoose.model(
      "NestedFieldEncryptionCustomSalt",
      NestedFieldEncryptionCustomSaltSchema
    );

    function expectEncryptionValues(sut) {
      const toObject = sut.toObject();

      expect(sut.__enc_toEncryptString).to.be.true;
      expect(sut.toEncryptString).to.equal("37373539656562373263336135633161:853640c6ba4c570e2818068ac79af248");

      expect(toObject.toEncryptObject).to.be.undefined;
      expect(sut.__enc_toEncryptObject_d).to.equal(
        "37373539656562373263336135633161:0c8443e5d5a6620a9840939748789fe1206b3d2f09c3b1caff0a4a56c5283e31ded93b4a8fa821200fa58a5874d41148"
      );
      expect(sut.__enc_toEncryptObject).to.be.true;

      expect(toObject.toEncryptArray).to.be.undefined;
      expect(sut.__enc_toEncryptArray_d).to.equal("37373539656562373263336135633161:1a94f782f6b93fc68f6059f2af865b84");
      expect(sut.__enc_toEncryptArray).to.be.true;

      expect(toObject.toEncryptDate).to.be.undefined;
      expect(sut.__enc_toEncryptDate).to.be.true;
      expect(sut.__enc_toEncryptDate_d).to.equal(
        "37373539656562373263336135633161:24a096e92ad9e32c8c8015a5bfab93c9fe88d027403c750ff4d71a35bb538ac3"
      );
    }

    function expectDecryptionValues(found) {
      expect(found.toEncryptString).to.equal("hide me!");
      expect(found.__enc_toEncryptString).to.be.false;

      expect(JSON.stringify(found.toEncryptObject)).to.equal('{"nested":"some stuff to encrypt"}');
      expect(found.__enc_toEncryptObject).to.be.false;
      expect(found.__enc_toEncryptObject_d).to.equal("");

      expect(JSON.stringify(found.toEncryptArray)).to.equal("[1,2,3]");
      expect(found.__enc_toEncryptArray).to.be.false;
      expect(found.__enc_toEncryptArray_d).to.equal("");

      expect(JSON.stringify(found.toEncryptDate)).to.equal('"2017-01-28T22:04:08.338Z"');
      expect(found.__enc_toEncryptDate).to.be.false;
      expect(found.__enc_toEncryptDate_d).to.equal("");
    }

    runTests(NestedFieldEncryptionCustomSalt, getSut, expectEncryptionValues, expectDecryptionValues);
  });

  describe("subdocument encryption", function () {
    it("should encrypt and decrypt subdocuments", function (done) {
      const UserExtraSchema = new mongoose.Schema({
        city: { type: String },
        country: { type: String },
        address: { type: String },
        postalCode: { type: String },
      });

      UserExtraSchema.plugin(fieldEncryptionPlugin, {
        fields: ["address"],
        secret: "icanhazcheeseburger",
        saltGenerator: (secret) => secret.slice(0, 16),
      });

      const UserSchema = new mongoose.Schema(
        {
          name: { type: String, required: true },
          surname: { type: String, required: true },
          email: { type: String, required: true },
          extra: UserExtraSchema,
        },
        { collection: "users" }
      );

      UserSchema.plugin(fieldEncryptionPlugin, {
        fields: ["name", "surname"],
        secret: "icanhazcheeseburger",
        saltGenerator: (secret) => secret.slice(0, 16),
      });

      const UserModel = mongoose.model("User", UserSchema);

      // given
      const sut = new UserModel({
        name: "snoop",
        surname: "dawg",
        email: "snoop.dawg@dadadadada.com",
        extra: {
          city: "cali",
          country: "usa",
          address: "bowchickabowwow",
          postalCode: "90210",
        },
      });

      // when
      sut
        .save()
        .then(() => {
          // then
          expect(sut.name).to.equal("31393663303733396265616337353364:5b8c2d2160c935152c7dd6bf6a31f894");
          expect(sut.extra.address).to.equal("31393663303733396265616337353364:b9610446ddefafef177ffe0cdfec2d2d");

          return UserModel.findById(sut._id);
        })
        .then((found) => {
          expect(found.name).to.equal("snoop");
          expect(found.extra.address).to.equal("bowchickabowwow");
        })
        .finally(() => {
          done();
        });
    });
  });

  function runTests(MongooseModel, getSut, expectEncryptionValues, expectDecryptionValues) {
    it("should encrypt fields on save and decrypt fields on findById", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          // then
          expectEncryptionValues(sut);

          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          expectDecryptionValues(found);
        });
    });

    it("should encrypt fields on save and decrypt fields on findOne", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);
          return MongooseModel.findOne({ _id: sut._id });
        })
        .then((found) => {
          expectDecryptionValues(found);
        });
    });

    it("should store encrypted fields as plaintext on findOneAndUpdate", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            { _id: sut._id },
            {
              $set: { toEncryptString: "snoop", __enc_toEncryptString: false },
            },
            { new: true, useFindAndModify: false }
          );
        })
        .then((found) => {
          // then
          expect(found.__enc_toEncryptString).to.be.false;
          expect(found.toEncryptString).to.equal("snoop");
        });
    });

    it("should encrypt string fields on update", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.update(
            { _id: sut._id },
            { $set: { toEncryptString: "snoop", __enc_toEncryptString: false } }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          // then
          expect(found.__enc_toEncryptString).to.be.false;
          expect(found.toEncryptString).to.equal("snoop");
        });
    });

    it("should encrypt string fields on updateOne", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.updateOne(
            { _id: sut._id },
            { $set: { toEncryptString: "snoop", __enc_toEncryptString: false } }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          // then
          expect(found.__enc_toEncryptString).to.be.false;
          expect(found.toEncryptString).to.equal("snoop");
        });
    });

    it("should encrypt string fields on update without $set", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.updateOne({ _id: sut._id }, { toEncryptString: "snoop" });
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          // then
          expect(found.__enc_toEncryptString).to.be.false;
          expect(found.toEncryptString).to.equal("snoop");
        });
    });

    it("should encrypt string fields on fineOneAndUpdate", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            { _id: sut._id },
            { $set: { toEncryptString: "snoop", __enc_toEncryptString: false } }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          // then
          expect(found.__enc_toEncryptString).to.be.false;
          expect(found.toEncryptString).to.equal("snoop");
        });
    });

    it("should encrypt non string fields on update", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.updateOne(
            {
              _id: sut._id,
            },
            {
              $set: {
                toEncryptObject: { nested: "snoop" },
                __enc_toEncryptObject: false,
              },
            }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          expect(found.toEncryptObject.nested).to.eql("snoop");
        });
    });

    it("should encrypt non string fields on fineOneAndUpdate without $set", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            {
              _id: sut._id,
            },
            {
              toEncryptObject: { nested: "snoop" },
            }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          expect(found.toEncryptObject.nested).to.eql("snoop");
        });
    });

    it("should decrypt data on find() method call", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            {
              _id: sut._id,
            },
            {
              toEncryptString: "yaddayadda",
              toEncryptObject: { nested: "snoop" },
            }
          );
        })
        .then(() => {
          return MongooseModel.find({ _id: sut._id });
        })
        .then((foundArray) => {
          const found = foundArray[0];
          expect(found.toEncryptString).to.eql("yaddayadda");
          expect(found.toEncryptObject.nested).to.eql("snoop");
        });
    });

    it("should decrypt data on find() method call when only selected encrypted fields are retrieved", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            {
              _id: sut._id,
            },
            {
              toEncryptString: "yaddayadda",
              toEncryptObject: { nested: "snoop" },
            }
          );
        })
        .then(() => {
          return MongooseModel.find({ _id: sut._id }, "__enc_toEncryptString toEncryptString");
        })
        .then((foundArray) => {
          const found = foundArray[0];
          expect(found.toEncryptString).to.equal("yaddayadda");
        });
    });

    it("should not encrypt already encrypted fields", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.updateOne(
            {
              _id: sut._id,
            },
            {
              $set: {
                toEncryptString: "already encrypted string",
                __enc_toEncryptObject: true,
              },
            }
          );
        })
        .then(() => {
          return MongooseModel.findById(sut._id);
        })
        .then((found) => {
          expect(found.toEncryptString).to.eql("already encrypted string");
        });
    });

    it("should decrypt data on find() method call even if some fields are marked as not selectables", function () {
      // given
      const sut = getSut(MongooseModel);

      // when
      return sut
        .save()
        .then(() => {
          expectEncryptionValues(sut);

          return MongooseModel.findOneAndUpdate(
            {
              _id: sut._id,
            },
            {
              toEncryptString: "yaddayadda",
              toEncryptObject: { nested: "snoop" },
              toEncryptStringNotRetrieved: "dubidubida",
            }
          );
        })
        .then(() => {
          return MongooseModel.find({ _id: sut._id });
        })
        .then((foundArray) => {
          const found = foundArray[0];
          expect(found.toEncryptString).to.equal("yaddayadda");
          expect(found.toEncryptStringNotRetrieved).to.be.undefined;
        });
    });
  }

  describe("falsy values", function () {
    it("should encrypt and decrypt falsy values", function () {
      const FalsySchema = {
        toEncryptString: { type: String },
        toEncryptArray: [],
        toEncryptDate: Date,
        toEncryptNumber: { type: Number },
        toEncryptBoolean: { type: Boolean },
      };

      const FalsyEncryptionSchema = new mongoose.Schema(FalsySchema);
      FalsyEncryptionSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncryptString", "toEncryptArray", "toEncryptDate", "toEncryptNumber", "toEncryptBoolean"],
        secret: "icanhazcheezburger",
        saltGenerator: (secret) => secret.slice(0, 16),
      });

      const FalsyEncryptionModel = mongoose.model("FalsyEncryptionModel", FalsyEncryptionSchema);
      const sut = new FalsyEncryptionModel({
        toEncryptString: "",
        toEncryptArray: [],
        toEncryptDate: 0,
        toEncryptNumber: 0,
        toEncryptBoolean: false,
      });

      return sut
        .save()
        .then(() => {
          // console.log(sut);

          expect(sut.__enc_toEncryptString).to.be.true;
          expect(sut.toEncryptString).to.equal("37373539656562373263336135633161:9af345f139de3d5397f513a2ab105607");

          expect(sut.toEncryptArray).to.be.undefined;
          expect(sut.__enc_toEncryptArray).to.be.true;
          expect(sut.__enc_toEncryptArray_d).to.equal(
            "37373539656562373263336135633161:b897c78694f3ad8533e246e21386e5d4"
          );

          expect(sut.toEncryptDate).to.be.undefined;
          expect(sut.__enc_toEncryptDate).to.be.true;
          expect(sut.__enc_toEncryptDate_d).to.equal(
            "37373539656562373263336135633161:da4568a1046a687ecdf7dc65793d44725d67efcefa88508339750a074e485f25"
          );

          expect(sut.toEncryptNumber).to.be.undefined;
          expect(sut.__enc_toEncryptNumber).to.be.true;
          expect(sut.__enc_toEncryptNumber_d).to.equal(
            "37373539656562373263336135633161:512c4a442a26f20f8ef81577d2fded37"
          );

          expect(sut.toEncryptBoolean).to.be.undefined;
          expect(sut.__enc_toEncryptBoolean).to.be.true;
          expect(sut.__enc_toEncryptBoolean_d).to.equal(
            "37373539656562373263336135633161:2eee0dc63b89e2f6bc99febe113989f3"
          );

          return FalsyEncryptionModel.findOne({ _id: sut._id });
        })
        .then((found) => {
          // console.log(found);

          expect(found.toEncryptString).to.equal("");
          expect(found.__enc_toEncryptString).to.be.false;

          expect(found.toEncryptArray).to.deep.equal([]);
          expect(found.__enc_toEncryptArray).to.be.false;

          expect(found.toEncryptDate).to.deep.equal(new Date(0));
          expect(found.__enc_toEncryptDate).to.be.false;

          expect(found.toEncryptNumber).to.equal(0);
          expect(found.__enc_toEncryptDate).to.be.false;

          expect(found.toEncryptBoolean).to.equal(false);
          expect(found.__enc_toEncryptDate).to.be.false;
        });
    });

    it("should encrypt and decrypt empty string and record a change", async function () {
      // given
      const FalsyRecordSchema = {
        toEncryptString: { type: String, required: false, default: "" },
      };

      const FalsyRecordEncryptionSchema = new mongoose.Schema(FalsyRecordSchema);
      FalsyRecordEncryptionSchema.plugin(fieldEncryptionPlugin, {
        fields: ["toEncryptString"],
        secret: "icanhazcheezburger",
        saltGenerator: (secret) => secret.slice(0, 16),
      });

      const FalsyRecordEncryptionModel = mongoose.model("FalsyRecordEncryptionModel", FalsyRecordEncryptionSchema);
      const sut = new FalsyRecordEncryptionModel({
        toEncryptString: "",
      });

      // when
      await sut.save();

      // then
      expect(sut.__enc_toEncryptString).to.be.true;
      expect(sut.toEncryptString).to.equal("37373539656562373263336135633161:9af345f139de3d5397f513a2ab105607");

      const found = await FalsyRecordEncryptionModel.findOne({ _id: sut._id });

      expect(found.toEncryptString).to.equal("");
      expect(found.__enc_toEncryptString).to.be.false;

      found.toEncryptString = "value";
      await found.save();

      expect(found.toEncryptString).to.equal("37373539656562373263336135633161:8335a0fb01aab80cfea6a61653a329aa");
      expect(found.__enc_toEncryptString).to.be.true;
    });
  });
});
