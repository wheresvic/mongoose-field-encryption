"use strict";

const crypto = require("crypto");
const expect = require("chai").expect;

const { encrypt, decrypt } = require("../lib/mongoose-field-encryption");

describe("manual usage", function () {
  it("encrypt and decrypt text", function (done) {
    // given
    const password = "thisissomepassword";
    const saltGenerator = (password) => password.substring(0, 16);
    const _hash = (secret) => crypto.createHash("sha256").update(secret).digest("hex").substring(0, 32);

    // when
    const encrypted = encrypt("some text", _hash(password), saltGenerator);
    const decrypted = decrypt(encrypted, _hash(password));

    // then
    expect(encrypted).to.equal("61373334306262636435636339333336:fbd69a23d9123e8df17325618e6c23f8");
    expect(decrypted).to.equal("some text");

    done();
  });
});
