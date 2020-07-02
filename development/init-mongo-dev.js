db.createUser({
  user: "mfe",
  pwd: "mfe",
  roles: [
    {
      role: "readWrite",
      db: "mongoose-field-encryption-test"
    }
  ]
})

