module.exports = {
  setupMongoose: function (mongoose) {
    if (mongoose.version) {
      const semanticPieces = mongoose.version.split(".");
      const majorVersion = parseInt(semanticPieces[0]);
      if (majorVersion < 6) {
        mongoose.set("useFindAndModify", false);
      }
    }
  },
};
