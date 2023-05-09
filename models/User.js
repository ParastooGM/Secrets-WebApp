const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: String,
  password: String,
  googleID: String,
  facebookID: String,
  secret: String,
});

//hashing and salting with passport
UserSchema.plugin(passportLocalMongoose, {
  usernameField: "username",
});

UserSchema.plugin(findOrCreate);

module.exports = User = mongoose.model("User", UserSchema);
