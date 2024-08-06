const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String },
    contact:{type:String},
    otp: { type: String },
    otpExpiration: { type: Date },
    isVerified: {type:Boolean},
});

module.exports = mongoose.model('User', userSchema);
