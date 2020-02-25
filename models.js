var mongoose = require("mongoose");

mongoose.model('User',new mongoose.Schema({
    email: String,
    passwordHash: String,
    name: String
}));

mongoose.model('Quote',new mongoose.Schema({
    id: Number,
    quote: String
}));