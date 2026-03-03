const mongoose = require("mongoose");

const userCloud = new mongoose.Schema({
  id_user: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
  id_classe: { type: mongoose.Schema.Types.ObjectId, ref: "Classe" },
  id_card: {type: mongoose.Schema.Types.ObjectId, ref: 'Card'},

  date: { type: Date, default: Date.now },
  filename:String,
  message:String,
});

module.exports = mongoose.model("Cloud", userCloud);
