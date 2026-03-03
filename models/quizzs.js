const mongoose = require("mongoose");

const userQuizz = new mongoose.Schema({
  id_user: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
  id_classe: { type: mongoose.Schema.Types.ObjectId, ref: "Classe" },
  id_card: {type: mongoose.Schema.Types.ObjectId, ref: 'Card'},
  date: { type: Date, default: Date.now },
  reponses: [Number],
});

module.exports = mongoose.model("Quizz", userQuizz);
