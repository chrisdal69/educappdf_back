const mongoose = require("mongoose");

const hrefSchema = new mongoose.Schema({
    txt: String,
    href: String,
    hover: { type: String, default: "" },
    visible:Boolean,
});

const quizzSchema = new mongoose.Schema({
    id: String,
    question: String,
    image: String,
    options: [String],
    correct: Number,
});

const flashSchema = new mongoose.Schema({
    id: String,
    question: String,
    imquestion: String,
    reponse: String,
    imreponse: String,
});

const cardSchema = new mongoose.Schema({
  num: Number,
  repertoire: String,
  cloud: Boolean,
  bg: String,
  titre: String,
  content: { type: [mongoose.Schema.Types.Mixed], default: [] },
  contentVersion: { type: Number, default: 1 },
  fichiers: { type: [hrefSchema], default: [] },
  quizz: { type: [quizzSchema], default: [] },
  flash: { type: [flashSchema], default: [] },
  video: { type: [hrefSchema], default: [] },
  evalQuizz:String,
  resultatQuizz:Boolean,
  visible:Boolean,
  order:Number,
  classe:{ type: mongoose.Schema.Types.ObjectId, ref: "Classe" }
});

cardSchema.index({ classe: 1, repertoire: 1, num: 1 }, { unique: true });
cardSchema.index({ classe: 1, repertoire: 1, order: 1 }, { unique: true });

module.exports = mongoose.model("Card", cardSchema);
