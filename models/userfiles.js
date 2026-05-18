const mongoose = require("mongoose");

const userFilesSchema = new mongoose.Schema({
  id_user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  id_classe: { type: mongoose.Schema.Types.ObjectId, ref: "Classe" },
  id_card: { type: mongoose.Schema.Types.ObjectId, ref: "Card" },
  filenames: [
    {
      name: String,
      filename: String,
      date: { type: Date, default: Date.now },
    },
  ],
});

module.exports = mongoose.model("UserFile", userFilesSchema);
