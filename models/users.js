const mongoose = require("mongoose");

const followSchema = new mongoose.Schema({
    classe: { type: mongoose.Schema.Types.ObjectId, ref: "Classe" },
    role: { type: String, enum: ["user", "admin"], default: "user" }
});


const userSchema = new mongoose.Schema({
  nom: { type: String, required: true, trim: true },
  prenom: { type: String, required: true, trim: true },
  email: { type: String, unique: true, required: true, trim: true, lowercase: true },
  password: { type: String, required: true, select: false },
  date: { type: Date, default: Date.now },
  isVerified: { type: Boolean, default: false },
  confirm: { type: String, default: "", select: false }, // code hashé
  confirmExpires: { type: Date, default: null, select: false },
  status: { type: String, enum: ["eleve", "prof"], default: "eleve" },
  follow: { type: [followSchema], default: [] },
  active: { type: Boolean, default: true },
});

module.exports = mongoose.model("User", userSchema);
