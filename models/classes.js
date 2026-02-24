const mongoose = require("mongoose");

const normalizeNoAccent = (value) => {
  if (typeof value !== "string") return "";
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
};

const normalizeUpperNoAccent = (value) =>
  normalizeNoAccent(value).trim().toUpperCase();

const normalizeLowerNoAccent = (value) =>
  normalizeNoAccent(value).trim().toLowerCase();

const studentSchema = new mongoose.Schema({
  nom: {
    type: String,
    required: true,
    set: normalizeUpperNoAccent,
  },
  prenom: {
    type: String,
    required: true,
    set: normalizeLowerNoAccent,
  },
  free: { type: Boolean, select: true },
  id_user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
});

const repertoiresSchema = new mongoose.Schema({
  repertoire: { type: String, required: true, trim: true },
  teachers: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    default: [],
  },
});

const classeSchema = new mongoose.Schema({
  directoryname: {
    type: String,
    unique: true,
    required: true,
    trim: true,
    lowercase: true,
  },
  publicname: { type: String, required: true, trim: true },
  date: { type: Date, default: Date.now },
  repertoires: { type: [repertoiresSchema], default: [] },
  code: { type: String, default: "", select: false },
  codeExpires: { type: Date, default: null, select: false },
  students: { type: [studentSchema], default: [] },
  active: { type: Boolean, default: true },
  exceptionvisible: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    default: [],
  },
});

module.exports = mongoose.model("Classe", classeSchema);
