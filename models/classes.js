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
});

const classeSchema = new mongoose.Schema({
  teacher: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  directory: {
    type: String,
    unique: true,
    required: true,
    trim: true,
    lowercase: true,
  },
  name: { type: String, required: true, trim: true },
  date: { type: Date, default: Date.now },
  tabs: { type: [String], default: [] },
  code: { type: String, default: "", select: false },
  codeExpires: { type: Date, default: null, select: false },
  students: { type: [studentSchema], default: [] },
  active: { type: Boolean, default: true },
});

module.exports = mongoose.model("Class", classeSchema);
