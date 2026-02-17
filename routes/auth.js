const express = require("express");
var router = express.Router();
const jwt = require("jsonwebtoken");
const yup = require("yup");
const mongoose = require("mongoose");
const User = require("../models/users");
const Classe = require("../models/classes");

const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

/* DEBUT SIGNUP */
// VERIFICATION DONNEE RECUES

const SIGNUP_CODE_TTL_MS = 7 * 60 * 1000;
const SIGNUP_CODE_TTL_MINUTES = 7;

const nameRegex = /^[\p{L}\s_-]+$/u;

const verifmailcodeSchema = yup.object().shape({
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
  code: yup.string().required("Le code est obligatoire"),
});

// DONNEE POUR ENVOI EMAIL
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_SEND_PASS,
  },
});
function generateCode(length = 4) {
  const chars = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function normalizeNoAccentNoSpaces(value) {
  if (typeof value !== "string") return "";
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, "")
    .trim();
}

function normalizeNom(rawNom) {
  return normalizeNoAccentNoSpaces(rawNom).toUpperCase();
}

function normalizePrenom(rawPrenom) {
  return normalizeNoAccentNoSpaces(rawPrenom).toLowerCase();
}

function normalizeForNameMatch(value) {
  if (typeof value !== "string") return "";
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[\s_-]+/g, "")
    .trim()
    .toLowerCase();
}

function removeSpaces(str) {
  if (typeof str !== "string") return "";

  // remplace accents ciblés puis enlève les espaces
  const accentMap = {
    é: "e",
    ë: "e",
    è: "e",
    ê: "e",
    É: "E",
    Ë: "E",
    È: "E",
    Ê: "E",
    ô: "o",
    ö: "o",
    Ô: "O",
    Ö: "O",
    ü: "u",
    ù: "u",
    û: "u",
    Ü: "U",
    Ù: "U",
    Û: "U",
    ï: "i",
    î: "i",
    Ï: "I",
    Î: "I",
    â: "a",
    à: "a",
    ä: "a",
    Â: "A",
    À: "A",
    Ä: "A",
    ç: "c",
    Ç: "C",
  };

  const withoutSeparators = str.replace(/[\s_-]+/g, "");
  return withoutSeparators.replace(
    /[éëèêÉËÈÊôöÔÖüùûÜÙÛïîÏÎâàäÂÀÄçÇ]/g,
    (c) => accentMap[c] || "",
  );
}

function formatNomForStorage(rawNom) {
  return typeof rawNom === "string" ? rawNom.toUpperCase().trim() : "";
}

function formatPrenomForStorage(rawPrenom) {
  return typeof rawPrenom === "string" ? rawPrenom.toLowerCase().trim() : "";
}

function buildUserPrefix({ nom, prenom }) {
  const upperNom = typeof nom === "string" ? nom.toUpperCase() : "";
  const lowerPrenom = typeof prenom === "string" ? prenom.toLowerCase() : "";
  return `${removeSpaces(upperNom)}${removeSpaces(lowerPrenom)}`;
}

const teacherCodeSchema = yup.object().shape({
  code: yup
    .string()
    .trim()
    .matches(/^[A-Za-z0-9]{4}$/, "Code professeur invalide")
    .required("Le code professeur est obligatoire"),
});

const signupTeacherCodeSchema = yup.object().shape({
  classId: yup
    .string()
    .trim()
    .matches(/^[0-9a-fA-F]{24}$/, "Identifiant de classe invalide")
    .required("La classe est obligatoire"),
  nom: yup
    .string()
    .trim()
    .min(2, "Le nom doit contenir au moins 2 caractères")
    .matches(nameRegex, "Lettres, espaces, - ou _ uniquement")
    .required("Le nom est obligatoire"),
  prenom: yup
    .string()
    .trim()
    .min(2, "Le prénom doit contenir au moins 2 caractères")
    .matches(nameRegex, "Lettres, espaces, - ou _ uniquement")
    .required("Le prénom est obligatoire"),
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
});

const signupCreateSchema = signupTeacherCodeSchema.shape({
  password: yup
    .string()
    .min(8, "8 caractères minimum")
    .matches(/[A-Z]/, "Une majuscule est requise")
    .matches(/[a-z]/, "Une minuscule est requise")
    .matches(/[0-9]/, "Un chiffre est requis")
    .matches(/[^A-Za-z0-9]/, "Un caractère spécial est requis")
    .required("Mot de passe obligatoire"),
  confirmPassword: yup
    .string()
    .oneOf([yup.ref("password"), null], "Les mots de passe ne correspondent pas")
    .required("Confirmez votre mot de passe"),
});

const signupJoinExistingSchema = signupTeacherCodeSchema.shape({
  password: yup.string().required("Mot de passe obligatoire"),
});

const signupCancelSchema = yup.object().shape({
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
});

async function getActiveClassByTeacherCode(rawCode) {
  const trimmed = typeof rawCode === "string" ? rawCode.trim() : "";
  const candidates = [trimmed];
  const upper = trimmed.toUpperCase();
  const lower = trimmed.toLowerCase();
  if (upper && upper !== trimmed) candidates.push(upper);
  if (lower && lower !== trimmed && lower !== upper) candidates.push(lower);

  return Classe.findOne({
    code: { $in: candidates },
    codeExpires: { $gt: new Date() },
    active: true,
  }).select("_id students");
}

async function ensureStudentInClass({ classId, nom, prenom, userObjectId = null }) {
  const classObjectId =
    classId && mongoose.Types.ObjectId.isValid(classId)
      ? new mongoose.Types.ObjectId(classId)
      : null;

  if (!classObjectId) {
    return { ok: false, message: "Ce code n'est pas ou n'est plus valide" };
  }

  const normalizedNom = normalizeNom(nom);
  const normalizedPrenom = normalizePrenom(prenom);

  const classe = await Classe.findOne({
    _id: classObjectId,
    codeExpires: { $gt: new Date() },
    active: true,
  })
    .select("_id students")
    .lean();

  if (!classe) {
    return { ok: false, message: "Ce code n'est pas ou n'est plus valide" };
  }

  const students = Array.isArray(classe.students) ? classe.students : [];
  const studentIndex = students.findIndex((st) => {
    const stNom = normalizeNom(st?.nom || "");
    const stPrenom = normalizePrenom(st?.prenom || "");
    return stNom === normalizedNom && stPrenom === normalizedPrenom;
  });
  const matchedStudent = studentIndex >= 0 ? students[studentIndex] : null;

  if (!matchedStudent) {
    return {
      ok: false,
      message:
        "Nom et prenom non reconnus pour ce code professeur. En informer votre professeur.",
    };
  }

  const isFree = matchedStudent?.free !== false;
  const idUserIsNull = matchedStudent?.id_user == null;
  const idUserMatches =
    userObjectId &&
    matchedStudent?.id_user &&
    matchedStudent.id_user.toString() === userObjectId.toString();

  const canUse = userObjectId
    ? idUserMatches || (isFree && idUserIsNull)
    : isFree && idUserIsNull;

  if (!canUse) {
    return {
      ok: false,
      message: "Cette place n'est plus disponible. En informer votre professeur.",
    };
  }

  return {
    ok: true,
    classObjectId,
    normalizedNom,
    normalizedPrenom,
    studentSubId: matchedStudent?._id || null,
    studentStoredNom: matchedStudent?.nom ?? null,
    studentStoredPrenom: matchedStudent?.prenom ?? null,
    studentIndex,
  };
}

async function claimStudentSlot({
  classId,
  nom,
  prenom,
  userObjectId,
  studentSubId = null,
  studentIndex = null,
}) {
  if (!userObjectId) {
    return { ok: false, message: "Ce code n'est pas ou n'est plus valide" };
  }

  const check = await ensureStudentInClass({ classId, nom, prenom, userObjectId });
  if (!check.ok) return check;

  const classObjectId = check.classObjectId;
  const effectiveStudentSubId = studentSubId || check.studentSubId;
  const effectiveStudentIndex =
    typeof studentIndex === "number" && studentIndex >= 0
      ? studentIndex
      : check.studentIndex;
  const storedNom = check.studentStoredNom;
  const storedPrenom = check.studentStoredPrenom;

  if (
    !effectiveStudentSubId &&
    !(typeof effectiveStudentIndex === "number" && effectiveStudentIndex >= 0)
  ) {
    return { ok: false, message: "Erreur interne du serveur." };
  }

  let studentIdentity;
  let update;

  if (effectiveStudentSubId) {
    studentIdentity = { _id: effectiveStudentSubId };
    update = await Classe.updateOne(
      {
        _id: classObjectId,
        codeExpires: { $gt: new Date() },
        active: true,
        students: {
          $elemMatch: {
            ...studentIdentity,
            $or: [
              { id_user: userObjectId },
              { free: { $ne: false }, id_user: null },
            ],
          },
        },
      },
      {
        $set: {
          "students.$.free": false,
          "students.$.id_user": userObjectId,
        },
      }
    );
  } else if (typeof effectiveStudentIndex === "number" && effectiveStudentIndex >= 0) {
    studentIdentity = { index: effectiveStudentIndex };
    const freePath = `students.${effectiveStudentIndex}.free`;
    const idUserPath = `students.${effectiveStudentIndex}.id_user`;
    const nomPath = `students.${effectiveStudentIndex}.nom`;
    const prenomPath = `students.${effectiveStudentIndex}.prenom`;

    update = await Classe.updateOne(
      {
        _id: classObjectId,
        codeExpires: { $gt: new Date() },
        active: true,
        ...(storedNom ? { [nomPath]: storedNom } : {}),
        ...(storedPrenom ? { [prenomPath]: storedPrenom } : {}),
        $or: [
          { [idUserPath]: userObjectId },
          { [idUserPath]: null, [freePath]: { $ne: false } },
        ],
      },
      { $set: { [freePath]: false, [idUserPath]: userObjectId } }
    );
  }

  const matched = update?.matchedCount ?? update?.n ?? 0;
  const modified = update?.modifiedCount ?? update?.nModified ?? 0;

  if (!matched) {
    let alreadyOwned = null;
    if (studentIdentity?.index !== undefined) {
      alreadyOwned = await Classe.exists({
        _id: classObjectId,
        [`students.${studentIdentity.index}.id_user`]: userObjectId,
      });
    } else if (studentIdentity?._id) {
      alreadyOwned = await Classe.exists({
        _id: classObjectId,
        students: { $elemMatch: { _id: studentIdentity._id, id_user: userObjectId } },
      });
    } else {
      alreadyOwned = await Classe.exists({
        _id: classObjectId,
        students: { $elemMatch: { id_user: userObjectId } },
      });
    }
    if (alreadyOwned) return { ok: true };
    return { ok: false, message: "Cette place n'est plus disponible." };
  }

  if (!modified) return { ok: true };

  return { ok: true };
}

router.post("/signup/validate-teacher-code", async (req, res) => {
  try {
    const { code } = req.body || {};
    await teacherCodeSchema.validate({ code }, { abortEarly: false });

    const classe = await getActiveClassByTeacherCode(code);
    if (!classe) {
      return res.status(400).json({
        message: "Ce code n'est pas ou n'est plus valide",
        redirect: true,
      });
    }

    const students = Array.isArray(classe.students) ? classe.students : [];
    const availableStudents = students.filter(
      (st) => st?.free !== false && (st?.id_user === null || st?.id_user === undefined)
    );

    return res.status(200).json({
      classId: classe._id.toString(),
      students: availableStudents,
    });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    return res.status(400).json({
      message: "Ce code n'est pas ou n'est plus valide",
      redirect: true,
    });
  }
});

router.post("/signup/check-student", async (req, res) => {
  try {
    let { classId, nom, prenom, email } = req.body || {};
    email = typeof email === "string" ? email.toLowerCase().trim() : "";

    await signupTeacherCodeSchema.validate(
      { classId, nom, prenom, email },
      { abortEarly: false }
    );

    const studentCheck = await ensureStudentInClass({ classId, nom, prenom });
    if (!studentCheck.ok) {
      return res
        .status(400)
        .json({ message: studentCheck.message, redirect: true });
    }

    const existingUser = await User.findOne({ email }).select(
      "_id isVerified +signupExpiresAt"
    );

    if (
      existingUser &&
      existingUser.isVerified === false &&
      existingUser.signupExpiresAt &&
      existingUser.signupExpiresAt < new Date()
    ) {
      await User.deleteOne({ _id: existingUser._id, isVerified: false }).catch(
        () => {}
      );
      return res.status(200).json({ emailExists: false });
    }

    return res.status(200).json({ emailExists: !!existingUser });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur /signup/check-student :", error);
    return res.status(500).json({ message: "Erreur interne du serveur." });
  }
});

router.post("/signup/create", async (req, res) => {
  let { classId, nom, prenom, email, password, confirmPassword } = req.body || {};
  const rawNom = nom;
  const rawPrenom = prenom;
  const storedNom = formatNomForStorage(rawNom);
  const storedPrenom = formatPrenomForStorage(rawPrenom);
  const prefix = buildUserPrefix({ nom: rawNom, prenom: rawPrenom });
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    await signupCreateSchema.validate(
      { classId, nom: rawNom, prenom: rawPrenom, email, password, confirmPassword },
      { abortEarly: false }
    );

    const studentCheck = await ensureStudentInClass({
      classId,
      nom: rawNom,
      prenom: rawPrenom,
    });
    if (!studentCheck.ok) {
      return res
        .status(400)
        .json({ message: studentCheck.message, redirect: true });
    }

    const now = new Date();
    const existingEmail = await User.findOne({ email }).select(
      "_id isVerified +signupExpiresAt"
    );
    if (existingEmail) {
      const isExpiredUnverified =
        existingEmail.isVerified === false &&
        existingEmail.signupExpiresAt &&
        existingEmail.signupExpiresAt < now;

      if (isExpiredUnverified) {
        await User.deleteOne({ _id: existingEmail._id, isVerified: false }).catch(
          () => {}
        );
      } else {
        return res.status(400).json({ error: "Cet email est déjà utilisé" });
      }
    }

    const existingUser = await User.findOne({ prefix });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: `L'utilisateur ${storedNom} ${storedPrenom} est déjà inscrit` });
    }

    const codeAlea = generateCode();
    const hashedCode = await bcrypt.hash(codeAlea, 10);

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Inscription MathsApp - Vérification de l'email",
      text: `Bonjour ${prenom},\n\nVotre code de vérification est : ${codeAlea}\nFaire la différence entre majuscule et micuscule\nCe code expire dans ${SIGNUP_CODE_TTL_MINUTES} minutes.`,
      html: `<div style="font-family: Arial, sans-serif; font-size:16px; line-height:1.6;">
    <p>Bonjour ${prenom},</p>
    <p>Votre code de vérification est :</p>
    <div style="font-size:28px; font-weight:bold; letter-spacing:3px;">${codeAlea}</div>
    <p>Faire la différence entre majuscule et minuscule.</p>
    <p>Ce code expire dans ${SIGNUP_CODE_TTL_MINUTES} minutes.</p>
  </div>`,
    };

    const info = await transporter.sendMail(mailOptions);

    const hashedPassword = await bcrypt.hash(password, 10);
    const signupExpiresAt = new Date(Date.now() + SIGNUP_CODE_TTL_MS);

    const newUser = new User({
      nom: storedNom,
      prenom: storedPrenom,
      prefix,
      email,
      password: hashedPassword,
      confirm: hashedCode,
      confirmExpires: signupExpiresAt,
      signupExpiresAt,
    });

    await newUser.save();

    return res
      .status(201)
      .json({ sendMail: true, email, infoMail: info.messageId });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur /signup/create :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

router.post("/signup/cancel", async (req, res) => {
  let { email } = req.body || {};
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    await signupCancelSchema.validate({ email }, { abortEarly: false });

    const user = await User.findOne({ email }).select(
      "_id isVerified +signupExpiresAt",
    );

    if (!user) {
      return res.status(400).json({ message: "Aucun compte trouvé pour cet email." });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "Ce compte est déjà vérifié." });
    }

    if (!user.signupExpiresAt) {
      return res.status(400).json({
        message: "Aucune inscription en attente à annuler pour cet email.",
      });
    }

    const deleted = await User.deleteOne({
      _id: user._id,
      isVerified: false,
      signupExpiresAt: { $ne: null },
    });

    if (deleted.deletedCount !== 1) {
      return res.status(400).json({ message: "Inscription déjà annulée." });
    }

    return res.status(200).json({ canceled: true, message: "Inscription annulée" });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur /signup/cancel :", error);
    return res.status(500).json({ message: "Erreur interne du serveur." });
  }
});

router.post("/signup/join-existing", async (req, res) => {
  let { classId, nom, prenom, email, password } = req.body || {};
  const rawNom = nom;
  const rawPrenom = prenom;
  const normalizedNom = normalizeForNameMatch(nom);
  const normalizedPrenom = normalizeForNameMatch(prenom);
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    await signupJoinExistingSchema.validate(
      { classId, nom: rawNom, prenom: rawPrenom, email, password },
      { abortEarly: false }
    );

    const user = await User.findOne({ email, active: true }).select("+password");
    if (!user || !bcrypt.compareSync(password, user.password) || !user.isVerified) {
      return res.status(401).json({ message: "Identifiants invalides." });
    }

    const nomBdd = user.nom || "";
    const prenomBdd = user.prenom || "";

    if (
      normalizedNom !== normalizeForNameMatch(nomBdd) ||
      normalizedPrenom !== normalizeForNameMatch(prenomBdd)
    ) {
      return res.status(400).json({
        message: `Les nom et prénom correspondant à l'email ${email} ne correspondent pas à ceux déjà saisis qui sont ${nomBdd} ${prenomBdd}. En informer votre professeur`,
        redirect: true,
      });
    }

    if (!user.prefix) {
      const prefix = buildUserPrefix({ nom: user.nom || "", prenom: user.prenom || "" });
      await User.updateOne({ _id: user._id, prefix: { $in: [null, ""] } }, { $set: { prefix } });
    }

    const claim = await claimStudentSlot({
      classId,
      nom: rawNom,
      prenom: rawPrenom,
      userObjectId: user._id,
    });
    if (!claim.ok) {
      const status = claim.message?.includes("place") ? 409 : 400;
      return res.status(status).json({ message: claim.message, redirect: true });
    }

    const classObjectId = new mongoose.Types.ObjectId(classId);
    await User.updateOne(
      {
        _id: user._id,
        follow: { $not: { $elemMatch: { classe: classObjectId } } },
      },
      { $push: { follow: { classe: classObjectId, role: "user" } } }
    );

    return res.status(200).json({ success: true });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur /signup/join-existing :", error);
    return res.status(500).json({ message: "Erreur interne du serveur." });
  }
});

router.post("/verifmail", async (req, res) => {
  let { email, code, classId } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";
  classId = typeof classId === "string" ? classId.trim() : "";

  try {
    // 1️⃣ Validation des données avec Yup
    await verifmailcodeSchema.validate(
      { email, code },
      { abortEarly: false } // pour obtenir toutes les erreurs à la fois
    );

    // 2️⃣ Lecture du code dans la bdd Mongoose
    const user = await User.findOne({ email }).select("+confirm +confirmExpires");

    if (!user) {
      return res
        .status(400)
        .json({ error: "Aucun compte trouvé pour cet email." });
    }

    // ⚠️ Vérifie si déjà vérifié
    if (user.isVerified) {
      return res.status(400).json({ error: "Ce compte est déjà vérifié." });
    }

    // ⏳ Vérifie expiration du code
    if (!user.confirmExpires || user.confirmExpires < new Date()) {
      return res
        .status(400)
        .json({ error: "Le code a expiré. Veuillez en demander un nouveau." });
    }

    // 🔑 Vérifie le code
    const isMatch = bcrypt.compareSync(code, user.confirm);
    console.log("verifmail isMatch: ", isMatch);
    if (!isMatch) {
      return res.status(400).json({ error: "Code incorrect." });
    }

    if (classId && mongoose.Types.ObjectId.isValid(classId)) {
      const claim = await claimStudentSlot({
        classId,
        nom: user.nom,
        prenom: user.prenom,
        userObjectId: user._id,
      });

      if (!claim.ok) {
        const status = claim.message?.includes("place") ? 409 : 400;
        return res.status(status).json({ error: claim.message });
      }

      const classObjectId = new mongoose.Types.ObjectId(classId);
      await User.updateOne(
        { _id: user._id },
        {
          $set: { isVerified: true, confirm: "", confirmExpires: null },
          $unset: { signupExpiresAt: 1 },
          $addToSet: { follow: { classe: classObjectId, role: "user" } },
        }
      );
    } else {
      await User.updateOne(
        { email },
        {
          $set: { isVerified: true, confirm: "", confirmExpires: null },
          $unset: { signupExpiresAt: 1 },
        }
      );
    }

    return res
      .status(200)
      .json({ success: true, message: "Email vérifié avec succès." });
  } catch (error) {
    // Gestion des erreurs de validation Yup
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur lors de l'inscription :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

router.post("/resend-code", async (req, res) => {
  let { email } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    // 1️⃣ Vérifie que l’email est fourni
    if (!email) {
      return res.status(400).json({ error: "L'adresse email est requise." });
    }

    // 2️⃣ Recherche de l’utilisateur
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ error: "Aucun compte trouvé avec cet email." });
    }

    // 3️⃣ Vérifie si déjà vérifié
    if (user.isVerified) {
      return res.status(400).json({ error: "Ce compte est déjà vérifié." });
    }

    // 4️⃣ Génère un nouveau code
    const newCode = generateCode();
    const newHashedCode = await bcrypt.hash(newCode, 10);

    const newExpire = new Date(Date.now() + SIGNUP_CODE_TTL_MS);

    // 5️⃣ Met à jour le code dans la base
    await User.updateOne(
      { email },
      {
        $set: {
          confirm: newHashedCode,
          confirmExpires: newExpire,
          signupExpiresAt: newExpire,
        },
      }
    );
    console.log("code dans /resend-code : ", newCode);
    // 6️⃣ Envoie du nouveau mail

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Inscription MathsApp - Vérification de l’email",
      text: `Bonjour,\n\nVotre code de vérification est : ${newCode}\nFaire la différence entre majuscule et micuscule\nCe code expire dans ${SIGNUP_CODE_TTL_MINUTES} minutes.`,
      html: `<div style="font-family: Arial, sans-serif; font-size:16px; line-height:1.6;">
    <p>Bonjour,</p>
    <p>Votre code de vérification est :</p>
    <div style="font-size:28px; font-weight:bold; letter-spacing:3px;">${newCode}</div>
    <p>Faire la différence entre majuscule et minuscule.</p>
    <p>Ce code expire dans ${SIGNUP_CODE_TTL_MINUTES} minutes.</p>
  </div>`,
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({
      resend: true,
      message: "Un nouveau code a été envoyé par email.",
    });
  } catch (error) {
    console.error("Erreur lors du renvoi du code :", error);
    return res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

/* FIN SIGNUP */
/************************************************************************* */
/* DEBUT LOGIN */
const loginSchema = yup.object().shape({
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
  password: yup
    .string()
    .min(8, "8 caractères minimum")
    .matches(/[A-Z]/, "Une majuscule est requise")
    .matches(/[a-z]/, "Une minuscule est requise")
    .matches(/[0-9]/, "Un chiffre est requis")
    .matches(/[^A-Za-z0-9]/, "Un caractère spécial est requis")
    .required("Mot de passe obligatoire"),
});

const selectClassSchema = yup.object().shape({
  classId: yup
    .string()
    .trim()
    .matches(/^[0-9a-fA-F]{24}$/, "Identifiant de classe invalide")
    .required("La classe est obligatoire"),
});

const buildCookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  ...(maxAge ? { maxAge } : {}),
});

router.post("/login", async (req, res) => {
  let { email, password } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    // 1- Validation des donnees avec Yup
    await loginSchema.validate(
      { email, password },
      { abortEarly: false } // pour obtenir toutes les erreurs a la fois
    );

    // 2- Recherche dans la base de donnees de l'utilisateur et validation pass
    const data = await User.findOne({ email, active: true }).select("+password");
    if (
      !data ||
      !bcrypt.compareSync(password, data.password) ||
      !data.isVerified ||
      data.active === false
    ) {
      return res
        .status(401)
        .json({ message: "Compte inexistant ou non vérifié" });
    }

    // 3. Les classes disponibles sont dans `User.follow` (classe + role)
    const followEntries = Array.isArray(data.follow) ? data.follow : [];
    const adminClassIds = new Set();
    const userClassIds = new Set();

    for (const entry of followEntries) {
      const classeValue =
        entry && typeof entry === "object" ? entry.classe : entry;
      const classId = classeValue ? String(classeValue).trim() : "";
      if (!/^[0-9a-fA-F]{24}$/.test(classId)) {
        continue;
      }

      const followRole =
        entry &&
        typeof entry === "object" &&
        typeof entry.role === "string" &&
        entry.role === "admin"
          ? "admin"
          : "user";

      if (followRole === "admin") {
        adminClassIds.add(classId);
        userClassIds.delete(classId);
      } else if (!adminClassIds.has(classId)) {
        userClassIds.add(classId);
      }
    }

    const allClassIds = [...new Set([...adminClassIds, ...userClassIds])];

    const classes = await Classe.find({
      _id: { $in: allClassIds },
      active: true,
    }).select("_id publicname");

    const classNameById = new Map(
      classes.map((cl) => [cl._id.toString(), cl.publicname])
    );

    const teacherClassesSummary = [...adminClassIds]
      .filter((id) => classNameById.has(id))
      .map((id) => ({
        id,
        publicname: classNameById.get(id) || "Classe sans nom",
      }));

    const followedClassesSummary = [...userClassIds]
      .filter((id) => classNameById.has(id))
      .map((id) => ({
        id,
        publicname: classNameById.get(id) || "Classe sans nom",
      }));

    const totalClasses =
      teacherClassesSummary.length + followedClassesSummary.length;

    if (totalClasses === 0) {
      res.clearCookie("pending_login", buildCookieOptions());
      return res.json({
        message: "Cet utilisateur n'est inscrit à aucun cours",
        teachersClasses: [],
        followedClasses: [],
      });
    }

    const pendingLoginToken = jwt.sign(
      {
        userId: data._id.toString(),
        email: data.email,
        purpose: "class_selection",
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "10m" }
    );

    res.cookie("pending_login", pendingLoginToken, buildCookieOptions(600000));

    return res.json({
      message: "Choisissez une classe",
      teachersClasses: teacherClassesSummary,
      followedClasses: followedClassesSummary,
    });
  } catch (error) {
    // Gestion des erreurs de validation Yup
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur lors de la connexion :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

router.post("/login/select-class", async (req, res) => {
  let { classId } = req.body;
  classId = typeof classId === "string" ? classId.trim() : "";

  try {
    await selectClassSchema.validate(
      { classId },
      { abortEarly: false } // pour obtenir toutes les erreurs a la fois
    );

    const pendingToken = req.cookies.pending_login;
    if (!pendingToken) {
      return res.status(401).json({ message: "Session de connexion expirée" });
    }

    const pendingPayload = jwt.verify(
      pendingToken,
      process.env.ACCESS_TOKEN_SECRET
    );

    if (pendingPayload.purpose !== "class_selection") {
      return res.status(403).json({ message: "Session de connexion invalide" });
    }

    const user = await User.findById(pendingPayload.userId);
    if (!user || !user.isVerified || user.active === false) {
      return res.status(401).json({ message: "Compte inexistant ou non vérifié" });
    }

    const selectedClass = await Classe.findOne({
      _id: classId,
      active: true,
    }).select("_id publicname directoryname repertoires");

    if (!selectedClass) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    // Le role est deja defini dans `User.follow`.

    const followEntry = Array.isArray(user.follow)
      ? user.follow.find((entry) => {
          const followedId =
            entry && typeof entry === "object" ? entry.classe ?? entry : entry;
          return (
            followedId &&
            followedId.toString() === selectedClass._id.toString()
          );
        })
      : null;

    const isFollower = !!followEntry;

    if (!isFollower) {
      return res.status(403).json({ message: "Classe non autorisée" });
    }

    const role = followEntry?.role ?? "user";

    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        nom: user.nom,
        prenom: user.prenom,
        role,
        classId: selectedClass._id,
        publicname: selectedClass.publicname,
        directoryname: selectedClass.directoryname,
        repertoires: selectedClass.repertoires,
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("jwt", accessToken, buildCookieOptions());
    res.clearCookie("pending_login", buildCookieOptions());

    return res.json({
      message: "Connexion réussie",
      email: user.email,
      nom: user.nom,
      prenom: user.prenom,
      role,
      classId: selectedClass._id,
      publicname: selectedClass.publicname,
      directoryname: selectedClass.directoryname,
      repertoires: selectedClass.repertoires,
    });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }

    if (error.name === "TokenExpiredError") {
      res.clearCookie("pending_login", buildCookieOptions());
      return res.status(401).json({ message: "Session de connexion expirée" });
    }

    console.error("Erreur lors de la validation de classe :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

/* FIN LOGIN */
/************************************************************************* */
/* DEBUT LOGOUT */
router.post("/logout", async (req, res) => {
  res.clearCookie("jwt");
  res.clearCookie("pending_login");
  return res.json({ message: "Déconnexion réussie" });
});

/* FIN LOGOUT */
/************************************************************************* */

/* DEBUT FORGOT */
const FORGOT_CODE_TTL_MS = 7 * 60 * 1000;
const FORGOT_CODE_TTL_MINUTES = 7;

const verifmailSchema = yup.object().shape({
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
});
const verifmailcodepassSchema = yup.object().shape({
  email: yup
    .string()
    .trim()
    .email("Adresse email invalide")
    .required("L'email est obligatoire"),
  newPassword: yup
    .string()
    .min(8, "8 caractères minimum")
    .matches(/[A-Z]/, "Une majuscule est requise")
    .matches(/[a-z]/, "Une minuscule est requise")
    .matches(/[0-9]/, "Un chiffre est requis")
    .matches(/[^A-Za-z0-9]/, "Un caractère spécial est requis")
    .required("Mot de passe obligatoire"),
  code: yup.string().required("Le code est obligatoire"),
});
router.post("/forgot", async (req, res) => {
  let { email } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";
  try {
    // 1️⃣ Validation des données avec Yup
    await verifmailSchema.validate(
      { email },
      { abortEarly: false } // pour obtenir toutes les erreurs à la fois
    );

    // 2️⃣ Vérification si cet email existe bien
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Cet email n'est pas connu" });
    }
    if (!user.isVerified) {
      return res
        .status(400)
        .json({ error: "Ce compte n’a pas encore été vérifié." });
    }
    // 3️⃣ Envoi d'un code de validation
    const codeAlea = generateCode();
    const hashedCode = await bcrypt.hash(codeAlea, 10); // hash du code avant stockage
    const prenom = user.prenom;
    await User.updateOne(
      { email },
      {
        $set: {
          confirm: hashedCode,
          confirmExpires: new Date(Date.now() + FORGOT_CODE_TTL_MS),
        },
        $unset: { signupExpiresAt: 1 },
      }
    );

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Inscription MathsApp - Vérification de l’email",
      text: `Bonjour ${prenom},\n\nVotre code de vérification est : ${codeAlea}\nFaire la différence entre majuscule et micuscule\nCe code expire dans 10 minutes.`,
      html: `<div style="font-family: Arial, sans-serif; font-size:16px; line-height:1.6;">
    <p>Bonjour ${prenom},</p>
    <p>Votre code de vérification est :</p>
    <div style="font-size:28px; font-weight:bold; letter-spacing:3px;">${codeAlea}</div>
    <p>Faire la différence entre majuscule et minuscule.</p>
    <p>Ce code expire dans ${FORGOT_CODE_TTL_MINUTES} minutes.</p>
  </div>`,
    };

    const info = await transporter.sendMail(mailOptions);

    // 5️⃣ Réponse OK
    return res
      .status(201)
      .json({ sendMail: true, email, infoMail: info.messageId });
  } catch (error) {
    // Gestion des erreurs de validation Yup
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur lors de l'inscription :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

router.post("/resend-forgot", async (req, res) => {
  let { email } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

  try {
    // 1️⃣ Vérifie que l’email est fourni
    if (!email) {
      return res.status(400).json({ error: "L'adresse email est requise." });
    }

    // 2️⃣ Recherche de l’utilisateur
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ error: "Aucun compte trouvé avec cet email." });
    }

    // 3️⃣ Vérifie si déjà vérifié
    if (!user.isVerified) {
      return res
        .status(400)
        .json({ error: "Ce compte n'a pas été vérifié à l'inscription." });
    }

    // 4️⃣ Génère un nouveau code
    const newCode = generateCode();
    const hashedCode = await bcrypt.hash(newCode, 10);
    const newExpire = new Date(Date.now() + FORGOT_CODE_TTL_MS);

    // 5️⃣ Met à jour le code dans la base
    await User.updateOne(
      { email },
      { $set: { confirm: hashedCode, confirmExpires: newExpire }, $unset: { signupExpiresAt: 1 } }
    );

    // 6️⃣ Envoie du nouveau mail
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Inscription MathsApp - Vérification de l’email",
      text: `Bonjour,\n\nVotre code de vérification est : ${newCode}\nFaire la différence entre majuscule et micuscule\nCe code expire dans 10 minutes.`,
      html: `<div style="font-family: Arial, sans-serif; font-size:16px; line-height:1.6;">
    <p>Bonjour,</p>
    <p>Votre code de vérification est :</p>
    <div style="font-size:28px; font-weight:bold; letter-spacing:3px;">${newCode}</div>
    <p>Faire la différence entre majuscule et minuscule.</p>
    <p>Ce code expire dans ${FORGOT_CODE_TTL_MINUTES} minutes.</p>
  </div>`,
    };
    await transporter.sendMail(mailOptions);

    return res.status(200).json({
      resend: true,
      message: "Un nouveau code a été envoyé par email.",
    });
  } catch (error) {
    console.error("Erreur lors du renvoi du code :", error);
    return res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

router.post("/reset-password", async (req, res) => {
  let { email, code, newPassword } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";
  try {
    // 1️⃣ Validation des données avec Yup
    await verifmailcodepassSchema.validate(
      { email, code, newPassword },
      { abortEarly: false } // pour obtenir toutes les erreurs à la fois
    );

    // 2️⃣ Lecture du code dans la bdd Mongoose
    const user = await User.findOne({ email }).select("+confirm +confirmExpires");
    if (!user) {
      return res
        .status(400)
        .json({ error: "Aucun compte trouvé pour cet email." });
    }
    // ⏳ Vérifie expiration du code
    if (!user.confirmExpires || user.confirmExpires < new Date()) {
      return res
        .status(400)
        .json({ error: "Le code a expiré. Veuillez en demander un nouveau." });
    }
    // 🔑 Vérifie le code
    const isMatch = await bcrypt.compare(code, user.confirm);
    if (!isMatch) {
      return res
        .status(400)
        .json({ error: "Code saisi précédemment incorrect : Retour et réessayer !" });
    }
    // ✅ Active le compte
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.updateOne(
      { email },
      {
        $set: {
          password: hashedPassword,
          confirm: "",
          confirmExpires: null,
        },
        $unset: { signupExpiresAt: 1 },
      }
    );
    return res.status(200).json({
      success: true,
      message: "Mot de passe mis à jour avec succès.",
    });
  } catch (error) {
    // Gestion des erreurs de validation Yup
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur lors de l'inscription :", error);
    return res.status(500).json({ error: "Erreur interne du serveur" });
  }
});

/* FIN FORGOT */
/************************************************************************* */
/* Route pour verif cookies (non utilisé) */
router.get("/me", async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.status(401).json({ error: "Non authentifié" });

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const { email, nom, prenom, role } = decoded;
    res.json({ user: { email, nom, prenom, role } });
  } catch (err) {
    res.status(403).json({ error: "Token invalide ou expiré" });
  }
});

module.exports = router;
