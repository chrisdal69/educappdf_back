const express = require("express");
var router = express.Router();
const jwt = require("jsonwebtoken");
const yup = require("yup");
const User = require("../models/users");
const Classe = require("../models/classes");

const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

/* DEBUT SIGNUP */
// VERIFICATION DONNEE RECUES

const nameRegex = /^[\p{L}\s_-]+$/u;

const signupSchema = yup.object().shape({
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

function removeSpaces(str) {
  if (typeof str !== "string") return "";

  // remplace accents ciblés puis enlève les espaces
  const accentMap = {
    é: "e", ë: "e", è: "e", ê: "e", É: "E", Ë: "E", È: "E", Ê: "E",
    ô: "o", ö: "o", Ô: "O", Ö: "O",
    ü: "u", ù: "u", û: "u", Ü: "U", Ù: "U", Û: "U",
    ï: "i", î: "i", Ï: "I", Î: "I",
    â: "a", à: "a", ä: "a", Â: "A", À: "A", Ä: "A",
    ç: "c", Ç: "C",
  };

  const withoutSpaces = str.replace(/\s+/g, "");
  return withoutSpaces.replace(
    /[éëèêÉËÈÊôöÔÖüùûÜÙÛïîÏÎâàäÂÀÄçÇ]/g,
    (c) => accentMap[c] || ""
  );
}


router.post("/signup", async (req, res) => {
  let { nom, prenom, email, password, confirmPassword } = req.body;
  nom = removeSpaces(nom);
  nom = nom.toUpperCase().trim();
  prenom = removeSpaces(prenom)
  prenom = prenom.toLowerCase().trim();
  email = typeof email === "string" ? email.toLowerCase().trim() : "";
  try {
    // 1️⃣ Validation des données avec Yup
    await signupSchema.validate(
      { nom, prenom, email, password, confirmPassword },
      { abortEarly: false } // pour obtenir toutes les erreurs à la fois
    );

    // 2️⃣ Vérification si l'utilisateur existe déjà par l'email et par le nom, prenom
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: "Cet email est déjà utilisé" });
    }
    const existingUser = await User.findOne({ nom, prenom });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: `L'utilisateur ${nom} ${prenom} est déjà inscrit` });
    }

    // 3️⃣ Validation de l'adresse email récupérée
    const codeAlea = generateCode();
    const hashedCode = await bcrypt.hash(codeAlea, 10); // hash du code avant stockage
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
    <p>Ce code expire dans 10 minutes.</p>
  </div>`,
    };

    const info = await transporter.sendMail(mailOptions);

    // 3️⃣ Hash du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4️⃣ Création de l’utilisateur dans la BDD Mongoose
    const newUser = new User({
      nom,
      prenom,
      email,
      password: hashedPassword,
      confirm: hashedCode,
      confirmExpires: new Date(Date.now() + 10 * 60 * 1000), // 10 min
    });
    const newDoc = await newUser.save();
    console.log("signup : ", newDoc);

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

router.post("/verifmail", async (req, res) => {
  let { email, code } = req.body;
  email = typeof email === "string" ? email.toLowerCase().trim() : "";

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

    // ✅ Active le compte
    await User.updateOne(
      { email },
      {
        $set: { isVerified: true, confirm: "", confirmExpires: null },
      }
    );
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

    const newExpire = new Date(Date.now() + 10 * 60 * 1000); // expire dans 10 min

    // 5️⃣ Met à jour le code dans la base
    await User.updateOne(
      { email },
      { $set: { confirm: newHashedCode, confirmExpires: newExpire } }
    );
    console.log("code dans /resend-code : ", newCode);
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
    <p>Ce code expire dans 10 minutes.</p>
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
    }).select("_id name");

    const classNameById = new Map(
      classes.map((cl) => [cl._id.toString(), cl.name])
    );

    const teacherClassesSummary = [...adminClassIds]
      .filter((id) => classNameById.has(id))
      .map((id) => ({
        id,
        name: classNameById.get(id) || "Classe sans nom",
      }));

    const followedClassesSummary = [...userClassIds]
      .filter((id) => classNameById.has(id))
      .map((id) => ({
        id,
        name: classNameById.get(id) || "Classe sans nom",
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
    }).select("_id name directory tabs");

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
        name: selectedClass.name,
        directory: selectedClass.directory,
        tabs: selectedClass.tabs,
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
      name: selectedClass.name,
      directory: selectedClass.directory,
      tabs: selectedClass.tabs,
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
          confirmExpires: new Date(Date.now() + 10 * 60 * 1000), // expire dans 10 min
        },
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
    <p>Ce code expire dans 10 minutes.</p>
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
    const newExpire = new Date(Date.now() + 10 * 60 * 1000); // expire dans 10 min

    // 5️⃣ Met à jour le code dans la base
    await User.updateOne(
      { email },
      { $set: { confirm: hashedCode, confirmExpires: newExpire } }
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
    <p>Ce code expire dans 10 minutes.</p>
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
