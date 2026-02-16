const express = require("express");
const router = express.Router();
const { authenticate, authorize } = require("../middlewares/auth");
const mongoose = require("mongoose");
const User = require("../models/users");
const Classe = require("../models/classes");
const yup = require("yup");
const bcrypt = require("bcrypt");

const buildCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
});

/* DEBUT info utilisateur */
router.get("/me", authenticate, (req, res) => {
  const { email, nom, prenom, role } = req.user;
  console.log("email, nom, prenom, role : ", email, nom, prenom, role);
  res.json({ email, nom, prenom, role });
});
/* FIN info utilisateur */

/************************************************************************* */

/* DEBUT Changepassword */
const schema = yup.object().shape({
  newPassword: yup
    .string()
    .min(8, "8 caractères minimum")
    .matches(/[A-Z]/, "Une majuscule est requise")
    .matches(/[a-z]/, "Une minuscule est requise")
    .matches(/[0-9]/, "Un chiffre est requis")
    .matches(/[^A-Za-z0-9]/, "Un caractère spécial est requis")
    .required("Mot de passe obligatoire"),
});
router.post("/change-password", authenticate, async (req, res) => {
  const { newPassword } = req.body;
  console.log("etape 1 : ", newPassword);
  try {
    // Vérifie la présence du nouveau mot de passe
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: "Mot de passe invalide." });
    }
    // Validation des données avec Yup
    await schema.validate(
      { newPassword },
      { abortEarly: false } // pour obtenir toutes les erreurs à la fois
    );
    console.log("etape 2 : ", newPassword);

    // Récupère l’utilisateur connecté via req.user.userId
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "Utilisateur introuvable." });
    }
    console.log("etape 3 : ", user);

    // Hash le nouveau mot de passe
    const hashed = await bcrypt.hash(newPassword, 10);

    //  Met à jour l’utilisateur
    user.password = hashed;
    await user.save();

    // Réponse au client
    return res.json({
      success: true,
      message: "Mot de passe changé avec succès ✅",
    });
  } catch (err) {
    if (err.name === "ValidationError") {
      const validationErrors = err.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }
    console.error("Erreur changement mot de passe :", err);
    return res.status(500).json({ error: "Erreur serveur." });
  }
});
/* FIN Changepassword */

/* DEBUT leave class (unfollow) */
const leaveClassSchema = yup.object().shape({
  classId: yup
    .string()
    .trim()
    .matches(/^[0-9a-fA-F]{24}$/, "Identifiant de classe invalide")
    .required("La classe est obligatoire"),
});

router.post("/leave-class", authenticate, async (req, res) => {
  let { classId } = req.body || {};
  classId = typeof classId === "string" ? classId.trim() : "";
  try {
    await leaveClassSchema.validate({ classId }, { abortEarly: false });

    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ message: "Utilisateur non authentifié." });
    }

    

    const pullCandidates = [classId];
    const lower = classId.toLowerCase();
    if (lower !== classId) {
      pullCandidates.push(lower);
    }
    const classObjectId = new mongoose.Types.ObjectId(classId);
    pullCandidates.push(classObjectId);

    const userObjectId = mongoose.Types.ObjectId.isValid(userId)
      ? new mongoose.Types.ObjectId(userId)
      : null;

    if (!userObjectId) {
      return res.status(401).json({ message: "Token invalide." });
    }

    // Utiliser le driver natif pour éviter le casting Mongoose sur `follow`.
    const [updateNewShape, updateOldShape] = await Promise.all([
      User.collection.updateOne(
        { _id: userObjectId },
        { $pull: { follow: { classe: classObjectId } } }
      ),
      User.collection.updateOne(
        { _id: userObjectId },
        { $pull: { follow: { $in: pullCandidates } } }
      ),
    ]);

    const matched = updateNewShape?.matchedCount ?? updateNewShape?.n ?? 0;
    const modifiedNew =
      updateNewShape?.modifiedCount ?? updateNewShape?.nModified ?? 0;
    const modifiedOld =
      updateOldShape?.modifiedCount ?? updateOldShape?.nModified ?? 0;
    const modified = modifiedNew + modifiedOld;

    if (!matched) {
      return res.status(404).json({ message: "Utilisateur introuvable." });
    }

    if (!modified) {
      return res
        .status(400)
        .json({ message: "Impossible de se désinscrire de cette classe" });
    }

    return res.status(200).json({ message: "Désinscription réalisée" });
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = error.inner.map((err) => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({ errors: validationErrors });
    }

    console.error("Erreur leave-class :", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});
/* FIN leave class (unfollow) */

/* DEBUT delete account */
router.post("/delete-account", authenticate, async (req, res) => {
  try {
    const userId = req.user?.userId;
    const userObjectId = mongoose.Types.ObjectId.isValid(userId)
      ? new mongoose.Types.ObjectId(userId)
      : null;

    if (!userObjectId) {
      return res.status(401).json({ message: "Token invalide." });
    }

    const isTeacher = await Classe.exists({ teacher: userObjectId });
    if (isTeacher) {
      return res
        .status(403)
        .json({ message: "Impossible pour un professeur de se désinscrire" });
    }

    const deletion = await User.deleteOne({ _id: userObjectId });
    const deleted =
      deletion?.deletedCount ?? deletion?.n ?? deletion?.nRemoved ?? 0;

    if (!deleted) {
      return res.status(400).json({ message: "Désinscription impossible" });
    }

    res.clearCookie("jwt", buildCookieOptions());
    res.clearCookie("pending_login", buildCookieOptions());
    return res.status(200).json({ message: "Suppression de compte réalisée" });
  } catch (error) {
    console.error("Erreur delete-account :", error);
    return res.status(500).json({ message: "Désinscription impossible" });
  }
});
/* FIN delete account */

module.exports = router;
