const express = require("express");
const router = express.Router();
const { authenticate, authorize, requireAdmin } = require("../middlewares/auth");
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

    await Classe.updateOne(
      { _id: classObjectId },
      {
        $set: {
          "students.$[st].free": true,
          "students.$[st].id_user": null,
        },
      },
      { arrayFilters: [{ "st.id_user": userObjectId }] }
    ).catch((err) => {
      console.error("Erreur libération student slot :", err);
    });

    await Classe.updateOne(
      { _id: classObjectId },
      { $pull: { "repertoires.$[].teachers": userObjectId } }
    ).catch((err) => {
      console.error("Erreur suppression teacher rights :", err);
    });

    // Le JWT courant est lié à la classe sélectionnée: on le retire.
    await Classe.updateOne(
      { _id: classObjectId },
      { $pull: { exceptionvisible: userObjectId } }
    ).catch((err) => {
      console.error("Erreur suppression exceptionvisible :", err);
    });

    res.clearCookie("jwt", buildCookieOptions());
    res.clearCookie("pending_login", buildCookieOptions());

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

    const isTeacher = await User.exists({
      _id: userObjectId,
      follow: { $elemMatch: { role: "admin" } },
    });
    if (isTeacher) {
      return res
        .status(403)
        .json({ message: "Impossible pour un professeur de se désinscrire" });
    }

    const rawUser = await User.collection.findOne(
      { _id: userObjectId },
      { projection: { follow: 1 } }
    );
    const follow = Array.isArray(rawUser?.follow) ? rawUser.follow : [];
    const classObjectIds = follow
      .map((entry) => {
        if (!entry) return null;
        if (typeof entry === "string") {
          return mongoose.Types.ObjectId.isValid(entry)
            ? new mongoose.Types.ObjectId(entry)
            : null;
        }
        const id = entry?.classe ?? entry;
        return id && mongoose.Types.ObjectId.isValid(id)
          ? new mongoose.Types.ObjectId(id)
          : null;
      })
      .filter(Boolean);

    if (classObjectIds.length) {
      await Classe.updateMany(
        { _id: { $in: classObjectIds } },
        {
          $set: {
            "students.$[st].free": true,
            "students.$[st].id_user": null,
          },
        },
        { arrayFilters: [{ "st.id_user": userObjectId }] }
      );
    }

    await Classe.updateMany(
      { "repertoires.teachers": userObjectId },
      { $pull: { "repertoires.$[].teachers": userObjectId } }
    ).catch((err) => {
      console.error("Erreur suppression teacher rights :", err);
    });

    await Classe.updateMany(
      { exceptionvisible: userObjectId },
      { $pull: { exceptionvisible: userObjectId } }
    ).catch((err) => {
      console.error("Erreur suppression exceptionvisible :", err);
    });

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

/* DEBUT admin manage class students */
const objectIdSchema = yup
  .string()
  .trim()
  .matches(/^[0-9a-fA-F]{24}$/, "Identifiant invalide")
  .required("Identifiant obligatoire");

const adminClassSchema = yup.object().shape({
  classId: objectIdSchema,
});

const adminStudentSchema = yup.object().shape({
  classId: objectIdSchema,
  studentId: objectIdSchema,
});

const adminCreateStudentSchema = yup.object().shape({
  classId: objectIdSchema,
  nom: yup
    .string()
    .trim()
    .min(1, "Nom obligatoire")
    .max(80, "Nom trop long")
    .required("Nom obligatoire"),
  prenom: yup
    .string()
    .trim()
    .min(1, "Prénom obligatoire")
    .max(80, "Prénom trop long")
    .required("Prénom obligatoire"),
});

const adminUploadStudentsSchema = yup.object().shape({
  classId: objectIdSchema,
});

const adminCodeDurationSchema = yup.object().shape({
  classId: objectIdSchema,
  duration: yup
    .string()
    .oneOf(["3d", "1w", "2w"], "Durée invalide")
    .required("Durée obligatoire"),
});

const isAdminForClass = (req, classId) =>
  req?.user?.classId && String(req.user.classId) === String(classId);

const handleYupError = (error, res) => {
  if (error?.name !== "ValidationError") return false;
  const validationErrors = error.inner.map((err) => ({
    field: err.path,
    message: err.message,
  }));
  res.status(400).json({ errors: validationErrors });
  return true;
};

const stripAccentsLower = (value) =>
  String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();

const toSlug = (value) =>
  stripAccentsLower(value)
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

const adminTeachersSchema = yup.object().shape({
  classId: objectIdSchema,
  userId: objectIdSchema,
  adminRepertoires: yup
    .array()
    .of(
      yup
        .string()
        .trim()
        .matches(/^[a-z0-9-]{1,60}$/, "Repertoire invalide")
    )
    .default([]),
});

const adminExceptionVisibleSchema = yup.object().shape({
  classId: objectIdSchema,
  userId: objectIdSchema.notRequired(),
  studentId: objectIdSchema.notRequired(),
});

router.get("/admin/class/:classId/repertoires", requireAdmin, async (req, res) => {
  const { classId } = req.params || {};
  try {
    await adminClassSchema.validate({ classId }, { abortEarly: false });

    if (!isAdminForClass(req, classId)) {
      return res.status(403).json({ message: "Classe non autorisÃ©e" });
    }

    const classe = await Classe.findById(classId).select("repertoires").lean();
    if (!classe) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    const reps = Array.isArray(classe.repertoires) ? classe.repertoires : [];
    const repertoires = reps
      .map((rep) => {
        const label = typeof rep?.repertoire === "string" ? rep.repertoire.trim() : "";
        const slug = toSlug(label);
        if (!label || !slug) return null;
        const teachers = Array.isArray(rep?.teachers)
          ? rep.teachers
              .filter(Boolean)
              .map((teacherId) =>
                teacherId?.toString ? teacherId.toString() : String(teacherId)
              )
          : [];

        return { slug, label, teachers };
      })
      .filter(Boolean);

    return res.status(200).json({ repertoires });
  } catch (error) {
    if (handleYupError(error, res)) return;
    console.error("Erreur admin class repertoires:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

router.patch(
  "/admin/class/:classId/repertoires/teachers",
  requireAdmin,
  async (req, res) => {
    const { classId } = req.params || {};
    const { userId, adminRepertoires } = req.body || {};

    try {
      await adminTeachersSchema.validate(
        { classId, userId, adminRepertoires },
        { abortEarly: false }
      );

      if (!isAdminForClass(req, classId)) {
        return res.status(403).json({ message: "Classe non autorisÃ©e" });
      }

      const classe = await Classe.findById(classId).select("repertoires");
      if (!classe) {
        return res.status(404).json({ message: "Classe introuvable" });
      }

      const selected = new Set(
        Array.isArray(adminRepertoires) ? adminRepertoires : []
      );
      const teacherObjectId = new mongoose.Types.ObjectId(userId);
      const teacherIdStr = teacherObjectId.toString();

      const reps = Array.isArray(classe.repertoires) ? classe.repertoires : [];
      reps.forEach((rep) => {
        const label = typeof rep?.repertoire === "string" ? rep.repertoire.trim() : "";
        const slug = toSlug(label);
        if (!slug) return;

        const currentTeachers = Array.isArray(rep.teachers) ? rep.teachers : [];
        const hasTeacher = currentTeachers.some(
          (id) => id && id.toString && id.toString() === teacherIdStr
        );

        if (selected.has(slug)) {
          if (!hasTeacher) {
            currentTeachers.push(teacherObjectId);
          }
          rep.teachers = currentTeachers;
          return;
        }

        if (hasTeacher) {
          rep.teachers = currentTeachers.filter(
            (id) => !(id && id.toString && id.toString() === teacherIdStr)
          );
        }
      });

      await classe.save();

      const repertoires = reps
        .map((rep) => {
          const label = typeof rep?.repertoire === "string" ? rep.repertoire.trim() : "";
          const slug = toSlug(label);
          if (!label || !slug) return null;
          const teachers = Array.isArray(rep?.teachers)
            ? rep.teachers
                .filter(Boolean)
                .map((teacherId) =>
                  teacherId?.toString ? teacherId.toString() : String(teacherId)
                )
            : [];
          return { slug, label, teachers };
        })
        .filter(Boolean);

      return res.status(200).json({ repertoires });
    } catch (error) {
      if (handleYupError(error, res)) return;
      console.error("Erreur update admin teachers:", error);
      return res.status(500).json({ message: "Erreur serveur." });
    }
  }
);

router.patch(
  "/admin/class/:classId/exceptionvisible",
  requireAdmin,
  async (req, res) => {
    const { classId } = req.params || {};
    const { userId, studentId } = req.body || {};

    try {
      await adminExceptionVisibleSchema.validate(
        { classId, userId, studentId },
        { abortEarly: false }
      );

      if (!isAdminForClass(req, classId)) {
        return res.status(403).json({ message: "Classe non autorisée" });
      }

      const classe = await Classe.findById(classId).select(
        "students exceptionvisible"
      );
      if (!classe) {
        return res.status(404).json({ message: "Classe introuvable" });
      }

      const students = Array.isArray(classe?.students) ? classe.students : [];

      let targetUserId = typeof userId === "string" ? userId.trim() : "";
      const targetStudentId =
        typeof studentId === "string" ? studentId.trim() : "";

      if (targetStudentId) {
        const student = students.find(
          (st) => st?._id && String(st._id) === String(targetStudentId)
        );
        if (!student || student?.free !== false || !student?.id_user) {
          return res.status(400).json({ message: "Utilisateur non inscrit." });
        }
        targetUserId = String(student.id_user);
      }

      if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
        return res.status(400).json({ message: "Identifiant invalide" });
      }

      const isRegisteredStudent = students.some((st) => {
        if (!st || st.free !== false) return false;
        const id = st.id_user ? String(st.id_user) : "";
        return id && id === String(targetUserId);
      });

      if (!isRegisteredStudent) {
        return res.status(400).json({ message: "Utilisateur non inscrit." });
      }

      const userObjectId = new mongoose.Types.ObjectId(targetUserId);
      const userIdStr = userObjectId.toString();

      const registeredUserIds = new Set(
        students
          .filter((st) => st?.free === false && st?.id_user)
          .map((st) => String(st.id_user))
      );

      const rawCurrent = Array.isArray(classe.exceptionvisible)
        ? classe.exceptionvisible
        : [];
      const current = rawCurrent.filter(
        (id) => id && id.toString && registeredUserIds.has(id.toString())
      );
      if (current.length !== rawCurrent.length) {
        classe.exceptionvisible = current;
      }
      const hasUser = current.some(
        (id) => id && id.toString && id.toString() === userIdStr
      );

      if (hasUser) {
        classe.exceptionvisible = current.filter(
          (id) => !(id && id.toString && id.toString() === userIdStr)
        );
      } else {
        classe.exceptionvisible = [...current, userObjectId];
      }

      await classe.save();

      const exceptionvisible = Array.isArray(classe.exceptionvisible)
        ? classe.exceptionvisible
            .filter(Boolean)
            .map((id) => (id?.toString ? id.toString() : String(id)))
        : [];

      return res.status(200).json({ exceptionvisible, enabled: !hasUser });
    } catch (error) {
      if (handleYupError(error, res)) return;
      console.error("Erreur update exceptionvisible:", error);
      return res.status(500).json({ message: "Erreur serveur." });
    }
  }
);

router.get("/admin/class/:classId/students", requireAdmin, async (req, res) => {
  const { classId } = req.params || {};
  try {
    await adminClassSchema.validate({ classId }, { abortEarly: false });

    if (!isAdminForClass(req, classId)) {
      return res.status(403).json({ message: "Classe non autorisée" });
    }

    const classe = await Classe.findById(classId)
      .select("students exceptionvisible")
      .lean();
    if (!classe) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    const students = Array.isArray(classe.students) ? classe.students : [];
    const followedUserIds = students
      .filter((st) => st?.free === false && st?.id_user)
      .map((st) => String(st.id_user));

    const users =
      followedUserIds.length > 0
        ? await User.find({ _id: { $in: followedUserIds } })
            .select("nom prenom email")
            .lean()
        : [];

    const userById = new Map(users.map((u) => [String(u._id), u]));

    const resolvedStudents = students.map((st) => {
      const free = st?.free !== false;
      const userId = st?.id_user ? String(st.id_user) : null;
      const user = userId ? userById.get(userId) : null;
      const email = user?.email ?? st?.email ?? null;

      return {
        studentId: st?._id ? String(st._id) : null,
        free,
        userId,
        nom: user?.nom ?? st?.nom ?? null,
        prenom: user?.prenom ?? st?.prenom ?? null,
        email,
      };
    });

    const exceptionvisible = Array.isArray(classe?.exceptionvisible)
      ? classe.exceptionvisible
          .filter(Boolean)
          .map((id) => (id?.toString ? id.toString() : String(id)))
      : [];

    return res.status(200).json({ students: resolvedStudents, exceptionvisible });
  } catch (error) {
    if (handleYupError(error, res)) return;
    console.error("Erreur admin class students:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

router.get("/admin/class/:classId/code", requireAdmin, async (req, res) => {
  const { classId } = req.params || {};
  try {
    await adminClassSchema.validate({ classId }, { abortEarly: false });

    if (!isAdminForClass(req, classId)) {
      return res.status(403).json({ message: "Classe non autorisée" });
    }

    const classe = await Classe.findById(classId)
      .select("+code +codeExpires")
      .lean();
    if (!classe) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    return res.status(200).json({
      code: classe?.code || "",
      codeExpires: classe?.codeExpires ? new Date(classe.codeExpires).toISOString() : null,
    });
  } catch (error) {
    if (handleYupError(error, res)) return;
    console.error("Erreur admin class code:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

const CODE_CHARS =
  "abcdefghjklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789";

const generateRandomCode = (length = 4) => {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
  }
  return out;
};

const generateUniqueActiveCode = async (now, maxAttempts = 200) => {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const code = generateRandomCode(4);
    // Ne doit pas entrer en collision avec un code encore valide.
    const exists = await Classe.exists({ code, codeExpires: { $gt: now } });
    if (!exists) return code;
  }
  throw new Error("Impossible de générer un code unique.");
};

router.post("/admin/class/:classId/code/regenerate", requireAdmin, async (req, res) => {
  const { classId } = req.params || {};
  const { duration } = req.body || {};
  try {
    await adminCodeDurationSchema.validate({ classId, duration }, { abortEarly: false });

    if (!isAdminForClass(req, classId)) {
      return res.status(403).json({ message: "Classe non autorisée" });
    }

    const classeExists = await Classe.exists({ _id: classId });
    if (!classeExists) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    const now = new Date();
    const days =
      duration === "3d" ? 3 : duration === "1w" ? 7 : duration === "2w" ? 14 : 0;
    const nextExpires = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

    const nextCode = await generateUniqueActiveCode(now);

    const update = await Classe.updateOne(
      { _id: classId },
      { $set: { code: nextCode, codeExpires: nextExpires } }
    );
    const matched = update?.matchedCount ?? update?.n ?? 0;
    const modified = update?.modifiedCount ?? update?.nModified ?? 0;

    if (!matched) {
      return res.status(404).json({ message: "Classe introuvable" });
    }
    if (!modified) {
      return res.status(400).json({ message: "Mise à jour impossible" });
    }

    return res.status(200).json({
      code: nextCode,
      codeExpires: nextExpires.toISOString(),
    });
  } catch (error) {
    if (handleYupError(error, res)) return;
    console.error("Erreur regenerate code:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

router.post("/admin/class/:classId/students", requireAdmin, async (req, res) => {
  const { classId } = req.params || {};
  const { nom, prenom } = req.body || {};
  try {
    await adminCreateStudentSchema.validate(
      { classId, nom, prenom },
      { abortEarly: false }
    );

    if (!isAdminForClass(req, classId)) {
      return res.status(403).json({ message: "Classe non autorisée" });
    }

    const classe = await Classe.findById(classId).select("students");
    if (!classe) {
      return res.status(404).json({ message: "Classe introuvable" });
    }

    classe.students.push({
      nom,
      prenom,
      free: true,
      id_user: null,
    });

    await classe.save();

    const created = Array.isArray(classe.students)
      ? classe.students[classe.students.length - 1]
      : null;

    return res.status(201).json({
      studentId: created?._id ? String(created._id) : null,
    });
  } catch (error) {
    if (handleYupError(error, res)) return;
    console.error("Erreur create student:", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

router.post(
  "/admin/class/:classId/students/upload",
  requireAdmin,
  async (req, res) => {
    const { classId } = req.params || {};
    try {
      await adminUploadStudentsSchema.validate({ classId }, { abortEarly: false });

      if (!isAdminForClass(req, classId)) {
        return res.status(403).json({ message: "Classe non autorisée" });
      }

      const file = req?.files?.file;
      if (!file) {
        return res.status(400).json({ message: "Fichier manquant." });
      }

      const originalName = String(file?.name || "");
      const lower = originalName.toLowerCase();
      const isCsvOrTxt = lower.endsWith(".csv") || lower.endsWith(".txt");

      if (!isCsvOrTxt) {
        return res.status(400).json({
          message:
            "Format non supporté. Merci d'utiliser un fichier .csv ou .txt (ou exporter Excel en CSV).",
        });
      }

      const buffer = file?.data;
      const decodeTextBuffer = (buf) => {
        if (!Buffer.isBuffer(buf)) return "";
        if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
          return buf.slice(3).toString("utf8");
        }
        if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
          return buf.slice(2).toString("utf16le");
        }
        if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
          const sliced = buf.slice(2);
          const swapped = Buffer.allocUnsafe(sliced.length - (sliced.length % 2));
          for (let i = 0; i < swapped.length; i += 2) {
            swapped[i] = sliced[i + 1];
            swapped[i + 1] = sliced[i];
          }
          return swapped.toString("utf16le");
        }

        const utf8 = buf.toString("utf8");
        const replacementCount = (utf8.match(/\uFFFD/g) || []).length;
        if (replacementCount > 0) {
          const latin1 = buf.toString("latin1");
          if (!latin1.includes("\u0000")) return latin1;
        }
        return utf8;
      };

      const raw = decodeTextBuffer(buffer);
      if (!raw.trim()) {
        return res.status(400).json({ message: "Fichier vide." });
      }

      const rows = raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

      const parsed = rows
        .map((line) => {
          const parts = line.split(/[;,]/).map((p) => p.trim());
          const nom = parts[0] || "";
          const prenom = parts[1] || "";
          return { nom, prenom };
        })
        .filter(({ nom, prenom }) => nom && prenom)
        .filter(({ nom, prenom }) => {
          const n = nom.toLowerCase();
          const p = prenom.toLowerCase();
          return !(n === "nom" && (p === "prenom" || p === "prénom"));
        });

      if (!parsed.length) {
        return res.status(400).json({
          message:
            "Aucun élève détecté. Format attendu : Nom,prenom (une ligne par élève).",
        });
      }

      const classe = await Classe.findById(classId).select("students");
      if (!classe) {
        return res.status(404).json({ message: "Classe introuvable" });
      }

      parsed.forEach(({ nom, prenom }) => {
        classe.students.push({ nom, prenom, free: true, id_user: null });
      });

      await classe.save();

      return res.status(201).json({ created: parsed.length });
    } catch (error) {
      if (handleYupError(error, res)) return;
      console.error("Erreur upload students:", error);
      return res.status(500).json({ message: "Erreur serveur." });
    }
  }
);

router.delete(
  "/admin/class/:classId/students/:studentId",
  requireAdmin,
  async (req, res) => {
    const { classId, studentId } = req.params || {};
    try {
      await adminStudentSchema.validate({ classId, studentId }, { abortEarly: false });

      if (!isAdminForClass(req, classId)) {
        return res.status(403).json({ message: "Classe non autorisée" });
      }

      const classObjectId = new mongoose.Types.ObjectId(classId);
      const studentObjectId = new mongoose.Types.ObjectId(studentId);

      const classe = await Classe.findById(classObjectId).select("students").lean();
      const students = Array.isArray(classe?.students) ? classe.students : [];
      const student =
        students.find((st) => String(st?._id) === String(studentObjectId)) || null;
      if (!student) {
        return res.status(404).json({ message: "Elève introuvable" });
      }

      const pull = await Classe.updateOne(
        { _id: classObjectId },
        { $pull: { students: { _id: studentObjectId } } }
      );
      const modified = pull?.modifiedCount ?? pull?.nModified ?? 0;
      if (!modified) {
        return res.status(400).json({ message: "Désinscription impossible" });
      }

      const userId = student?.id_user ? String(student.id_user) : null;
      const wasRegistered = student?.free === false && !!userId;

      if (wasRegistered && mongoose.Types.ObjectId.isValid(userId)) {
        const userObjectId = new mongoose.Types.ObjectId(userId);
        const pullCandidates = [classId];
        const lower = classId.toLowerCase();
        if (lower !== classId) pullCandidates.push(lower);
        pullCandidates.push(classObjectId);

        await Promise.all([
          Classe.collection.updateOne(
            { _id: classObjectId },
            { $pull: { exceptionvisible: userObjectId } }
          ),
          User.collection.updateOne(
            { _id: userObjectId },
            { $pull: { follow: { classe: classObjectId } } }
          ),
          User.collection.updateOne(
            { _id: userObjectId },
            { $pull: { follow: { $in: pullCandidates } } }
          ),
        ]).catch((err) => {
          console.error("Erreur suppression follow:", err);
        });
      }

      return res.status(200).json({ message: "Désinscription réalisée" });
    } catch (error) {
      if (handleYupError(error, res)) return;
      console.error("Erreur unsubscribe student:", error);
      return res.status(500).json({ message: "Erreur serveur." });
    }
  }
);
/* FIN admin manage class students */

module.exports = router;
