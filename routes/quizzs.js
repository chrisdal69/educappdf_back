const express = require("express");
const router = express.Router();
const path = require("path");
const archiver = require("archiver");
const mongoose = require("mongoose");
const yup = require("yup");
const { Storage } = require("@google-cloud/storage");
const { authenticate, requireAdmin, requireScopedAdmin } = require("../middlewares/auth");
const Quizz = require("../models/quizzs");
const Card = require("../models/cards");

const getCardRepertoire = async (cardId, expectedClassId) => {
  const trimmed = typeof cardId === "string" ? cardId.trim() : "";
  if (!trimmed || !mongoose.Types.ObjectId.isValid(trimmed)) return null;

  const classId =
    typeof expectedClassId === "string" ? expectedClassId.trim() : "";
  if (classId && !mongoose.Types.ObjectId.isValid(classId)) {
    return null;
  }

  const card = await Card.findById(trimmed).select("repertoire classe").lean();
  if (!card) {
    return null;
  }

  if (classId) {
    const cardClassId = card?.classe ? card.classe.toString() : "";
    if (!cardClassId || cardClassId !== classId) {
      return null;
    }
  }

  return typeof card?.repertoire === "string" ? card.repertoire.trim() : null;
};

const requireQuizzScopedAdmin = requireScopedAdmin((req) =>
  getCardRepertoire(req.params?.id, req.user?.classId)
);

const NODE_ENV = process.env.NODE_ENV;
let storage;
if (NODE_ENV === "production") {
  const serviceAccount = JSON.parse(process.env.GCP_KEY);
  storage = new Storage({
    projectId: serviceAccount.project_id,
    credentials: serviceAccount,
  });
} else {
  storage = new Storage({ keyFilename: "config/gcs-key.json" });
}
const bucketName = process.env.BUCKET_NAME || "mathsapp";
const bucket = storage.bucket(bucketName);
const allowedImageExtensions = new Set([".jpg", ".jpeg", ".png"]);

const quizzSaveSchema = yup.object().shape({
  cardId: yup.string().trim().required("cardId requis"),
  reponses: yup
    .array()
    .of(yup.number().integer().min(0))
    .min(1, "Aucune reponse fournie")
    .required("Reponses requises"),
});

const sanitizeStorageSegment = (value, label) => {
  if (!value || typeof value !== "string") {
    return null;
  }
  const cleaned = value.trim();
  if (!cleaned || cleaned.length > 60) {
    throw new Error(`${label} invalide.`);
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(cleaned)) {
    throw new Error(`${label} invalide.`);
  }
  return cleaned;
};

const normalizeTagNumber = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return Math.trunc(parsed);
};

const extractSingleFile = (files) => {
  if (!files || typeof files !== "object") {
    return null;
  }
  const candidates = ["file", "image", "bg", "upload"];
  for (const key of candidates) {
    if (files[key]) {
      return Array.isArray(files[key]) ? files[key][0] : files[key];
    }
  }
  const values = Object.values(files);
  if (!values.length) {
    return null;
  }
  const first = values[0];
  return Array.isArray(first) ? first[0] : first;
};

const uploadBufferToBucket = (fileRef, buffer, mimetype) =>
  new Promise((resolve, reject) => {
    const stream = fileRef.createWriteStream({
      metadata: { contentType: mimetype || "application/octet-stream" },
      resumable: false,
    });
    stream.on("error", (err) => reject(err));
    stream.on("finish", resolve);
    stream.end(buffer);
  });

let uniformBucketLevelAccessEnabled = null;

const isUniformBucketLevelAccessEnabled = async () => {
  if (uniformBucketLevelAccessEnabled !== null) {
    return uniformBucketLevelAccessEnabled;
  }
  try {
    const [metadata] = await bucket.getMetadata();
    uniformBucketLevelAccessEnabled = Boolean(
      metadata?.iamConfiguration?.uniformBucketLevelAccess?.enabled
    );
  } catch (err) {
    console.warn(
      "Impossible de lire la config du bucket; tentative ACL directe.",
      err
    );
    uniformBucketLevelAccessEnabled = false;
  }
  return uniformBucketLevelAccessEnabled;
};

const isUniformAccessError = (err) => {
  const message = typeof err?.message === "string" ? err.message : "";
  return err?.code === 400 && message.includes("uniform bucket-level access");
};

const makePublicIfAllowed = async (fileRef, label) => {
  const uniformEnabled = await isUniformBucketLevelAccessEnabled();
  if (uniformEnabled) {
    return false;
  }
  try {
    await fileRef.makePublic();
    return true;
  } catch (err) {
    if (isUniformAccessError(err)) {
      uniformBucketLevelAccessEnabled = true;
      return false;
    }
    console.warn(`Impossible de rendre ${label} public immediatement`, err);
    return false;
  }
};

const sanitizeQuizzArray = (value) => {
  if (!Array.isArray(value)) {
    return null;
  }
  return value.map((q, idx) => {
    const opts = Array.isArray(q?.options)
      ? q.options.map((o) =>
          typeof o === "string" ? o : o === null || o === undefined ? "" : `${o}`
        )
      : [];
    const normalizedCorrect =
      q && Object.prototype.hasOwnProperty.call(q, "correct")
        ? Number.isInteger(q.correct)
          ? q.correct
          : null
        : null;
    return {
      id: q?.id || `q${idx + 1}`,
      question: typeof q?.question === "string" ? q.question : "",
      image: typeof q?.image === "string" ? q.image : "",
      options: opts,
      correct: normalizedCorrect,
    };
  });
};

const sanitizeFileBaseName = (rawName, extension) => {
  const ext = typeof extension === "string" ? extension : path.extname(rawName || "").toLowerCase();
  const base = path
    .basename(rawName || "image", ext)
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60);
  return { base: base || "image", ext };
};

const isSafeFileName = (value) => {
  if (!value || typeof value !== "string") return false;
  if (value.length > 200) return false;
  if (value.includes("/") || value.includes("\\") || value.includes("..")) return false;
  return true;
};

const isAllowedImageName = (value) => {
  if (!isSafeFileName(value)) return false;
  const ext = path.extname(value).toLowerCase();
  return allowedImageExtensions.has(ext);
};

const buildExportZipName = (card, id) => {
  const parts = ["quizz"];
  const repertoire = (card?.repertoire ?? "").toString().trim();
  if (repertoire) parts.push(repertoire);
  const num =
    typeof card?.num !== "undefined" && card?.num !== null
      ? `${card.num}`.trim()
      : "";
  if (num) parts.push(`tag${num}`);
  if (parts.length === 1 && id) parts.push(`${id}`);
  const base = parts.join("_");
  const safe = base
    .replace(/[^a-zA-Z0-9_-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80);
  return `${safe || "quizz"}.zip`;
};

router.get("/historique", authenticate, async (req, res) => {
  try {
    const cardId = (req.query && req.query.cardId) || "";
    if (!cardId) {
      return res.status(400).json({ message: "cardId requis." });
    }

    const card = await Card.findById(cardId)
      .select("evalQuizz resultatQuizz")
      .lean();
    if (!card || card.evalQuizz !== "oui") {
      return res.status(404).json({ message: "Quizz non disponible." });
    }

    const existing = await Quizz.findOne({
      id_user: req.user.userId,
      id_card: cardId,
    }).lean();

    if (!existing) {
      return res.status(200).json({ alreadyDone: false });
    }

    const correctCount =
      Array.isArray(existing.reponses) && existing.reponses.length
        ? existing.reponses.reduce(
            (sum, val) => sum + (Number(val) === 1 ? 1 : 0),
            0
          )
        : 0;

    return res.status(200).json({
      alreadyDone: true,
      date: existing.date,
      correctCount: card.resultatQuizz ? correctCount : undefined,
      totalQuestions: card.resultatQuizz
        ? existing.reponses?.length || 0
        : undefined,
    });
  } catch (error) {
    console.error("GET /quizzs/historique :", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});






router.get("/:id/results", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const card = await Card.findById(id).select("quizz").lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const questionCount = Array.isArray(card.quizz) ? card.quizz.length : 0;
    const submissions = await Quizz.find({ id_card: id }).select("reponses").lean();

    const totalSubmissions = submissions.length;
    const correctCounts = Array.from({ length: questionCount }, () => 0);

    submissions.forEach((entry) => {
      const reps = Array.isArray(entry?.reponses) ? entry.reponses : [];
      for (let i = 0; i < questionCount; i += 1) {
        if (reps[i] === 1) {
          correctCounts[i] += 1;
        }
      }
    });

    return res.json({ totalSubmissions, correctCounts });
  } catch (error) {
    console.error("GET /quizzs/:id/results", error);
    return res
      .status(500)
      .json({ error: "Erreur lors du chargement des resultats." });
  }
});


router.get("/:id/results/export", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const card = await Card.findById(id).select("quizz titre num repertoire").lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const totalQuestions = Array.isArray(card.quizz) ? card.quizz.length : 0;
    const submissions = await Quizz.find({ id_card: id })
      .populate({ path: "id_user", select: "prenom nom" })
      .select("reponses id_user")
      .lean();

    const escapeCsv = (val) => {
      const str = `${val ?? ""}`;
      const escaped = str.replace(/"/g, '""');
      return /[";\\,\\n]/.test(escaped) ? `"${escaped}"` : escaped;
    };

    const rows = submissions.map((entry) => {
      const user = entry?.id_user || {};
      const prenom = user.prenom || "";
      const nom = user.nom || "";
      const score = Array.isArray(entry?.reponses)
        ? entry.reponses.reduce((sum, val) => sum + (Number(val) === 1 ? 1 : 0), 0)
        : 0;
      const total = totalQuestions || (Array.isArray(entry?.reponses) ? entry.reponses.length : 0);
      return { prenom, nom, score, total };
    });

    const header = ["quizz", "num", "repertoire"].join(";");
    const metaLine = [
      escapeCsv(card.titre || `quizz_${id}`),
      escapeCsv(card.num ?? ""),
      escapeCsv(card.repertoire ?? ""),
    ].join(";");
    const bodyHeader = ["prenom", "nom", "bonnes_reponses", "nombre_questions"].join(";");
    const body = rows
      .map((r) => [escapeCsv(r.prenom), escapeCsv(r.nom), escapeCsv(r.score), escapeCsv(r.total || totalQuestions)].join(";"))
      .join("\n");
    const csv = [header, metaLine, bodyHeader, body].filter(Boolean).join("\n");

    const safeTitle = [
      "quizz",
      (card.num ?? "").toString().trim() || `${id}`,
      (card.repertoire ?? "").toString().trim(),
    ]
      .filter(Boolean)
      .join("_")
      .replace(/[^a-zA-Z0-9_-]+/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 80);

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.csv"`);
    return res.status(200).send(csv);
  } catch (error) {
    console.error("GET /quizzs/:id/results/export", error);
    return res.status(500).json({ error: "Erreur lors de l'export des resultats." });
  }
});

router.get("/:id/export/zip", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const card = await Card.findById(id).select("quizz num repertoire").lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const normalizedQuizz = sanitizeQuizzArray(card.quizz || []) || [];
    const reindexedQuizz = normalizedQuizz.map((q, idx) => ({
      ...q,
      id: `q${idx + 1}`,
    }));

    const fileName = buildExportZipName(card, id);
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Cache-Control", "no-store");

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("warning", (err) => {
      console.warn("Archive warning", err);
    });
    archive.on("error", (err) => {
      console.error("Erreur export zip quizz", err);
      if (!res.headersSent) {
        return res.status(500).json({ error: "Erreur lors de l'export." });
      }
      res.end();
    });

    archive.pipe(res);
    archive.append(JSON.stringify(reindexedQuizz, null, 2), {
      name: "quizz.json",
    });

    let sanitizedRepertoire = null;
    try {
      sanitizedRepertoire = sanitizeStorageSegment(
        card.repertoire,
        "Repertoire"
      );
    } catch (error) {
      sanitizedRepertoire = null;
    }
    const tagNumber = normalizeTagNumber(card.num);

    if (sanitizedRepertoire && tagNumber !== null) {
      const imageNames = new Set();
      reindexedQuizz.forEach((q) => {
        if (q?.image && isAllowedImageName(q.image)) {
          imageNames.add(q.image);
        }
      });

      for (const imageName of imageNames) {
        const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesQuizz/${imageName}`;
        const fileRef = bucket.file(objectPath);
        try {
          const [exists] = await fileRef.exists();
          if (!exists) continue;
          const stream = fileRef.createReadStream();
          stream.on("error", (err) => {
            console.warn("Erreur lecture image export quizz", err);
          });
          archive.append(stream, { name: `images/${imageName}` });
        } catch (error) {
          console.warn("Image ignorée lors de l'export", error);
        }
      }
    }

    await archive.finalize();
    return null;
  } catch (error) {
    console.error("GET /quizzs/:id/export/zip", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Erreur lors de l'export." });
    }
    res.end();
  }
});

router.post("/", authenticate, async (req, res) => {
  try {
    const { cardId, reponses } = await quizzSaveSchema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    const existing = await Quizz.findOne({
      id_user: req.user.userId,
      id_card: cardId,
    });

    const card = await Card.findById(cardId)
      .select("evalQuizz quizz resultatQuizz")
      .lean();
    if (!card) {
      return res.status(404).json({ message: "Carte inconnue." });
    }
    if (card.evalQuizz === "attente") {
      return res.status(403).json({ message: "Quizz non accessible." });
    }
    if (card.evalQuizz !== "oui") {
      return res
        .status(403)
        .json({ message: "Ce quizz n'est pas reserve aux comptes." });
    }

    const questions = Array.isArray(card.quizz) ? card.quizz : [];
    if (questions.length !== reponses.length) {
      return res
        .status(400)
        .json({ message: "Nombre de reponses incoherent avec le quizz." });
    }

    const scoredReponses = questions.map((q, idx) => {
      const userChoice = reponses[idx];
      const correctIndex =
        q && Object.prototype.hasOwnProperty.call(q, "correct")
          ? q.correct
          : null;
      if (typeof userChoice !== "number" || !Number.isInteger(correctIndex)) {
        return 0;
      }
      return userChoice === correctIndex ? 1 : 0;
    });

    if (existing) {
      if (card.resultatQuizz) {
        const correctCount =
          Array.isArray(existing.reponses) && existing.reponses.length
            ? existing.reponses.reduce((sum, val) => sum + (Number(val) === 1 ? 1 : 0), 0)
            : 0;
        return res.status(200).json({
          alreadyDone: true,
          date: existing.date,
          correctCount,
          totalQuestions: existing.reponses?.length || questions.length,
          message: "Ce quizz a deja ete enregistre pour cet utilisateur.",
        });
      }

      return res.status(200).json({
        alreadyDone: true,
        date: existing.date,
        message: "Ce quizz a deja ete enregistre pour cet utilisateur.",
      });
    }

    const doc = new Quizz({
      id_user: req.user.userId,
      id_card: cardId,
      reponses: scoredReponses,
    });
    const saved = await doc.save();

    if (card.resultatQuizz) {
      const correctCount = scoredReponses.reduce(
        (sum, val) => sum + (Number(val) === 1 ? 1 : 0),
        0
      );

      return res.status(201).json({
        message: "Reponses enregistrees.",
        quizz: saved,
        date: saved.date,
        correctCount,
        totalQuestions: scoredReponses.length,
      });
    }

    return res.status(201).json({
      message: "Reponses enregistrees.",
      quizz: saved,
      date: saved.date,
    });
  } catch (error) {
    if (error.name === "ValidationError") {
      if (Array.isArray(error.inner) && error.inner.length) {
        const errors = error.inner.map((err) => ({
          field: err.path,
          message: err.message,
        }));
        return res.status(400).json({ errors });
      }
      return res.status(400).json({ message: error.message });
    }
    console.error("Erreur route /quizzs :", error);
    return res.status(500).json({ message: "Erreur serveur." });
  }
});

router.patch("/:id", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const normalizedQuizz = sanitizeQuizzArray((req.body || {}).quizz);
    if (!normalizedQuizz) {
      return res.status(400).json({ error: "Le quizz doit etre un tableau." });
    }
    const reindexedQuizz = normalizedQuizz.map((q, idx) => ({
      ...q,
      id: `q${idx + 1}`,
    }));

    // Nettoyage des images orphelines (questions supprimées)
    const existingQuizz = sanitizeQuizzArray(card.quizz || []) || [];
    const existingImages = new Set(
      existingQuizz.map((q) => (q && typeof q.image === "string" ? q.image : "")).filter(Boolean)
    );
    const nextImages = new Set(
      reindexedQuizz.map((q) => (q && typeof q.image === "string" ? q.image : "")).filter(Boolean)
    );

    const imagesToDelete = [...existingImages].filter((img) => img && !nextImages.has(img) && isSafeFileName(img));

    if (imagesToDelete.length) {
      try {
        const sanitizedRepertoire = sanitizeStorageSegment(card.repertoire, "Repertoire");
        const tagNumber = normalizeTagNumber(card.num);
        if (sanitizedRepertoire && tagNumber !== null) {
          await Promise.all(
            imagesToDelete.map((img) =>
              bucket
                .file(`${sanitizedRepertoire}/tag${tagNumber}/imagesQuizz/${img}`)
                .delete({ ignoreNotFound: true })
                .catch((err) => console.warn("Suppression image quizz orpheline échouée", err))
            )
          );
        }
      } catch (cleanupErr) {
        console.warn("Nettoyage images orphelines quizz échoué", cleanupErr);
      }
    }

    const update = { quizz: reindexedQuizz };
    const rawEval = (req.body && req.body.evalQuizz) || null;
    if (rawEval !== null) {
      const val = typeof rawEval === "string" ? rawEval.trim() : "";
      if (!["oui", "non", "attente"].includes(val)) {
        return res.status(400).json({ error: "Valeur evalQuizz invalide." });
      }
      update.evalQuizz = val;
    }
    if (Object.prototype.hasOwnProperty.call(req.body || {}, "resultatQuizz")) {
      update.resultatQuizz = !!req.body.resultatQuizz;
    }

    const updatedCard = await Card.findByIdAndUpdate(id, update, { new: true }).lean();
    return res.json({ result: updatedCard });
  } catch (error) {
    console.error("PATCH /quizzs/:id", error);
    return res.status(500).json({ error: "Erreur lors de la mise a jour." });
  }
});

router.post("/:id/image", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const questionId = (req.body && req.body.questionId) || "";
    if (!questionId) {
      return res.status(400).json({ error: "questionId requis." });
    }

    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "Aucun fichier fourni." });
    }

    const file = extractSingleFile(req.files);
    if (!file || !file.data) {
      return res.status(400).json({ error: "Fichier invalide." });
    }
    const extension = path.extname(file.name || "").toLowerCase();
    if (!allowedImageExtensions.has(extension)) {
      return res.status(400).json({ error: "Extension d'image non autorisee." });
    }

    const targetRepertoire =
      (req.body && req.body.repertoire) || card.repertoire;
    let sanitizedRepertoire;
    try {
      sanitizedRepertoire = sanitizeStorageSegment(
        targetRepertoire,
        "Repertoire"
      );
    } catch (validationError) {
      return res.status(400).json({ error: validationError.message });
    }
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Repertoire manquant." });
    }

    const tagNumber = normalizeTagNumber(
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num
    );
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }

    const { base, ext } = sanitizeFileBaseName(file.name, extension);
    const uniqueName = `${base}_${Date.now()}${ext}`;
    const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesQuizz/${uniqueName}`;
    const fileRef = bucket.file(objectPath);

    const normalizedQuizz = sanitizeQuizzArray(card.quizz || []);
    const targetQuestion =
      normalizedQuizz?.find((q) => q && q.id === questionId) || null;
    if (!targetQuestion) {
      return res.status(404).json({ error: "Question introuvable." });
    }

    if (targetQuestion.image) {
      const safeName = targetQuestion.image;
      if (isSafeFileName(safeName)) {
        const previousFile = bucket.file(
          `${sanitizedRepertoire}/tag${tagNumber}/imagesQuizz/${safeName}`
        );
        previousFile
          .delete({ ignoreNotFound: true })
          .catch((err) =>
            console.warn("Suppression ancienne image quizz echouee", err)
          );
      }
    }

    await uploadBufferToBucket(fileRef, file.data, file.mimetype);
    await makePublicIfAllowed(fileRef, "l'image");

    const nextQuizz = normalizedQuizz.map((q, idx) => ({
      ...q,
      id: `q${idx + 1}`,
      image: q.id === questionId ? uniqueName : q.image || "",
    }));

    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { quizz: nextQuizz },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apres upload." });
    }

    return res.json({
      result: updatedCard,
      fileName: uniqueName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (error) {
    console.error("POST /quizzs/:id/image", error);
    return res.status(500).json({ error: "Erreur lors de l'upload de l'image." });
  }
});

router.delete("/:id/image", requireQuizzScopedAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const questionId = (req.body && req.body.questionId) || "";
    const image = (req.body && req.body.image) || "";
    if (!questionId || !image) {
      return res.status(400).json({ error: "questionId et image requis." });
    }
    if (!isSafeFileName(image)) {
      return res.status(400).json({ error: "Nom de fichier invalide." });
    }

    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const targetRepertoire =
      (req.body && req.body.repertoire) || card.repertoire;
    let sanitizedRepertoire;
    try {
      sanitizedRepertoire = sanitizeStorageSegment(
        targetRepertoire,
        "Repertoire"
      );
    } catch (validationError) {
      return res.status(400).json({ error: validationError.message });
    }
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Repertoire manquant." });
    }
    const tagNumber = normalizeTagNumber(
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num
    );
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }

    const normalizedQuizz = sanitizeQuizzArray(card.quizz || []);
    const exists = normalizedQuizz.some(
      (q) => q && q.id === questionId && q.image === image
    );
    if (!exists) {
      return res.status(404).json({ error: "Image non trouvee dans le quizz." });
    }

    const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesQuizz/${image}`;
    try {
      await bucket.file(objectPath).delete({ ignoreNotFound: true });
    } catch (err) {
      console.warn("Suppression image quizz echouee", err);
    }

    const nextQuizz = normalizedQuizz.map((q, idx) => ({
      ...q,
      id: `q${idx + 1}`,
      image: q.id === questionId ? "" : q.image,
    }));
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { quizz: nextQuizz },
      { new: true }
    ).lean();
    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apres suppression." });
    }

    return res.json({ result: updatedCard });
  } catch (error) {
    console.error("DELETE /quizzs/:id/image", error);
    return res
      .status(500)
      .json({ error: "Erreur lors de la suppression de l'image." });
  }
});

module.exports = router;
