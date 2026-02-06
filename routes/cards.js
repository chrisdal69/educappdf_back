var express = require("express");
var router = express.Router();
const path = require("path");
const archiver = require("archiver");
const sharp = require("sharp");
const mongoose = require("mongoose");
const { Storage } = require("@google-cloud/storage");
const {
  authenticate,
  authorize,
  verifyToken,
  requireAdmin,
} = require("../middlewares/auth");
const Card = require("../models/cards");
const Cloud = require("../models/cloud");
const Quizz = require("../models/quizzs");
const User = require("../models/users");

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
const allowedBgExtensions = new Set([
  ".jpg",
  ".jpeg",
  ".png",
  ".webp",
  ".gif",
  ".bmp",
]);
const allowedFileExtensions = new Set([
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".csv",
  ".txt",
  ".md",
  ".py",
  ".zip",
  ".rar",
  ".7z",
  ".ppt",
  ".pptx",
  ".jpg",
  ".jpeg",
  ".png",
  ".gif",
  ".svg",
  ".webp",
  ".mp4",
  ".fls",
  ".ggb"
]);
const allowedFlashImageExtensions = new Set([".jpg", ".jpeg", ".png"]);
const MAX_FLASH_IMAGE_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const toBlurFileName = (filename) => {
  if (!filename || typeof filename !== "string") {
    return null;
  }
  const lastDot = filename.lastIndexOf(".");
  if (lastDot === -1) {
    return `${filename}Blur`;
  }
  return `${filename.slice(0, lastDot)}Blur${filename.slice(lastDot)}`;
};

router.get("/", async (req, res) => {
  try {
    const result = await Card.find({ visible: true })
      .sort({ order: -1 })
      .lean()
      .exec();

    if (!result.length) {
      return res.status(404).json({ error: "Aucune carte trouvée." });
    }

    const sanitized = result.map((card) => {
      const filteredFiles = Array.isArray(card.fichiers)
        ? card.fichiers.filter((f) => f && f.visible === true)
        : card.fichiers;

      if (!Array.isArray(card.quizz)) {
        return { ...card, fichiers: filteredFiles };
      }

      return {
        ...card,
        fichiers: filteredFiles,
        quizz: card.quizz.map((q) => {
          const base = {
            id: q.id,
            question: q.question,
            image: q.image,
            options: Array.isArray(q.options) ? q.options : [],
          };
          if (card.evalQuizz === "non") {
            return { ...base, correct: q.correct };
          }
          return base;
        }),
      };
    });

    res.json({ result: sanitized });
  } catch (err) {
    console.error("GET /cards", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

router.get("/admin", requireAdmin, async (req, res) => {
  try {
    const result = await Card.find().sort({ order: -1 }).lean().exec();

    if (!result.length) {
      return res.status(404).json({ error: "Aucune carte trouvée." });
    }

    res.json({ result });
  } catch (err) {
    console.error("GET /cards/admin", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

router.post("/admin", requireAdmin, async (req, res) => {
  const repertoire = (req.body?.repertoire || "").trim();

  if (!repertoire) {
    return res.status(400).json({ error: "Repertoire manquant." });
  }

  try {
    const computeNextValues = async () => {
      const [agg] = await Card.aggregate([
        { $match: { repertoire } },
        {
          $group: {
            _id: null,
            maxNum: { $max: "$num" },
            maxOrder: { $max: "$order" },
          },
        },
      ]);

      const nextNum = Number.isFinite(agg?.maxNum)
        ? Math.trunc(agg.maxNum) + 1
        : 1;
      const nextOrder = Number.isFinite(agg?.maxOrder)
        ? Math.trunc(agg.maxOrder) + 1
        : 1;
      return { nextNum, nextOrder };
    };

    let values = await computeNextValues();
    let created = null;

    for (let attempt = 0; attempt < 2 && !created; attempt += 1) {
      const payload = {
        num: values.nextNum,
        repertoire,
        cloud: false,
        bg: "",
        titre: "",
        content: [
          {
            type: "paragraph",
            children: [{ text: "" }],
          },
        ],
        contentVersion: 1,
        fichiers: [],
        quizz: [],
        flash:[],
        video: [],
        evalQuizz: "non",
        resultatQuizz: false,
        visible: false,
        order: values.nextOrder,
      };

      try {
        created = await Card.create(payload);
      } catch (error) {
        const isDupKey = error?.code === 11000;
        if (isDupKey && attempt === 0) {
          values = await computeNextValues();
          continue;
        }
        if (isDupKey) {
          return res
            .status(409)
            .json({ error: "Une carte avec ce num ou cet ordre existe deja." });
        }
        throw error;
      }
    }

    const result = created?.toObject ? created.toObject() : created;

    res.status(201).json({ result });
  } catch (err) {
    console.error("POST /cards/admin", err);
    res.status(500).json({ error: "Erreur lors de la creation de la carte." });
  }
});

router.get("/cloud", authenticate, async (req, res) => {
  const trimmedCard =
    typeof req.query.id_card === "string" ? req.query.id_card.trim() : "";
  const userId = req.user?.userId;

  if (!trimmedCard) {
    return res.status(400).json({ error: "Id de carte manquant." });
  }
  if (!mongoose.Types.ObjectId.isValid(trimmedCard)) {
    return res.status(400).json({ error: "Id de carte invalide." });
  }
  if (!userId) {
    return res.status(401).json({ error: "Utilisateur non authentifie." });
  }

  try {
    const result = await Cloud.find({
      id_card: trimmedCard,
      id_user: userId,
    })
      .sort({ date: -1 })
      .lean();

    return res.json({ result });
  } catch (err) {
    console.error("GET /cards/cloud", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la recuperation des messages cloud." });
  }
});

router.delete("/cloud/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const userId = req.user?.userId;

  if (!id) {
    return res.status(400).json({ error: "Id de message manquant." });
  }
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Id de message invalide." });
  }
  if (!userId) {
    return res.status(401).json({ error: "Utilisateur non authentifie." });
  }

  try {
    const deleted = await Cloud.findOneAndDelete({
      _id: id,
      id_user: userId,
    }).lean();

    if (!deleted) {
      return res.status(404).json({ error: "Message introuvable." });
    }

    return res.json({ result: { id: deleted._id } });
  } catch (err) {
    console.error("DELETE /cards/cloud/:id", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la suppression du message cloud." });
  }
});

router.post("/cloud", requireAdmin, async (req, res) => {
  const { id_card, nom, prenom, message, filename } = req.body || {};
  const trimmedCard = typeof id_card === "string" ? id_card.trim() : "";
  const trimmedNom = typeof nom === "string" ? nom.trim().toUpperCase() : "";
  const trimmedPrenom =
    typeof prenom === "string" ? prenom.trim().toLowerCase() : "";
  const trimmedMessage = typeof message === "string" ? message.trim() : "";
  const trimmedFilename =
    typeof filename === "string" ? filename.trim() : "";

  if (!trimmedCard) {
    return res.status(400).json({ error: "Id de carte manquant." });
  }
  if (!mongoose.Types.ObjectId.isValid(trimmedCard)) {
    return res.status(400).json({ error: "Id de carte invalide." });
  }
  if (!trimmedNom || !trimmedPrenom) {
    return res.status(400).json({ error: "Nom ou prenom manquant." });
  }
  if (!trimmedMessage) {
    return res.status(400).json({ error: "Message manquant." });
  }
  if (!trimmedFilename) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }

  try {
    const user = await User.findOne({
      nom: trimmedNom,
      prenom: trimmedPrenom,
    }).lean();
    if (!user) {
      console.log(trimmedNom , trimmedPrenom )
      return res.status(404).json({ error: "Utilisateur introuvable." });
    }

    const card = await Card.findById(trimmedCard).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const created = await Cloud.create({
      id_user: user._id,
      id_card: card._id,
      filename: trimmedFilename,
      message: trimmedMessage,
    });

    return res.status(201).json({ result: created });
  } catch (err) {
    console.error("POST /cards/cloud", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la creation du message cloud." });
  }
});

router.patch("/:id/title", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { titre } = req.body || {};

  if (!titre || !titre.trim()) {
    return res.status(400).json({ error: "Le titre est obligatoire." });
  }

  try {
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { titre: titre.trim() },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/title", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

router.patch("/:id/visible", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawValue = (req.body || {}).visible;
  let normalizedVisible = null;

  if (typeof rawValue === "boolean") {
    normalizedVisible = rawValue;
  } else if (typeof rawValue === "string") {
    if (rawValue.toLowerCase() === "true") {
      normalizedVisible = true;
    } else if (rawValue.toLowerCase() === "false") {
      normalizedVisible = false;
    }
  }

  if (normalizedVisible === null) {
    return res.status(400).json({ error: "Valeur de visibilitǸ invalide." });
  }

  try {
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { visible: normalizedVisible },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/visible", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

router.patch("/:id/cloud", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawValue = (req.body || {}).cloud;
  let normalizedCloud = null;

  if (typeof rawValue === "boolean") {
    normalizedCloud = rawValue;
  } else if (typeof rawValue === "string") {
    if (rawValue.toLowerCase() === "true") {
      normalizedCloud = true;
    } else if (rawValue.toLowerCase() === "false") {
      normalizedCloud = false;
    }
  }

  if (normalizedCloud === null) {
    return res.status(400).json({ error: "Valeur cloud invalide." });
  }

  try {
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { cloud: normalizedCloud },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/cloud", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

router.delete("/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const sanitizedRepertoire = sanitizeStorageSegment(card.repertoire, "Repertoire");
    const tagNumber = normalizeTagNumber(card.num);

    await Promise.all([
      Card.deleteOne({ _id: card._id }),
      Quizz.deleteMany({ id_card: card._id }),
      Cloud.deleteMany({ id_card: card._id }),
      (async () => {
        if (sanitizedRepertoire && tagNumber !== null) {
          const tagSuffix = `tag${Math.trunc(tagNumber)}`;
          const prefix = `${sanitizedRepertoire}/${tagSuffix}/`;
          const cloudPrefix = `cloud/${sanitizedRepertoire}${tagSuffix}/`;
          try {
            await bucket.deleteFiles({ prefix });
          } catch (err) {
            console.warn("Suppression des fichiers du bucket échouée", err);
          }
          try {
            await bucket.deleteFiles({ prefix: cloudPrefix });
          } catch (err) {
            console.warn("Suppression des fichiers cloud du bucket echouee", err);
          }
        }
      })(),
    ]);

    return res.json({
      result: {
        id: card._id,
        num: card.num,
        repertoire: card.repertoire,
      },
    });
  } catch (err) {
    console.error("DELETE /cards/:id", err);
    res.status(500).json({ error: "Erreur lors de la suppression de la carte." });
  }
});

router.patch("/:id/move", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const direction = (req.body?.direction || "").toLowerCase();

  if (direction !== "up" && direction !== "down") {
    return res.status(400).json({ error: "Direction invalide (attendue: up ou down)." });
  }

  try {
    const current = await Card.findById(id).lean();
    if (!current) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const filter = { repertoire: current.repertoire };
    const sorted = await Card.find(filter).sort({ order: -1, num: -1 }).lean();

    const index = sorted.findIndex((c) => String(c._id) === String(id));
    if (index === -1) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const neighborIndex = direction === "up" ? index - 1 : index + 1;
    if (neighborIndex < 0 || neighborIndex >= sorted.length) {
      return res
        .status(400)
        .json({ error: direction === "up" ? "Carte déjà en tête." : "Carte déjà en queue." });
    }

    const neighbor = sorted[neighborIndex];
    const currentOrder = Number.isFinite(current.order) ? current.order : 0;
    const neighborOrder = Number.isFinite(neighbor.order) ? neighbor.order : 0;

    await Promise.all([
      Card.updateOne({ _id: current._id }, { $set: { order: neighborOrder } }),
      Card.updateOne({ _id: neighbor._id }, { $set: { order: currentOrder } }),
    ]);

    const updatedList = await Card.find(filter).sort({ order: -1, num: -1 }).lean();
    return res.json({ result: updatedList });
  } catch (err) {
    console.error("PATCH /cards/:id/move", err);
    res.status(500).json({ error: "Erreur lors du déplacement de la carte." });
  }
});

router.patch("/:id/content", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawContent = (req.body || {}).content;
  const rawVersion = (req.body || {}).contentVersion;

  if (!Array.isArray(rawContent)) {
    return res.status(400).json({
      error: "Le champ content doit etre un tableau Slate.",
    });
  }

  const normalizedVersion =
    Number.isInteger(rawVersion) && rawVersion > 0 ? rawVersion : 1;

  try {
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { content: rawContent, contentVersion: normalizedVersion },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/content", err);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

const patchStringField = async (req, res, fieldName, label = fieldName) => {
  const { id } = req.params;
  const rawValue = (req.body || {})[fieldName];
  const trimmed = typeof rawValue === "string" ? rawValue.trim() : "";

  if (!trimmed) {
    return res
      .status(400)
      .json({ error: `Le champ ${label} est obligatoire.` });
  }

  try {
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { [fieldName]: trimmed },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error(`PATCH /cards/:id/${fieldName}`, err);
    res.status(500).json({ error: "Erreur serveur." });
  }
};

router.patch("/:id/bg", requireAdmin, async (req, res) => {
  await patchStringField(req, res, "bg", "bg");
});

const sanitizeStorageSegment = (value, label) => {
  if (!value || typeof value !== "string") {
    return null;
  }
  const cleaned = value.trim();
  if (!cleaned) {
    return null;
  }
  if (cleaned.length > 60) {
    throw new Error(`${label} trop long.`);
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
  return parsed;
};

const sanitizeFileBaseName = (rawName, extension) => {
  const ext =
    typeof extension === "string"
      ? extension
      : path.extname(rawName || "").toLowerCase();
  const base = path
    .basename(rawName || "fichier", ext)
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60);
  return { ext, base: base || "fichier" };
};

const resolveArrayInsertIndex = (list, position) => {
  const length = Array.isArray(list) ? list.length : 0;
  if (position === "start") return 0;
  if (
    position === "end" ||
    typeof position === "undefined" ||
    position === null
  ) {
    return length;
  }
  const numeric = Number(position);
  if (!Number.isNaN(numeric)) {
    return Math.max(0, Math.min(length, numeric + 1));
  }
  return length;
};

const sanitizeVideoArray = (list) =>
  Array.isArray(list)
    ? list.map((v) => ({
        txt: typeof v?.txt === "string" ? v.txt.trim() : "",
        href: typeof v?.href === "string" ? v.href.trim() : "",
      }))
    : [];

const sanitizeFlashArray = (list) => {
  if (!Array.isArray(list)) return [];
  const reservedIds = new Set();
  list.forEach((item) => {
    const trimmedId = typeof item?.id === "string" ? item.id.trim() : "";
    if (trimmedId) {
      reservedIds.add(trimmedId);
    }
  });
  const usedIds = new Set();
  let counter = 1;
  const nextId = () => {
    let candidate = `f${counter}`;
    while (reservedIds.has(candidate) || usedIds.has(candidate)) {
      counter += 1;
      candidate = `f${counter}`;
    }
    usedIds.add(candidate);
    reservedIds.add(candidate);
    counter += 1;
    return candidate;
  };

  return list.map((item) => {
    const trimmedId = typeof item?.id === "string" ? item.id.trim() : "";
    let id = trimmedId;
    if (!id || usedIds.has(id)) {
      id = nextId();
    } else {
      usedIds.add(id);
    }
    return {
      id,
      question: typeof item?.question === "string" ? item.question.trim() : "",
      imquestion:
        typeof item?.imquestion === "string" ? item.imquestion.trim() : "",
      reponse: typeof item?.reponse === "string" ? item.reponse.trim() : "",
      imreponse:
        typeof item?.imreponse === "string" ? item.imreponse.trim() : "",
    };
  });
};

const isSafeFileName = (value) => {
  if (!value || typeof value !== "string") return false;
  if (value.length > 200) return false;
  if (value.includes("/") || value.includes("\\") || value.includes(".."))
    return false;
  return true;
};

const isAllowedFlashImageName = (value) => {
  if (!isSafeFileName(value)) return false;
  const ext = path.extname(value).toLowerCase();
  return allowedFlashImageExtensions.has(ext);
};

const buildFlashExportZipName = (card, id) => {
  const parts = ["flash"];
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
  return `${safe || "flash"}.zip`;
};

const extractSingleFile = (files) => {
  if (!files || typeof files !== "object") {
    return null;
  }
  const candidates = ["file", "bg", "background", "image"];
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

const buildBlurBuffer = async (buffer, format) => {
  try {
    let instance = sharp(buffer)
      .resize({ width: 32, height: 32, fit: "inside" })
      .blur(8);
    if (format === ".jpg") {
      instance = instance.jpeg({ quality: 60 });
    } else if (format === ".jpeg") {
      instance = instance.jpeg({ quality: 60 });
    } else if (format === ".png") {
      instance = instance.png({ quality: 60 });
    } else if (format === ".webp") {
      instance = instance.webp({ quality: 50 });
    }
    return await instance.toBuffer();
  } catch (err) {
    console.warn("Impossible de générer l'aperçu flouté :", err);
    return null;
  }
};

router.get("/:id/flash/export/zip", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const card = await Card.findById(id)
      .select("flash num repertoire")
      .lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const normalizedFlash = sanitizeFlashArray(card.flash || []);
    const reindexedFlash = normalizedFlash.map((item, idx) => ({
      ...item,
      id: `f${idx + 1}`,
    }));

    const fileName = buildFlashExportZipName(card, id);
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Cache-Control", "no-store");

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("warning", (err) => {
      console.warn("Archive warning", err);
    });
    archive.on("error", (err) => {
      console.error("Erreur export zip flash", err);
      if (!res.headersSent) {
        return res.status(500).json({ error: "Erreur lors de l'export." });
      }
      res.end();
    });

    archive.pipe(res);
    archive.append(JSON.stringify(reindexedFlash, null, 2), {
      name: "flash.json",
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
      reindexedFlash.forEach((item) => {
        if (item?.imquestion && isAllowedFlashImageName(item.imquestion)) {
          imageNames.add(item.imquestion);
        }
        if (item?.imreponse && isAllowedFlashImageName(item.imreponse)) {
          imageNames.add(item.imreponse);
        }
      });

      for (const imageName of imageNames) {
        const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesFlash/${imageName}`;
        const fileRef = bucket.file(objectPath);
        try {
          const [exists] = await fileRef.exists();
          if (!exists) continue;
          const stream = fileRef.createReadStream();
          stream.on("error", (err) => {
            console.warn("Erreur lecture image export flash", err);
          });
          archive.append(stream, { name: `images/${imageName}` });
        } catch (error) {
          console.warn("Image ignoree lors de l'export", error);
        }
      }
    }

    await archive.finalize();
    return null;
  } catch (error) {
    console.error("GET /cards/:id/flash/export/zip", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Erreur lors de l'export." });
    }
    res.end();
  }
});

router.patch("/:id/flash", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawFlash = (req.body || {}).flash;

  if (!Array.isArray(rawFlash)) {
    return res.status(400).json({ error: "Le flash doit etre un tableau." });
  }

  try {
    const sanitized = sanitizeFlashArray(rawFlash);
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { flash: sanitized },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    return res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/flash", err);
    return res.status(500).json({ error: "Erreur lors de la mise a jour du flash." });
  }
});

router.post("/:id/flash", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const position = req.body?.position;

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const currentList = sanitizeFlashArray(card.flash);
    const insertIndex = resolveArrayInsertIndex(currentList, position);
    const normalizedIndex = Math.max(
      0,
      Math.min(currentList.length, insertIndex)
    );
    const next = [...currentList];
    next.splice(normalizedIndex, 0, {
      id: "",
      question: "",
      imquestion: "",
      reponse: "",
      imreponse: "",
    });

    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { flash: sanitizeFlashArray(next) },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apres ajout." });
    }

    return res.json({ result: updatedCard });
  } catch (err) {
    console.error("POST /cards/:id/flash", err);
    return res.status(500).json({ error: "Erreur lors de l'ajout du flash." });
  }
});

router.delete("/:id/flash", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawIndex = req.body?.index;
  const flashId = typeof req.body?.flashId === "string" ? req.body.flashId.trim() : "";
  const index = Number.isInteger(rawIndex) ? rawIndex : Number(rawIndex);

  if (!flashId && (!Number.isInteger(index) || index < 0)) {
    return res.status(400).json({ error: "Indice ou flashId manquant." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const currentList = sanitizeFlashArray(card.flash);
    let targetIndex = -1;
    if (Number.isInteger(index) && index >= 0 && index < currentList.length) {
      targetIndex = index;
    } else if (flashId) {
      targetIndex = currentList.findIndex((item) => item.id === flashId);
    }

    if (targetIndex === -1) {
      return res.status(404).json({ error: "Flash card introuvable." });
    }

    const targetFlash = currentList[targetIndex] || {};
    const imagesToDelete = [
      targetFlash.imquestion,
      targetFlash.imreponse,
    ].filter((value) => typeof value === "string" && value.trim());
    const next = currentList.filter((_, idx) => idx !== targetIndex);
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { flash: sanitizeFlashArray(next) },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apres suppression." });
    }

    if (imagesToDelete.length) {
      let sanitizedRepertoire = null;
      try {
        sanitizedRepertoire = sanitizeStorageSegment(
          card.repertoire,
          "Repertoire"
        );
      } catch (validationError) {
        console.warn(
          "Repertoire invalide, tentative suppression avec valeur brute.",
          validationError
        );
        sanitizedRepertoire = null;
      }

      const tagNumber = normalizeTagNumber(card.num);
      const fallbackRepertoire =
        typeof card.repertoire === "string" ? card.repertoire.trim() : "";
      const repertoireSegment = sanitizedRepertoire || fallbackRepertoire;
      if (repertoireSegment && tagNumber !== null) {
        const normalizedTagNumber = Math.trunc(tagNumber);
        const deletions = imagesToDelete
          .filter((name) => isSafeFileName(name))
          .map((name) =>
            bucket
              .file(
                `${repertoireSegment}/tag${normalizedTagNumber}/imagesFlash/${name}`
              )
              .delete({ ignoreNotFound: true })
          );
        const results = await Promise.allSettled(deletions);
        results.forEach((result) => {
          if (result.status === "rejected") {
            console.warn("Suppression image flash echouee", result.reason);
          }
        });
      }
    }

    return res.json({ result: updatedCard });
  } catch (err) {
    console.error("DELETE /cards/:id/flash", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la suppression du flash." });
  }
});

router.post("/:id/flash/image", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const flashId = typeof req.body?.flashId === "string" ? req.body.flashId.trim() : "";
  const fieldRaw = typeof req.body?.field === "string" ? req.body.field.trim() : "";
  const field =
    fieldRaw === "imquestion" || fieldRaw === "imreponse" ? fieldRaw : null;

  if (!flashId || !field) {
    return res.status(400).json({ error: "flashId et field requis." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "Aucun fichier fourni." });
    }

    const file = extractSingleFile(req.files);
    if (!file || !file.data) {
      return res.status(400).json({ error: "Fichier d'upload invalide." });
    }

    const extension = path.extname(file.name || "").toLowerCase();
    if (!allowedFlashImageExtensions.has(extension)) {
      return res
        .status(400)
        .json({ error: "Extension d'image non autorisee." });
    }

    if (file.size && file.size > MAX_FLASH_IMAGE_BYTES) {
      return res
        .status(400)
        .json({ error: "Fichier trop volumineux (4 Mo max)." });
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
    const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesFlash/${uniqueName}`;
    const fileRef = bucket.file(objectPath);

    const normalizedFlash = sanitizeFlashArray(card.flash || []);
    const targetFlash =
      normalizedFlash.find((q) => q && q.id === flashId) || null;
    if (!targetFlash) {
      return res.status(404).json({ error: "Flash card introuvable." });
    }

    if (targetFlash[field]) {
      const safeName = targetFlash[field];
      if (isSafeFileName(safeName)) {
        const previousFile = bucket.file(
          `${sanitizedRepertoire}/tag${tagNumber}/imagesFlash/${safeName}`
        );
        previousFile
          .delete({ ignoreNotFound: true })
          .catch((err) =>
            console.warn("Suppression ancienne image flash echouee", err)
          );
      }
    }

    await uploadBufferToBucket(fileRef, file.data, file.mimetype);
    await makePublicIfAllowed(fileRef, "l'image");

    const nextFlash = normalizedFlash.map((q, idx) => ({
      ...q,
      id: q.id || `f${idx + 1}`,
      [field]: q.id === flashId ? uniqueName : q[field] || "",
    }));

    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { flash: sanitizeFlashArray(nextFlash) },
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
    console.error("POST /cards/:id/flash/image", error);
    return res.status(500).json({ error: "Erreur lors de l'upload de l'image." });
  }
});

router.delete("/:id/flash/image", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const flashId = typeof req.body?.flashId === "string" ? req.body.flashId.trim() : "";
    const image = typeof req.body?.image === "string" ? req.body.image.trim() : "";
    const fieldRaw = typeof req.body?.field === "string" ? req.body.field.trim() : "";
    const field =
      fieldRaw === "imquestion" || fieldRaw === "imreponse" ? fieldRaw : null;

    if (!flashId || !image || !field) {
      return res.status(400).json({ error: "flashId, field et image requis." });
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

    const normalizedFlash = sanitizeFlashArray(card.flash || []);
    const exists = normalizedFlash.some(
      (q) => q && q.id === flashId && q[field] === image
    );
    if (!exists) {
      return res.status(404).json({ error: "Image non trouvee dans le flash." });
    }

    const objectPath = `${sanitizedRepertoire}/tag${tagNumber}/imagesFlash/${image}`;
    try {
      await bucket.file(objectPath).delete({ ignoreNotFound: true });
    } catch (err) {
      console.warn("Suppression image flash echouee", err);
    }

    const nextFlash = normalizedFlash.map((q, idx) => ({
      ...q,
      id: q.id || `f${idx + 1}`,
      [field]: q.id === flashId ? "" : q[field] || "",
    }));
    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { flash: sanitizeFlashArray(nextFlash) },
      { new: true }
    ).lean();
    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apres suppression." });
    }

    return res.json({ result: updatedCard });
  } catch (error) {
    console.error("DELETE /cards/:id/flash/image", error);
    return res
      .status(500)
      .json({ error: "Erreur lors de la suppression de l'image." });
  }
});

router.post("/:id/bg/upload", requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "Aucun fichier fourni." });
    }

    const uploadedFile = extractSingleFile(req.files);
    if (!uploadedFile || !uploadedFile.data) {
      return res.status(400).json({ error: "Fichier d'upload invalide." });
    }

    const extension = path.extname(uploadedFile.name || "").toLowerCase();
    if (!allowedBgExtensions.has(extension)) {
      return res
        .status(400)
        .json({ error: "Extension d'image non autorisée." });
    }

    const targetRepertoire =
      (req.body && req.body.repertoire) || card.repertoire;
    let sanitizedRepertoire;
    try {
      sanitizedRepertoire = sanitizeStorageSegment(
        targetRepertoire,
        "Répertoire"
      );
    } catch (validationError) {
      return res.status(400).json({ error: validationError.message });
    }
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Répertoire manquant." });
    }

    const rawNum =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num;
    const tagNumber = normalizeTagNumber(rawNum);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numéro de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const safeBaseName = path
      .basename(uploadedFile.name || "background", extension)
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_+|_+$/g, "");
    const finalBase = safeBaseName ? safeBaseName.slice(0, 60) : "background";
    const uniqueBase = `${finalBase}_${Date.now()}`;
    const uniqueName = `${uniqueBase}${extension}`;
    const blurName = `${uniqueBase}Blur${extension}`;
    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${uniqueName}`;
    const blurPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${blurName}`;
    const fileRef = bucket.file(objectPath);
    const blurRef = bucket.file(blurPath);

    if (card.bg) {
      const previousFile = bucket.file(
        `${sanitizedRepertoire}/tag${normalizedTagNumber}/${card.bg}`
      );
      previousFile
        .delete({ ignoreNotFound: true })
        .catch((err) =>
          console.warn("Suppression de l'ancien background échouée", err)
        );

      const prevBlurName = toBlurFileName(card.bg);
      if (prevBlurName) {
        const prevBlurFile = bucket.file(
          `${sanitizedRepertoire}/tag${normalizedTagNumber}/${prevBlurName}`
        );
        prevBlurFile
          .delete({ ignoreNotFound: true })
          .catch((err) =>
            console.warn(
              "Suppression de l'ancien background flouté échouée",
              err
            )
          );
      }
    }

    await uploadBufferToBucket(
      fileRef,
      uploadedFile.data,
      uploadedFile.mimetype
    );
    const blurBuffer = await buildBlurBuffer(uploadedFile.data, extension);
    if (blurBuffer) {
      await uploadBufferToBucket(blurRef, blurBuffer, uploadedFile.mimetype);
    }
    await makePublicIfAllowed(fileRef, "le fichier");
    if (blurBuffer) {
      await makePublicIfAllowed(blurRef, "le fichier floute");
    }

    const updatedCard = await Card.findByIdAndUpdate(
      id,
      { bg: uniqueName },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({ error: "Carte introuvable après upload." });
    }

    res.json({
      result: updatedCard,
      fileName: uniqueName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (err) {
    console.error("POST /cards/:id/bg/upload", err);
    res.status(500).json({ error: "Erreur lors de l'upload de l'image." });
  }
});

router.post("/:id/files/sign", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawName = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const rawType = typeof req.body?.type === "string" ? req.body.type.trim() : "";
  const rawSize = req.body?.size;

  if (!rawName) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }

  const size = Number(rawSize);
  if (!Number.isFinite(size) || size <= 0) {
    return res.status(400).json({ error: "Taille de fichier invalide." });
  }
  if (size > MAX_FILE_BYTES) {
    return res
      .status(400)
      .json({ error: "Fichier trop volumineux (100 Mo max)." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const rawExtension = path.extname(rawName || "").toLowerCase();
    const { ext, base } = sanitizeFileBaseName(rawName, rawExtension);
    if (!ext || !allowedFileExtensions.has(ext)) {
      return res
        .status(400)
        .json({ error: "Extension de fichier non autorisee." });
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

    const rawNum =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num;
    const tagNumber = normalizeTagNumber(rawNum);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const uniqueName = `${base}_${Date.now()}${ext}`;
    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${uniqueName}`;
    const fileRef = bucket.file(objectPath);
    const contentType = rawType || "application/octet-stream";

    const [signedUrl] = await fileRef.getSignedUrl({
      version: "v4",
      action: "write",
      expires: Date.now() + 15 * 60 * 1000,
      contentType,
    });

    return res.json({
      result: {
        url: signedUrl,
        fileName: uniqueName,
        objectPath,
        contentType,
        publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
      },
    });
  } catch (err) {
    console.error("POST /cards/:id/files/sign", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la preparation de l'upload." });
  }
});

router.post("/:id/files/confirm", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const descriptionRaw =
    (req.body && (req.body.description || req.body.txt)) || "";
  const description =
    typeof descriptionRaw === "string" ? descriptionRaw.trim() : "";
  const hoverRaw = (req.body && req.body.hover) || "";
  const hover = typeof hoverRaw === "string" ? hoverRaw.trim() : "";
  const rawFileName =
    typeof req.body?.fileName === "string" ? req.body.fileName.trim() : "";

  if (!description) {
    return res.status(400).json({ error: "Le descriptif est obligatoire." });
  }
  if (!rawFileName) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(rawFileName)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }

  const extension = path.extname(rawFileName).toLowerCase();
  if (!extension || !allowedFileExtensions.has(extension)) {
    return res
      .status(400)
      .json({ error: "Extension de fichier non autorisee." });
  }

  try {
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

    const rawNum =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num;
    const tagNumber = normalizeTagNumber(rawNum);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${rawFileName}`;
    const fileRef = bucket.file(objectPath);
    const [exists] = await fileRef.exists();
    if (!exists) {
      return res
        .status(404)
        .json({ error: "Fichier introuvable sur le stockage." });
    }

    let metadata;
    try {
      [metadata] = await fileRef.getMetadata();
    } catch (err) {
      console.warn("Impossible de lire les metadonnees du fichier.", err);
      metadata = null;
    }

    const storedSize = Number(metadata?.size);
    if (Number.isFinite(storedSize) && storedSize > MAX_FILE_BYTES) {
      try {
        await fileRef.delete({ ignoreNotFound: true });
      } catch (err) {
        console.warn("Suppression du fichier trop volumineux echouee.", err);
      }
      return res
        .status(400)
        .json({ error: "Fichier trop volumineux (100 Mo max)." });
    }

    await makePublicIfAllowed(fileRef, "le fichier");

    const listPosition = resolveArrayInsertIndex(
      card.fichiers,
      req.body?.position
    );
    const normalizedPosition = Number.isFinite(listPosition)
      ? Math.trunc(listPosition)
      : null;
    const updateQuery = {
      _id: card._id,
      repertoire: card.repertoire,
      num: card.num,
    };
    const update = {
      $push: {
        fichiers: {
          $each: [
            { txt: description, href: rawFileName, visible: true, hover },
          ],
          ...(Number.isFinite(normalizedPosition)
            ? { $position: normalizedPosition }
            : {}),
        },
      },
    };
    const updatedCard = await Card.findOneAndUpdate(updateQuery, update, {
      new: true,
    }).lean();

    if (!updatedCard) {
      try {
        await fileRef.delete({ ignoreNotFound: true });
      } catch (err) {
        console.warn("Suppression fichier orphelin echouee", err);
      }
      return res
        .status(404)
        .json({ error: "Carte introuvable apres upload." });
    }

    return res.json({
      result: updatedCard,
      fileName: rawFileName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (err) {
    console.error("POST /cards/:id/files/confirm", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la confirmation de l'upload." });
  }
});

router.post("/:id/files/replace/sign", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const targetHref = (
    req.body && Object.prototype.hasOwnProperty.call(req.body, "href")
      ? `${req.body.href}`
      : ""
  ).trim();
  const rawName = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const rawType = typeof req.body?.type === "string" ? req.body.type.trim() : "";
  const rawSize = req.body?.size;

  if (!targetHref) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(targetHref)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }
  if (!rawName) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }

  const size = Number(rawSize);
  if (!Number.isFinite(size) || size <= 0) {
    return res.status(400).json({ error: "Taille de fichier invalide." });
  }
  if (size > MAX_FILE_BYTES) {
    return res
      .status(400)
      .json({ error: "Fichier trop volumineux (100 Mo max)." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const existsInCard = Array.isArray(card.fichiers)
      ? card.fichiers.some((f) => f && f.href === targetHref)
      : false;
    if (!existsInCard) {
      return res
        .status(404)
        .json({ error: "Fichier non trouve dans la carte." });
    }

    const rawExtension = path.extname(rawName || "").toLowerCase();
    const { ext, base } = sanitizeFileBaseName(rawName, rawExtension);
    if (!ext || !allowedFileExtensions.has(ext)) {
      return res
        .status(400)
        .json({ error: "Extension de fichier non autorisee." });
    }

    const sanitizedRepertoire = sanitizeStorageSegment(
      card.repertoire,
      "Repertoire"
    );
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Repertoire manquant." });
    }
    const tagNumber = normalizeTagNumber(card.num);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const uniqueName = `${base}_${Date.now()}${ext}`;
    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${uniqueName}`;
    const fileRef = bucket.file(objectPath);
    const contentType = rawType || "application/octet-stream";

    const [signedUrl] = await fileRef.getSignedUrl({
      version: "v4",
      action: "write",
      expires: Date.now() + 15 * 60 * 1000,
      contentType,
    });

    return res.json({
      result: {
        url: signedUrl,
        fileName: uniqueName,
        objectPath,
        contentType,
        publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
      },
    });
  } catch (err) {
    console.error("POST /cards/:id/files/replace/sign", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la preparation du remplacement." });
  }
});

router.post("/:id/files/replace/confirm", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const targetHref = (
    req.body && Object.prototype.hasOwnProperty.call(req.body, "href")
      ? `${req.body.href}`
      : ""
  ).trim();
  const rawFileName =
    typeof req.body?.fileName === "string" ? req.body.fileName.trim() : "";

  if (!targetHref) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(targetHref)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }
  if (!rawFileName) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(rawFileName)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }
  if (rawFileName === targetHref) {
    return res.status(400).json({ error: "Fichier de remplacement invalide." });
  }

  const extension = path.extname(rawFileName).toLowerCase();
  if (!extension || !allowedFileExtensions.has(extension)) {
    return res
      .status(400)
      .json({ error: "Extension de fichier non autorisee." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const existsInCard = Array.isArray(card.fichiers)
      ? card.fichiers.some((f) => f && f.href === targetHref)
      : false;
    if (!existsInCard) {
      return res
        .status(404)
        .json({ error: "Fichier non trouve dans la carte." });
    }

    const sanitizedRepertoire = sanitizeStorageSegment(
      card.repertoire,
      "Repertoire"
    );
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Repertoire manquant." });
    }
    const tagNumber = normalizeTagNumber(card.num);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${rawFileName}`;
    const fileRef = bucket.file(objectPath);
    const [exists] = await fileRef.exists();
    if (!exists) {
      return res
        .status(404)
        .json({ error: "Fichier introuvable sur le stockage." });
    }

    let metadata;
    try {
      [metadata] = await fileRef.getMetadata();
    } catch (err) {
      console.warn("Impossible de lire les metadonnees du fichier.", err);
      metadata = null;
    }

    const storedSize = Number(metadata?.size);
    if (Number.isFinite(storedSize) && storedSize > MAX_FILE_BYTES) {
      try {
        await fileRef.delete({ ignoreNotFound: true });
      } catch (err) {
        console.warn("Suppression du fichier trop volumineux echouee.", err);
      }
      return res
        .status(400)
        .json({ error: "Fichier trop volumineux (100 Mo max)." });
    }

    await makePublicIfAllowed(fileRef, "le fichier");

    const updatedCard = await Card.findOneAndUpdate(
      {
        _id: card._id,
        repertoire: card.repertoire,
        num: card.num,
        "fichiers.href": targetHref,
      },
      { $set: { "fichiers.$.href": rawFileName } },
      { new: true }
    ).lean();

    if (!updatedCard) {
      try {
        await fileRef.delete({ ignoreNotFound: true });
      } catch (err) {
        console.warn("Suppression fichier orphelin echouee", err);
      }
      return res
        .status(404)
        .json({ error: "Carte introuvable apres remplacement." });
    }

    const oldPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${targetHref}`;
    try {
      await bucket.file(oldPath).delete({ ignoreNotFound: true });
    } catch (err) {
      console.warn("Suppression de l'ancien fichier bucket echouee", err);
    }

    return res.json({
      result: updatedCard,
      fileName: rawFileName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (err) {
    console.error("POST /cards/:id/files/replace/confirm", err);
    return res
      .status(500)
      .json({ error: "Erreur lors de la confirmation du remplacement." });
  }
});

router.post("/:id/files/replace", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const targetHref = (
    req.body && Object.prototype.hasOwnProperty.call(req.body, "href")
      ? `${req.body.href}`
      : ""
  ).trim();

  if (!targetHref) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(targetHref)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const existsInCard = Array.isArray(card.fichiers)
      ? card.fichiers.some((f) => f && f.href === targetHref)
      : false;
    if (!existsInCard) {
      return res
        .status(404)
        .json({ error: "Fichier non trouve dans la carte." });
    }

    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "Aucun fichier fourni." });
    }

    const uploadedFile = extractSingleFile(req.files);
    if (!uploadedFile || !uploadedFile.data) {
      return res.status(400).json({ error: "Fichier d'upload invalide." });
    }

    const rawExtension = path.extname(uploadedFile.name || "").toLowerCase();
    const { ext, base } = sanitizeFileBaseName(uploadedFile.name, rawExtension);
    if (!ext || !allowedFileExtensions.has(ext)) {
      return res
        .status(400)
        .json({ error: "Extension de fichier non autorisee." });
    }

    if (uploadedFile.size && uploadedFile.size > MAX_FILE_BYTES) {
      return res
        .status(400)
        .json({ error: "Fichier trop volumineux (100 Mo max)." });
    }

    const sanitizedRepertoire = sanitizeStorageSegment(
      card.repertoire,
      "Repertoire"
    );
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "Repertoire manquant." });
    }
    const tagNumber = normalizeTagNumber(card.num);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Numero de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const uniqueName = `${base}_${Date.now()}${ext}`;
    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${uniqueName}`;
    const fileRef = bucket.file(objectPath);

    await uploadBufferToBucket(fileRef, uploadedFile.data, uploadedFile.mimetype);
    await makePublicIfAllowed(fileRef, "le fichier");

    const updatedCard = await Card.findOneAndUpdate(
      {
        _id: card._id,
        repertoire: card.repertoire,
        num: card.num,
        "fichiers.href": targetHref,
      },
      { $set: { "fichiers.$.href": uniqueName } },
      { new: true }
    ).lean();

    if (!updatedCard) {
      try {
        await fileRef.delete({ ignoreNotFound: true });
      } catch (err) {
        console.warn("Suppression fichier orphelin echouee", err);
      }
      return res
        .status(404)
        .json({ error: "Carte introuvable apres remplacement." });
    }

    const oldPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${targetHref}`;
    try {
      await bucket.file(oldPath).delete({ ignoreNotFound: true });
    } catch (err) {
      console.warn("Suppression de l'ancien fichier bucket echouee", err);
    }

    return res.json({
      result: updatedCard,
      fileName: uniqueName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (err) {
    console.error("POST /cards/:id/files/replace", err);
    return res
      .status(500)
      .json({ error: "Erreur lors du remplacement du fichier." });
  }
});

router.post("/:id/files", requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const descriptionRaw =
      (req.body && (req.body.description || req.body.txt)) || "";
    const description =
      typeof descriptionRaw === "string" ? descriptionRaw.trim() : "";
    if (!description) {
      return res.status(400).json({ error: "Le descriptif est obligatoire." });
    }
    const hoverRaw = (req.body && req.body.hover) || "";
    const hover = typeof hoverRaw === "string" ? hoverRaw.trim() : "";

    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "Aucun fichier fourni." });
    }

    const uploadedFile = extractSingleFile(req.files);
    if (!uploadedFile || !uploadedFile.data) {
      return res.status(400).json({ error: "Fichier d'upload invalide." });
    }

    const rawExtension = path.extname(uploadedFile.name || "").toLowerCase();
    const { ext, base } = sanitizeFileBaseName(uploadedFile.name, rawExtension);
    if (!ext || !allowedFileExtensions.has(ext)) {
      return res
        .status(400)
        .json({ error: "Extension de fichier non autorisée." });
    }

    if (uploadedFile.size && uploadedFile.size > MAX_FILE_BYTES) {
      return res
        .status(400)
        .json({ error: "Fichier trop volumineux (100 Mo max)." });
    }

    const targetRepertoire =
      (req.body && req.body.repertoire) || card.repertoire;
    let sanitizedRepertoire;
    try {
      sanitizedRepertoire = sanitizeStorageSegment(
        targetRepertoire,
        "R\u00e9pertoire"
      );
    } catch (validationError) {
      return res.status(400).json({ error: validationError.message });
    }
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "R\u00e9pertoire manquant." });
    }

    const rawNum =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "num")
        ? req.body.num
        : card.num;
    const tagNumber = normalizeTagNumber(rawNum);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Num\u00e9ro de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const uniqueName = `${base}_${Date.now()}${ext}`;
    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${uniqueName}`;
    const fileRef = bucket.file(objectPath);

    await uploadBufferToBucket(
      fileRef,
      uploadedFile.data,
      uploadedFile.mimetype
    );
    await makePublicIfAllowed(fileRef, "le fichier");

    const listPosition = resolveArrayInsertIndex(
      card.fichiers,
      req.body?.position
    );
    const normalizedPosition = Number.isFinite(listPosition)
      ? Math.trunc(listPosition)
      : null;
    const updateQuery = {
      _id: card._id,
      repertoire: card.repertoire,
      num: card.num,
    };
    const update = {
      $push: {
        fichiers: {
          $each: [{ txt: description, href: uniqueName, visible: true, hover }],
          ...(Number.isFinite(normalizedPosition)
            ? { $position: normalizedPosition }
            : {}),
        },
      },
    };
    const updatedCard = await Card.findOneAndUpdate(updateQuery, update, {
      new: true,
    }).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s upload." });
    }

    res.json({
      result: updatedCard,
      fileName: uniqueName,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${objectPath}`,
    });
  } catch (err) {
    console.error("POST /cards/:id/files", err);
    res.status(500).json({ error: "Erreur lors de l'upload du fichier." });
  }
});

router.delete("/:id/files", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const targetHref = (
    req.body && req.body.href ? `${req.body.href}` : ""
  ).trim();

  if (!targetHref) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(targetHref)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const sanitizedRepertoire = sanitizeStorageSegment(
      card.repertoire,
      "R\u00e9pertoire"
    );
    if (!sanitizedRepertoire) {
      return res.status(400).json({ error: "R\u00e9pertoire manquant." });
    }
    const tagNumber = normalizeTagNumber(card.num);
    if (tagNumber === null) {
      return res.status(400).json({ error: "Num\u00e9ro de tag invalide." });
    }
    const normalizedTagNumber = Math.trunc(tagNumber);

    const existsInCard = Array.isArray(card.fichiers)
      ? card.fichiers.some((f) => f && f.href === targetHref)
      : false;
    if (!existsInCard) {
      return res
        .status(404)
        .json({ error: "Fichier non trouv\u00e9 dans la carte." });
    }

    const objectPath = `${sanitizedRepertoire}/tag${normalizedTagNumber}/${targetHref}`;
    try {
      const fileRef = bucket.file(objectPath);
      await fileRef.delete({ ignoreNotFound: true });
    } catch (err) {
      console.warn("Suppression fichier bucket \u00e9chou\u00e9e", err);
    }

    const updatedCard = await Card.findOneAndUpdate(
      { _id: card._id, repertoire: card.repertoire, num: card.num },
      { $pull: { fichiers: { href: targetHref } } },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s suppression." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("DELETE /cards/:id/files", err);
    res
      .status(500)
      .json({ error: "Erreur lors de la suppression du fichier." });
  }
});

router.patch("/:id/files", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const targetHref = (
    req.body && req.body.href ? `${req.body.href}` : ""
  ).trim();
  const hasTxt = Object.prototype.hasOwnProperty.call(req.body || {}, "txt");
  const hasVisible = Object.prototype.hasOwnProperty.call(
    req.body || {},
    "visible"
  );
  const hasHover = Object.prototype.hasOwnProperty.call(req.body || {}, "hover");
  const rawTxt = hasTxt ? (`${req.body?.txt || ""}`).trim() : "";
  const rawHover = hasHover ? (`${req.body?.hover || ""}`).trim() : "";
  const rawVisible = hasVisible ? req.body?.visible : undefined;

  if (!targetHref) {
    return res.status(400).json({ error: "Nom de fichier manquant." });
  }
  if (!isSafeFileName(targetHref)) {
    return res.status(400).json({ error: "Nom de fichier invalide." });
  }
  if (!hasTxt && !hasVisible && !hasHover) {
    return res.status(400).json({ error: "Aucune modification fournie." });
  }
  if (hasTxt && !rawTxt) {
    return res.status(400).json({ error: "Le descriptif est obligatoire." });
  }

  let normalizedVisible = null;
  if (hasVisible) {
    if (typeof rawVisible === "boolean") {
      normalizedVisible = rawVisible;
    } else if (typeof rawVisible === "string") {
      const lowered = rawVisible.toLowerCase();
      if (lowered === "true") normalizedVisible = true;
      else if (lowered === "false") normalizedVisible = false;
    }
    if (normalizedVisible === null) {
      return res.status(400).json({ error: "Valeur visible invalide." });
    }
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const existsInCard = Array.isArray(card.fichiers)
      ? card.fichiers.some((f) => f && f.href === targetHref)
      : false;
    if (!existsInCard) {
      return res
        .status(404)
        .json({ error: "Fichier non trouv\u00e9 dans la carte." });
    }

    const updateFields = {};
    if (hasTxt) {
      updateFields["fichiers.$.txt"] = rawTxt;
    }
    if (hasVisible) {
      updateFields["fichiers.$.visible"] = normalizedVisible;
    }
    if (hasHover) {
      updateFields["fichiers.$.hover"] = rawHover;
    }

    const updatedCard = await Card.findOneAndUpdate(
      {
        _id: card._id,
        repertoire: card.repertoire,
        num: card.num,
        "fichiers.href": targetHref,
      },
      { $set: updateFields },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s mise \u00e0 jour." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/files", err);
    res
      .status(500)
      .json({ error: "Erreur lors de la mise \u00e0 jour du fichier." });
  }
});

router.patch("/:id/files/reorder", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const rawOrder = Array.isArray(req.body?.hrefs)
    ? req.body.hrefs
    : Array.isArray(req.body?.order)
    ? req.body.order
    : null;

  if (!rawOrder) {
    return res
      .status(400)
      .json({ error: "Liste d'ordre manquante (hrefs ou order)." });
  }

  const cleanedOrder = [];
  for (const item of rawOrder) {
    const href = typeof item === "string" ? item.trim() : "";
    if (!href) {
      return res
        .status(400)
        .json({ error: "Nom de fichier invalide dans l'ordre fourni." });
    }
    if (!isSafeFileName(href)) {
      return res.status(400).json({ error: `Nom de fichier invalide: ${href}.` });
    }
    cleanedOrder.push(href);
  }

  const unique = new Set(cleanedOrder);
  if (unique.size !== cleanedOrder.length) {
    return res.status(400).json({ error: "Duplicata dans l'ordre fourni." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const currentList = Array.isArray(card.fichiers)
      ? card.fichiers.filter((f) => f && typeof f.href === "string")
      : [];

    if (!currentList.length) {
      return res.status(400).json({ error: "Aucun fichier a reordonner." });
    }

    if (cleanedOrder.length !== currentList.length) {
      return res.status(400).json({ error: "Ordre incomplet ou invalide." });
    }

    const fileMap = new Map();
    for (const file of currentList) {
      fileMap.set(file.href, file);
    }

    const missing = currentList
      .map((f) => f.href)
      .filter((href) => !unique.has(href));
    if (missing.length) {
      return res.status(400).json({
        error: "Tous les fichiers doivent etre inclus dans l'ordre fourni.",
      });
    }

    const unknown = cleanedOrder.filter((href) => !fileMap.has(href));
    if (unknown.length) {
      return res
        .status(400)
        .json({ error: "Fichier inconnu dans l'ordre fourni." });
    }

    const reordered = cleanedOrder
      .map((href) => fileMap.get(href))
      .filter(Boolean);

    const updatedCard = await Card.findOneAndUpdate(
      { _id: card._id, repertoire: card.repertoire, num: card.num },
      { fichiers: reordered },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res.status(404).json({
        error: "Carte introuvable apres reordonnancement.",
      });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/files/reorder", err);
    res.status(500).json({
      error: "Erreur lors du reordonnancement des fichiers.",
    });
  }
});

router.post("/:id/video", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const position = req.body?.position;

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const currentList = sanitizeVideoArray(card.video);
    const insertIndex = resolveArrayInsertIndex(currentList, position);
    const normalizedIndex = Math.max(
      0,
      Math.min(currentList.length, insertIndex)
    );
    const next = [...currentList];
    next.splice(normalizedIndex, 0, { txt: "", href: "" });

    const updatedCard = await Card.findOneAndUpdate(
      { _id: card._id, repertoire: card.repertoire, num: card.num },
      { video: next },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s ajout." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("POST /cards/:id/video", err);
    res.status(500).json({ error: "Erreur lors de l'ajout de la video." });
  }
});

router.delete("/:id/video", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const index = Number.isInteger(req.body?.index)
    ? req.body.index
    : Number(req.body?.index);

  if (!Number.isInteger(index) || index < 0) {
    return res.status(400).json({ error: "Indice de video invalide." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }
    const list = Array.isArray(card.video) ? card.video : [];
    if (index >= list.length) {
      return res.status(404).json({ error: "Video introuvable." });
    }

    const next = list.filter((_, idx) => idx !== index);
    const updatedCard = await Card.findOneAndUpdate(
      { _id: card._id, repertoire: card.repertoire, num: card.num },
      { video: next },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s suppression." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("DELETE /cards/:id/video", err);
    res
      .status(500)
      .json({ error: "Erreur lors de la suppression de la video." });
  }
});

router.patch("/:id/video", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const index = Number.isInteger(req.body?.index)
    ? req.body.index
    : Number(req.body?.index);
  const hasTxt = Object.prototype.hasOwnProperty.call(req.body || {}, "txt");
  const hasHref = Object.prototype.hasOwnProperty.call(req.body || {}, "href");

  if (!Number.isInteger(index) || index < 0) {
    return res.status(400).json({ error: "Indice de video invalide." });
  }
  if (!hasTxt && !hasHref) {
    return res.status(400).json({ error: "Aucune modification fournie." });
  }

  try {
    const card = await Card.findById(id).lean();
    if (!card) {
      return res.status(404).json({ error: "Carte introuvable." });
    }

    const list = sanitizeVideoArray(card.video);
    if (index >= list.length) {
      return res.status(404).json({ error: "Video introuvable." });
    }

    const current = list[index] || { txt: "", href: "" };
    list[index] = {
      txt: hasTxt ? (req.body.txt || "").trim() : current.txt || "",
      href: hasHref ? (req.body.href || "").trim() : current.href || "",
    };

    const updatedCard = await Card.findOneAndUpdate(
      { _id: card._id, repertoire: card.repertoire, num: card.num },
      { video: list },
      { new: true }
    ).lean();

    if (!updatedCard) {
      return res
        .status(404)
        .json({ error: "Carte introuvable apr\u00e8s mise \u00e0 jour." });
    }

    res.json({ result: updatedCard });
  } catch (err) {
    console.error("PATCH /cards/:id/video", err);
    res
      .status(500)
      .json({ error: "Erreur lors de la mise \u00e0 jour de la video." });
  }
});

module.exports = router;
