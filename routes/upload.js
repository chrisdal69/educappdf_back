var express = require("express");
var router = express.Router();
const path = require("path");
const archiver = require("archiver");
const { Storage } = require("@google-cloud/storage");
const {
  authenticate,
  authorize,
  verifyToken,
  requireAdmin,
  requireScopedAdmin,
} = require("../middlewares/auth");

const requireUploadScopedAdmin = requireScopedAdmin((req) => req.body?.repertoire);


//GESTION du google Storage
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
const fs = require("fs");
const bucket = storage.bucket(bucketName);

// Extensions autorisés
const allowedExtensions = [
  ".jpg",
  ".jpeg",
  ".png",
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".txt",
  ".py",
  ".html",
  ".css",
  ".js",
  ".ggb",
  ".fls",
];

// Liste blanche optionnelle des parents
const allowedParents = ["ciel1","cloud","python"];
const stripPrefix = (name = "") => {
  const parts = `${name}`.split("___");
  return parts.length > 1 ? parts.slice(1).join("___") : name;
};

// Téléchargement proxy (retire le préfixe nom+prenom+___ du nom proposé)
router.get("/download", authenticate, async (req, res) => {
  try {
    const parent = validatePathComponent(req.query.parent, "Dossier parent");
    const repertoire = validatePathComponent(
      req.query.repertoire,
      "Nom de répertoire"
    );
    const file = validateFileName(req.query.file, "Nom de fichier");

    if (!allowedParents.includes(parent)) {
      return res
        .status(403)
        .json({ error: "Dossier parent non autorisé." });
    }

    const objectPath = `${parent}/${repertoire}/${file}`;
    const fileRef = bucket.file(objectPath);
    const [exists] = await fileRef.exists();
    if (!exists) {
      return res.status(404).json({ error: "Fichier introuvable." });
    }

    const [metadata] = await fileRef.getMetadata();
    const contentType = metadata?.contentType || "application/octet-stream";
    const downloadName = stripPrefix(file) || file;
    const safeName = downloadName.replace(/"/g, "");

    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}"; filename*=UTF-8''${encodeURIComponent(
        safeName
      )}`
    );

    const stream = fileRef.createReadStream();
    stream.on("error", (err) => {
      console.error("Erreur lecture fichier cloud download", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Erreur lors du téléchargement." });
      } else {
        res.end();
      }
    });
    stream.pipe(res);
  } catch (err) {
    console.error("GET /upload/download", err);
    res
      .status(400)
      .json({ error: err.message || "Erreur lors du téléchargement." });
  }
});

/************************************************************************* */

//DEBUT CREATION FOLDER DANS Google Storage
// Crée un "dossier" dans le bucket mathsapp et rend public son contenu uniquement
//@param : exemple : createPublicFolder('ciel1', 'tp1')

async function createPublicFolder(dossierParent, folderName) {
  const folderPath = folderName.endsWith("/")
    ? `${dossierParent}/${folderName}`
    : `${dossierParent}/${folderName}/`;
  try {
    // 1ï¸âƒ£ Vérifier si le dossier existe déjÃ 
    const [files] = await bucket.getFiles({
      prefix: folderPath,
      maxResults: 1,
    });
    if (files.length > 0) {
      console.log(
        `â„¹ï¸ Le dossier ${folderPath} existe déjÃ , aucune action nécessaire.`
      );
      return {
        result: true,
        message: `Le dossier ${folderPath} existe déjÃ .`,
        publicUrl: `https://storage.googleapis.com/${bucketName}/${folderPath}`,
      };
    }

    // 2ï¸âƒ£ Crée un "fichier" vide pour matérialiser le dossier
    const file = bucket.file(folderPath);
    await file.save("");
    console.log(`âœ… Dossier ${folderPath} créé.`);

    // 3ï¸âƒ£ RécupÃ¨re la policy IAM du bucket
    const [policy] = await bucket.iam.getPolicy();

    // 4ï¸âƒ£ Vérifie qu'une rÃ¨gle pour ce dossier n'existe pas déjÃ 
    const exists = policy.bindings.some(
      (b) =>
        b.role === "roles/storage.objectViewer" &&
        b.members.includes("allUsers") &&
        b.condition?.expression?.includes(`/objects/${folderPath}`)
    );

    if (exists) {
      console.log(`ðŸ”’ Les accÃ¨s publics pour ${folderPath} existent déjÃ .`);
      return {
        result: true,
        message: `Le dossier ${folderPath} existe déjÃ  et est public.`,
        publicUrl: `https://storage.googleapis.com/${bucketName}/${folderPath}`,
      };
    }

    // 5ï¸âƒ£ Ajoute la rÃ¨gle IAM publique pour ce préfixe
    policy.bindings.push({
      role: "roles/storage.objectViewer",
      members: ["allUsers"],
      condition: {
        title: `Public access to ${folderPath}`,
        description: `Allow public read access to files in ${folderPath}`,
        expression: `resource.name.startsWith("projects/_/buckets/${bucketName}/objects/${folderPath}")`,
      },
    });

    // 6ï¸âƒ£ Applique la policy mise Ã  jour
    await bucket.iam.setPolicy(policy);
    console.log(`ðŸŒ Le dossier ${folderPath} est désormais public.`);

    return {
      result: true,
      message: `Le dossier ${folderPath} a été créé et rendu public.`,
      publicUrl: `https://storage.googleapis.com/${bucketName}/${folderPath}`,
    };
  } catch (err) {
    console.error("âŒ Erreur lors de la création du dossier public :", err);
    return { result: false, error: err.message };
  }
}

//FIN CREATION FOLDER DANS Google Storage

/************************************************************************* */

/* DEBUT Lister des fichiers qui sont dans le répertoire */

router.post("/recup", authenticate, async (req, res) => {
  try {
    // Validation des champs name , parent et repertoire
    const { nom, prenom, email, role } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;
    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(
      req.body.repertoire,
      "Nom de répertoire"
    );
    // Whitelist de parent (cohérente avec l'upload)
    if (!allowedParents.includes(parent)) {
      return res.status(403).send("Dossier parent non autorisé.");
    }
    const repertoireBucket = `${parent}/${repertoire}`;

    // On cible le  répertoire
    const [files] = await bucket.getFiles({
      prefix: `${repertoireBucket}/`, // dossier cible
      delimiter: "/", // permet d'éviter de descendre dans des sous-dossiers
    });

    // Extraire uniquement les noms de fichiers
    const fileNames = files.map((file) => {
      return {
        name: file.name,
        url: `https://storage.googleapis.com/${bucketName}/${file.name}`,
      };
    });
    const fileNamesFilter = fileNames.filter((obj) =>
      obj.name
        .split("/")
        .pop()
        .startsWith(safeName + "___")
    );

    res.json(fileNamesFilter);
  } catch (err) {
    console.error(
      "Erreur lors de la récupération des fichiers du dossier",
      err
    );
    res
      .status(500)
      .send("Erreur lors de la récupération des fichiers du dossier");
  }
});


/* DEBUT téléchargement ZIP de tout un dossier (admin) */

router.post("/downloadZipA", requireUploadScopedAdmin, async (req, res) => {
  try {
    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(
      req.body.repertoire,
      "Nom de répertoire"
    );
    if (!allowedParents.includes(parent)) {
      return res
        .status(403)
        .json({ success: false, message: "Dossier parent non autorisé" });
    }

    const prefix = `${parent}/${repertoire}/`;
    const [files] = await bucket.getFiles({
      prefix,
      delimiter: "/",
    });
    const fileList = files.filter(
      (file) => file.name && !file.name.endsWith("/")
    );
    if (!fileList.length) {
      return res.status(404).json({
        success: false,
        message: "Aucun fichier à archiver dans ce dossier",
      });
    }

    const archiveName = `${repertoire}.zip`.replace(
      /[^a-zA-Z0-9._-]/g,
      "_"
    );
    res.setHeader("Content-Type", "application/zip");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${archiveName}"`
    );

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", (err) => {
      console.error("Erreur lors de la création de l'archive :", err);
      if (!res.headersSent) {
        res.status(500).end("Erreur lors de la génération du zip");
      } else {
        res.end();
      }
    });

    archive.pipe(res);

    fileList.forEach((file) => {
      const relativeName = file.name.startsWith(prefix)
        ? file.name.slice(prefix.length)
        : path.basename(file.name);
      const readStream = bucket.file(file.name).createReadStream();
      archive.append(readStream, {
        name: relativeName || path.basename(file.name),
      });
    });

    archive.finalize();
  } catch (err) {
    console.error("Erreur sur /downloadZipA :", err);
    res.status(500).json({
      success: false,
      message: "Erreur lors de la génération de l'archive",
      error: err.message,
    });
  }
});

/* FIN téléchargement ZIP de tout un dossier (admin) */

/* FIN  des fichiers qui sont dans le répertoire */

/************************************************************************* */

/* DEBUT Lister tous les fichiers qui sont dans le répertoire (admin) */

router.post("/recupA", requireUploadScopedAdmin, async (req, res) => {
  try {
    // Validation des champs name , parent et repertoire
    const { nom, prenom, email, role } = req.user;
    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(
      req.body.repertoire,
      "Nom de répertoire"
    );
    // Whitelist de parent (cohérente avec l'upload)
    if (!allowedParents.includes(parent)) {
      return res.status(403).send("Dossier parent non autorisé.");
    }
    const repertoireBucket = `${parent}/${repertoire}`;

    // On cible le  répertoire
    const [files] = await bucket.getFiles({
      prefix: `${repertoireBucket}/`, // dossier cible
      delimiter: "/", // permet d'éviter de descendre dans des sous-dossiers
    });

    // Extraire uniquement les noms de fichiers
    const fileNames = files.map((file) => {
      return {
        name: file.name,
        url: `https://storage.googleapis.com/${bucketName}/${file.name}`,
      };
    });
 
    res.json(fileNames);
  } catch (err) {
    console.error(
      "Erreur lors de la récupération des fichiers du dossier",
      err
    );
    res
      .status(500)
      .send("Erreur lors de la récupération des fichiers du dossier");
  }
});

/* FIN  liste admin des fichiers qui sont dans le répertoire */

/************************************************************************* */


/* DEBUT Récupérer l'upload du front et envoyer les fichiers dans le bucket google */
// Dossier de stockage dans le bucket
function validatePathComponent(value, label) {
  if (!value || typeof value !== "string") {
    throw new Error(`${label} manquant`);
  }

  // Nettoyage de base
  const cleaned = value.trim();

  // Longueur raisonnable
  if (cleaned.length > 50) {
    throw new Error(`${label} trop long`);
  }

  // Regex whitelist : uniquement lettres, chiffres, tirets et underscores
  if (!/^[a-zA-Z0-9_-]+$/.test(cleaned)) {
    throw new Error(
      `${label} invalide : seuls lettres, chiffres, "-", "_" sont autorisés`
    );
  }

  // EmpÃªche chemins relatifs ou séparateurs
  if (
    cleaned.includes("/") ||
    cleaned.includes("\\") ||
    cleaned.includes("..")
  ) {
    throw new Error(`${label} invalide : caractÃ¨res de chemin interdits`);
  }

  return cleaned;
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


// Valide un nom de fichier (pas de séparateurs/chemins, longueur et charset raisonnables)
function validateFileName(name, label = "Nom de fichier") {
  if (!name || typeof name !== "string") {
    throw new Error(`${label} manquant`);
  }
  const cleaned = name.trim();
  if (cleaned.length === 0 || cleaned.length > 100) {
    throw new Error(`${label} invalide : longueur incorrecte`);
  }
  // Autorise lettres/chiffres/.-_ (pas d'espaces ni séparateurs de chemin)
  if (!/^[a-zA-Z0-9._\- ]+$/.test(cleaned)) {
    throw new Error(
      `${label} invalide : seuls lettres, chiffres, ".", "-", "_" sont autorisés`
    );
  }
  if (cleaned.includes("/") || cleaned.includes("\\") || cleaned.includes("..")) {
    throw new Error(`${label} invalide : caractÃ¨res de chemin interdits`);
  }
  return cleaned;
}

router.post("/", authenticate, async (req, res) => {
  try {
    // Validation parent et repertoire
    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(
      req.body.repertoire,
      "Nom de répertoire"
    );
    // (Optionnel) Restreindre à une liste blanche
    if (!allowedParents.includes(parent)) {
      return res.status(403).send("Dossier parent non autorisé.");
    }
    // Création du répertoire public si besoin
    await createPublicFolder(parent, repertoire);
    const repertoireBucket = `${parent}/${repertoire}`;
    // Préfixe du user devant le fichier
    const { nom, prenom, email, role } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;
    // Vérifie la présence de fichiers
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).send("Aucun fichier reçu");
    }
    //
    const fichiersCopies = [];
    const rejected = [];
    const fichiers = Array.isArray(req.files.fichiers)
      ? req.files.fichiers
      : [req.files.fichiers];

    for (const file of fichiers) {
      const originalRaw = (file.name || "").toString();
      const originalBase = originalRaw.split(/[\\/]/).pop();
      let original;
      try {
        original = validateFileName(originalBase);
      } catch (e) {
        console.warn(`Nom de fichier invalide ignoré : ${originalBase}`);
        throw new Error(`Nom de fichier invalide: ${originalBase}`);
      }
      const ext = path.extname(original).toLowerCase();
      if (!allowedExtensions.includes(ext)) {
        throw new Error(`Extension invalide pour: ${original}`);
      }

      if (file.size > 5_000_000) {
        throw new Error(`Taille de fichier invalide: ${original}`);
      }

      const destFileName = `${repertoireBucket}/${safeName}___${original}`;
      const fileRef = bucket.file(destFileName);
      // Upload sans fichier temporaire si le buffer est disponible (express-fileupload useTempFiles: false)
      if (file.data && Buffer.isBuffer(file.data)) {
        await fileRef.save(file.data, {
          resumable: false,
          metadata: { contentType: file.mimetype },
        });
      } else if (file.tempFilePath && fs.existsSync(file.tempFilePath)) {
        // Fallback si express-fileupload est configuré avec useTempFiles: true
        await storage
          .bucket(bucketName)
          .upload(file.tempFilePath, {
            destination: destFileName,
            metadata: { contentType: file.mimetype },
            resumable: false,
          });
      } else {
        throw new Error(`Source de fichier indisponible pour: ${original}`);
      }
      fichiersCopies.push({
        name: original,
        url: `https://storage.googleapis.com/${bucketName}/${destFileName}`,
      });
    }

    if (fichiersCopies.length === 0) {
      return res.status(400).json({
        result: false,
        error: "Aucun fichier accepté (nom/extension/taille invalides)",
      });
    }

    res.json({
      result: true,
      files: fichiersCopies,
    });
  } catch (err) {
    console.error("Erreur réception sur le back :", err);
    const status =
      err.message.includes("invalide") || err.message.includes("manquant")
        ? 400
        : 500;
    res.status(status).json({ result: false, error: err.message, message: err.message });
  }
});

/* FIN Récupérer l'upload du front et envoyer les fichiers dans le bucket google */

/************************************************************************* */

/* DEBUT supprimer un fichier pour l'admin */
router.post("/delete", authenticate, async (req, res) => {
  try {
    const { nom, prenom } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;

    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(req.body.repertoire, "Nom de répertoire");
    const file = validateFileName(req.body.file, "Nom de fichier");

    if (!parent || !repertoire || !file) {
      return res
        .status(400)
        .json({ success: false, message: "Données manquantes" });
    }

    if (!allowedParents.includes(parent)) {
      return res.status(403).json({ success: false, message: "Dossier parent non autorisé" });
    }

    if (!file.startsWith(`${safeName}___`)) {
      return res.status(403).json({ success: false, message: "Accés refusé" });
    }

    const filePath = `${parent}/${repertoire}/${file}`;
    const fileRef = bucket.file(filePath);
    await fileRef.delete();

    console.log(`Fichier supprimé : ${filePath}`);
    return res.json({ success: true, message: "Fichier supprimé" });
  } catch (err) {
    console.error("Erreur suppression fichier :", err);
    return res.status(500).json({
      success: false,
      message: "Erreur lors de la suppression du fichier",
      error: err.message,
    });
  }
});
/* FIN supprimer un fichier */

/* DEBUT supprimer un fichier */
router.post("/deleteA", requireUploadScopedAdmin, async (req, res) => {
  try {
    const { nom, prenom } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;

    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(req.body.repertoire, "Nom de répertoire");
    const file = validateFileName(req.body.file, "Nom de fichier");

    if (!parent || !repertoire || !file) {
      return res
        .status(400)
        .json({ success: false, message: "Données manquantes" });
    }

    if (!allowedParents.includes(parent)) {
      return res.status(403).json({ success: false, message: "Dossier parent non autorisé" });
    }

    const filePath = `${parent}/${repertoire}/${file}`;
    const fileRef = bucket.file(filePath);
    await fileRef.delete();

    console.log(`Fichier supprimé : ${filePath}`);
    return res.json({ success: true, message: "Fichier supprimé" });
  } catch (err) {
    console.error("Erreur suppression fichier :", err);
    return res.status(500).json({
      success: false,
      message: "Erreur lors de la suppression du fichier",
      error: err.message,
    });
  }
});
/* FIN supprimer un fichier pour l'admin */





/* DEBUT renommer un fichier */
router.post("/rename", authenticate, async (req, res) => {
  try {
    const { nom, prenom } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;

    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(req.body.repertoire, "Nom de répertoire");
    const oldName = validateFileName(req.body.oldName, "Ancien nom");
    const newName = validateFileName(req.body.newName, "Nouveau nom");

    if (!parent || !repertoire || !oldName || !newName) {
      return res
        .status(400)
        .json({ success: false, message: "Données manquantes" });
    }

    if (!allowedParents.includes(parent)) {
      return res.status(403).json({ success: false, message: "Dossier parent non autorisé" });
    }
    if (!oldName.startsWith(`${safeName}___`)) {
      return res.status(403).json({ success: false, message: "Accés refusé" });
    }
    const ext = path.extname(newName).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({ success: false, message: "Extension non autorisée" });
    }

    const oldPath = `${parent}/${repertoire}/${oldName}`;
    const racine = oldName.split('___')[0];
    const newPath = `${parent}/${repertoire}/${racine}___${newName}`;
    
    const oldFile = bucket.file(oldPath);
    const newFile = bucket.file(newPath);

    // Vérifie si lâ€™ancien fichier existe
    const [exists] = await oldFile.exists();
    if (!exists) {
      return res
        .status(404)
        .json({ success: false, message: "Fichier introuvable" });
    }
    

    // Copie vers le nouveau nom
    await oldFile.copy(newFile);
    // Supprime lâ€™ancien fichier
    await oldFile.delete();

    console.log(`Fichier renommé : ${oldPath} â†’ ${newPath}`);
    return res.json({ success: true, message: "Fichier renommé" });
  } catch (err) {
    console.error("Erreur renommage fichier :", err);
    return res.status(500).json({
      success: false,
      message: "Erreur lors du renommage du fichier",
      error: err.message,
    });
  }
});
/* FIN renommer un fichier */

/* DEBUT renommer un fichier en admin*/
router.post("/renameA", requireUploadScopedAdmin, async (req, res) => {
  try {
    const { nom, prenom } = req.user;
    const safeName = `${removeSpaces(nom)}${removeSpaces(prenom)}`;

    const parent = validatePathComponent(req.body.parent, "Dossier parent");
    const repertoire = validatePathComponent(req.body.repertoire, "Nom de répertoire");
    const oldName = validateFileName(req.body.oldName, "Ancien nom");
    const newName = validateFileName(req.body.newName, "Nouveau nom");

    if (!parent || !repertoire || !oldName || !newName) {
      return res
        .status(400)
        .json({ success: false, message: "Données manquantes" });
    }

    if (!allowedParents.includes(parent)) {
      return res.status(403).json({ success: false, message: "Dossier parent non autorisé" });
    }
   
    const ext = path.extname(newName).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({ success: false, message: "Extension non autorisée" });
    }
   
    const oldPath = `${parent}/${repertoire}/${oldName}`;
    const racine = oldName.split('___')[0];
    const newPath = `${parent}/${repertoire}/${racine}___${newName}`;
    
    const oldFile = bucket.file(oldPath);
    const newFile = bucket.file(newPath);
 
    // Vérifie si lâ€™ancien fichier existe
    const [exists] = await oldFile.exists();
    if (!exists) {
      return res
        .status(404)
        .json({ success: false, message: "Fichier introuvable" });
    }

    // Copie vers le nouveau nom
    await oldFile.copy(newFile);
    // Supprime lâ€™ancien fichier
    await oldFile.delete();

    console.log(`Fichier renommé : ${oldPath} â†’ ${newPath}`);
    return res.json({ success: true, message: "Fichier renommé" });
  } catch (err) {
    console.error("Erreur renommage fichier :", err);
    return res.status(500).json({
      success: false,
      message: "Erreur lors du renommage du fichier",
      error: err.message,
    });
  }
});
/* FIN renommer un fichier en admin */



/* DEBUT exemple route pour utiliser veriyToken */

router.get("/profil", verifyToken, (req, res) => {
  // Tu as maintenant accÃ¨s Ã  req.user (décodé depuis le JWT)
  const { nom, prenom, email, role } = req.user;

  res.json({
    message: "Données de l'utilisateur connecté",
    nom,
    prenom,
    email,
    role,
  });
});

//router.use(verifyToken);

// Toutes les routes en dessous sont protégées
router.get("/dashboard", verifyToken, (req, res) => {
  res.json({ message: `Bienvenue ${req.user.prenom} ${req.user.nom}` });
});
/* FIN exemple route pour utiliser veriyToken */

module.exports = router;
