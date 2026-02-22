const jwt = require("jsonwebtoken");

const authenticate = (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) {
    return res.status(401).json({ message: "Non autorisé - token manquant" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded; // userId, email, nom, prenom, role
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Session expirée" });
    }
    return res.status(401).json({ message: "Token invalide" });
  }
};

function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Accès interdit" });
    }
    next();
  };
}

function verifyToken(req, res, next) {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ message: "Accès non autorisé : pas de token" });
    }
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Erreur de vérification du token :", error);
    return res.status(401).json({ message: "Token invalide ou expiré" });
  }
}

const requireAdmin = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ message: "Accès réservé aux administrateurs" });
    }
    next();
  });
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

function requireScopedAdmin(getRepertoire) {
  return (req, res, next) => {
    verifyToken(req, res, () => {
      if (req.user?.role === "admin") {
        return next();
      }

      Promise.resolve()
        .then(() =>
          typeof getRepertoire === "function" ? getRepertoire(req) : null
        )
        .then((repertoire) => {
          const slug = toSlug(repertoire);
          const allowed =
            !!slug &&
            Array.isArray(req.user?.adminRepertoires) &&
            req.user.adminRepertoires.includes(slug);

          if (!allowed) {
            return res.status(403).json({ message: "Accès réservé" });
          }

          return next();
        })
        .catch((err) => {
          console.error("Erreur d'autorisation scoped admin :", err);
          return res.status(500).json({ error: "Erreur interne du serveur" });
        });
    });
  };
}

module.exports = {
  authenticate,
  authorize,
  verifyToken,
  requireAdmin,
  requireScopedAdmin,
};
