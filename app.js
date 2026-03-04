var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
require("dotenv").config();
const connectToDatabase = require("./models/connection");

var indexRouter = require("./routes/index");
var authRoutes = require("./routes/auth");
var usersRouter = require("./routes/users");
var uploadRouter = require("./routes/upload");
var cardsRouter = require("./routes/cards");
var quizzsRouter = require("./routes/quizzs");

var app = express();
connectToDatabase().catch((err) => {
  console.error("Database connection error:", err);
});

const dbGuard = (req, res, next) => {
  connectToDatabase().then(() => next()).catch(next);
};

const fileUpload = require("express-fileupload");
app.use(
  fileUpload({
    limits: { fileSize: 100 * 1024 * 1024 },
    abortOnLimit: true, // optionnel : stoppe proprement si dépassement
    // responseOnLimit: "Fichier trop volumineux (100 Mo max)." // optionnel
  })
);
const cors = require("cors");
const allowedOrigins = [
  "http://localhost:3001", // front en local
  "http://localhost:3000", // front en local
  "https://educappdf-front.vercel.app", // front en production
  "https://educappdf-testfront.vercel.app", // front en test
  "https://mathsapp.fr", // DNS
];
app.use(
  cors({
    origin: function (origin, callback) {
      // Autorise les requêtes sans origin (Postman, server-side) ou celles dans la liste
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.error("❌ Requête refusée par CORS : ", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true })); //false ds la Capsule
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
app.use("/users", dbGuard, usersRouter); // pour profile, admin actions...
app.use("/auth", dbGuard, authRoutes); // pour login/logout/signup/refresh
app.use("/upload", uploadRouter);
app.use("/cards", dbGuard, cardsRouter); // pour profile, admin actions...
app.use("/quizzs", dbGuard, quizzsRouter); // pour enregistrements des résultats de quizz...

module.exports = app;
