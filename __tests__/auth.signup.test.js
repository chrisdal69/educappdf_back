const express = require("express");
const request = require("supertest");
const mongoose = require("mongoose");

jest.mock("nodemailer", () => ({
  createTransport: jest.fn(() => ({
    sendMail: jest.fn(async () => ({ messageId: "test-message-id" })),
  })),
}));

jest.mock("bcrypt", () => ({
  hash: jest.fn(async (value) => `hashed:${value}`),
  compareSync: jest.fn((plain, hashed) => hashed === `hashed:${plain}`),
}));

const makeQuery = (result) => {
  const query = {
    select: jest.fn(() => query),
    lean: jest.fn(async () => result),
    exec: jest.fn(async () => result),
    then: (resolve, reject) => Promise.resolve(result).then(resolve, reject),
    catch: (reject) => Promise.resolve(result).catch(reject),
  };
  return query;
};

jest.mock("../models/users", () => {
  const mongoose = require("mongoose");

  const User = jest.fn(function User(doc) {
    Object.assign(this, doc);
    this._id = this._id || new mongoose.Types.ObjectId();
    this.save = jest.fn(async () => this);
  });

  User.findOne = jest.fn();
  User.updateOne = jest.fn(async () => ({ acknowledged: true, matchedCount: 1, modifiedCount: 1 }));
  User.deleteOne = jest.fn(async () => ({ acknowledged: true, deletedCount: 1 }));
  User.exists = jest.fn(async () => null);
  User.findById = jest.fn();
  User.collection = {
    updateOne: jest.fn(async () => ({ acknowledged: true, matchedCount: 1, modifiedCount: 1 })),
    findOne: jest.fn(async () => null),
  };

  return User;
});

jest.mock("../models/classes", () => {
  const Classe = {};
  Classe.findOne = jest.fn();
  Classe.updateOne = jest.fn();
  Classe.exists = jest.fn();
  Classe.find = jest.fn();
  return Classe;
});

const User = require("../models/users");
const Classe = require("../models/classes");

const buildApp = () => {
  const authRouter = require("../routes/auth");
  const app = express();
  app.use(express.json());
  app.use("/auth", authRouter);
  return app;
};

describe("Auth signup flow", () => {
  beforeEach(() => {
    User.mockClear();
    User.findOne.mockReset();
    User.updateOne.mockClear();
    User.deleteOne.mockClear();
    Classe.findOne.mockReset();
    Classe.updateOne.mockReset();
    Classe.exists.mockReset();
  });

  test("POST /auth/signup/validate-teacher-code returns only available students", async () => {
    const classId = new mongoose.Types.ObjectId();
    const classeDoc = {
      _id: classId,
      students: [
        { nom: "DUPONT", prenom: "elodie", free: true, id_user: null },
        { nom: "MARTIN", prenom: "paul", free: false, id_user: null },
        { nom: "DURAND", prenom: "lea", free: true, id_user: new mongoose.Types.ObjectId() },
        { nom: "ROUX", prenom: "ana", id_user: null }, // free missing => considered available
      ],
    };

    Classe.findOne.mockReturnValueOnce(makeQuery(classeDoc));

    const app = buildApp();
    const res = await request(app)
      .post("/auth/signup/validate-teacher-code")
      .send({ code: "AB12" });

    expect(res.status).toBe(200);
    expect(res.body.classId).toBe(classId.toString());
    expect(Array.isArray(res.body.students)).toBe(true);
    expect(res.body.students).toHaveLength(2);
    expect(res.body.students.map((s) => s.nom)).toEqual(["DUPONT", "ROUX"]);
  });

  test("POST /auth/signup/check-student rejects when nom/prenom not in students", async () => {
    const classId = new mongoose.Types.ObjectId();
    const classeDoc = {
      _id: classId,
      students: [{ nom: "DUPONT", prenom: "elodie", free: true, id_user: null }],
    };

    // ensureStudentInClass uses findOne(...).select(...).lean()
    Classe.findOne.mockReturnValueOnce(makeQuery(classeDoc));

    const app = buildApp();
    const res = await request(app).post("/auth/signup/check-student").send({
      classId: classId.toString(),
      nom: "Martin",
      prenom: "Paul",
      email: "x@y.com",
    });

    expect(res.status).toBe(400);
    expect(res.body.redirect).toBe(true);
  });

  test("POST /auth/signup/create creates user and sends verification email (no slot claim yet)", async () => {
    const classId = new mongoose.Types.ObjectId();
    const classeDoc = {
      _id: classId,
      students: [{ nom: "DUPONT", prenom: "elodie", free: true, id_user: null }],
    };

    // ensureStudentInClass uses findOne(...).select(...).lean()
    Classe.findOne.mockReturnValue(makeQuery(classeDoc));

    User.findOne.mockImplementation((query) => {
      if (query && query.email) return makeQuery(null);
      if (query && query.nom && query.prenom) return makeQuery(null);
      return makeQuery(null);
    });

    const app = buildApp();
    const res = await request(app).post("/auth/signup/create").send({
      classId: classId.toString(),
      nom: "Dupont",
      prenom: "Élodie",
      email: "elodie.dupont@test.com",
      password: "Abcd!1234",
      confirmPassword: "Abcd!1234",
    });

    expect(res.status).toBe(201);
    expect(res.body.sendMail).toBe(true);
    expect(Classe.updateOne).not.toHaveBeenCalled();
  });

  test("POST /auth/verifmail claims student slot and completes signup", async () => {
    const classId = new mongoose.Types.ObjectId();
    const classeDoc = {
      _id: classId,
      students: [{ nom: "DUPONT", prenom: "elodie", free: true, id_user: null }],
    };

    Classe.findOne.mockReturnValue(makeQuery(classeDoc));

    const userDoc = {
      _id: new mongoose.Types.ObjectId(),
      email: "elodie.dupont@test.com",
      nom: "DUPONT",
      prenom: "elodie",
      confirm: "hashed:ABCD",
      confirmExpires: new Date(Date.now() + 10 * 60 * 1000),
      isVerified: false,
    };
    User.findOne.mockImplementation((query) => {
      if (query && query.email === userDoc.email) return makeQuery(userDoc);
      return makeQuery(null);
    });

    Classe.updateOne.mockResolvedValueOnce({
      acknowledged: true,
      matchedCount: 1,
      modifiedCount: 1,
      upsertedCount: 0,
      upsertedId: null,
    });

    const app = buildApp();
    const res = await request(app).post("/auth/verifmail").send({
      email: userDoc.email,
      code: "ABCD",
      classId: classId.toString(),
    });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Classe.updateOne).toHaveBeenCalledTimes(1);
    expect(User.updateOne).toHaveBeenCalled();
  });

  test("POST /auth/signup/join-existing claims slot and adds follow", async () => {
    const classId = new mongoose.Types.ObjectId();
    const classeDoc = {
      _id: classId,
      students: [{ nom: "DUPONT", prenom: "elodie", free: true, id_user: null }],
    };

    Classe.findOne.mockReturnValue(makeQuery(classeDoc));
    Classe.updateOne.mockResolvedValueOnce({
      acknowledged: true,
      matchedCount: 1,
      modifiedCount: 1,
      upsertedCount: 0,
      upsertedId: null,
    });

    const userDoc = {
      _id: new mongoose.Types.ObjectId(),
      email: "elodie.dupont@test.com",
      nom: "DUPONT",
      prenom: "elodie",
      password: "hashed:Abcd!1234",
      active: true,
      isVerified: true,
      follow: [],
    };

    User.findOne.mockImplementation((query) => {
      if (query && query.email && query.active === true) return makeQuery(userDoc);
      return makeQuery(null);
    });

    const app = buildApp();
    const res = await request(app).post("/auth/signup/join-existing").send({
      classId: classId.toString(),
      nom: "Dupont",
      prenom: "Élodie",
      email: "elodie.dupont@test.com",
      password: "Abcd!1234",
    });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(User.updateOne).toHaveBeenCalled();
  });
});
