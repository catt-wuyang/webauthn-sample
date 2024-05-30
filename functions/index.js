const functions = require("firebase-functions");
const express = require("express");
const crypto = require("crypto");
const cbor = require("cbor");
const base64url = require("base64url");
const cors = require("cors");

const app = express();
let originalChallenge = null;
let uuid = "FqrvpNoeZ2MahNsAex6dEogzNY1Zur27y9V1TF0aeDA";
let publicKey =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk6CXI1pMVI5LSkHrGN_Glm9zjMsWUjSnAaFFtKyib-yx-NUzLv_zuXGZ98gX8uXZwpBWSduR7bGfRRbh9JrNpg";

app.use(
  cors({
    origin: ["http://localhost:5173"],
  }),
  express.json()
);

app.post("/generate-registration-challenge", (req, res) => {
  const userQuery = req.body;

  // https://stackoverflow.com/questions/56373349/why-replace-the-challenge-by-webauthn
  // webauthn use base64url generate challenge
  const challengeBuffer = crypto.randomBytes(32);
  originalChallenge = challengeBuffer;

  const challenge = base64url(challengeBuffer);
  const userId = base64url(Buffer.from(userQuery.user_id));

  const credentialCreationOptions = {
    challenge,
    rp: {
      name: "Identity Verification Sample",
    },
    user: {
      id: userId,
      name: "user_demo",
      displayName: "User Demo",
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7,
      },
      {
        type: "public-key",
        alg: -257,
      },
    ],
    attestation: "direct",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
    },
    timeout: 60000,
  };

  res.status(200).send(credentialCreationOptions);
});

app.post("/register", (req, res) => {
  try {
    const credential = req.body;

    // includes challenge
    const clientData = JSON.parse(base64url.decode(credential.clientData));

    // 验证挑战
    if (
      !Buffer.from(clientData.challenge, "base64").equals(originalChallenge)
    ) {
      return res
        .status(400)
        .send({ code: 400, message: "Challenge does not match" });
    }

    // 唯一标识，用于之后找到用户设备的私钥
    uuid = credential.id;
    // 注册时存储 publicKey 到数据库
    publicKey = credential.publicKey;

    // 并绑定当前用户设备和 userId
    // savePublicKeyToDB(id, publicKey)

    res.status(200).json({ code: 200, message: "Registration successfully" });
  } catch (error) {
    console.error("Internal server error", error);
    res.status(500).json({ code: 500, message: "Internal server error" });
  }
});

app.post("/generate-authentication-challenge", (req, res) => {
  const userId = req.body.user_id;

  // 验证 userId 是否已注册过
  // const user = findUserById(userId)
  // const user = {};

  // if (!user) {
  //   return res.status(400).send("User not found");
  // }

  const challenge = base64url(crypto.randomBytes(32));

  const authChallenge = {
    challenge: challenge,
    allowCredentials: [
      {
        type: "public-key",
        id: uuid, // navigator.credentials.create result id 唯一标识
      },
    ],
    userVerification: "required",
    timeout: 60000,
  };

  // 存储挑战，用户设备返回结果验证挑战
  // saveChallengeForUser(userId, challenge)

  res.status(200).json(authChallenge);
});

app.listen("4001", () => {
  console.log(`http://localhost:4001`);
});

exports.generateWebauthn = functions.https.onRequest(app);
