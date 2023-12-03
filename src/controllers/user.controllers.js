const catchError = require("../utils/catchError");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  //(1) Desestructurar el req.body
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  //(2) Tomar la password y encriptar
  const hashedPw = await bcrypt.hash(password, 10);
  //(3) Crear el payload para enviarlo al modelo con .create()
  const payload = {
    email,
    password: hashedPw,
    firstName,
    lastName,
    country,
    image,
  };
  //(4) Enviando el payload creado en el paso anterior al modelo User con el metodo .create()
  const result = await User.create(payload);
  //(5) Crear el codigo
  const code = require("crypto").randomBytes(32).toString("hex");
  //(6) crear el codigo y asociarlo con id del usuario
  await EmailCode.create({
    code: code,
    userId: result.id,
  });
  //(7) Crear el link
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;
  //(8) usar sendEmail para enviar un email al usuario con el CODIGO de verificación
  await sendEmail({
    to: email, // Email del receptor
    subject: "Este es el asunto del correo", // asunto
    html: `
        <h1>Hello ${payload.firstName} ${payload.lastName}</h1>
        <p><b>Thanks</b> for sing up in <a href=${link}>User-App-Colombia</a></p>
        <p>Please click in the follow link to verificate your account</p>
        <a href="${link}">${link}</a>
    `, // texto
  });
  //(9) el return
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  //cinfig update
  const { id } = req.params;
  const result = await User.update(req.body, {
    where: { id },
    returning: true,
  });
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCodeInstance = await EmailCode.findOne({ where: { code } });
  if (!emailCodeInstance)
    res.json({ message: "Problemas al encontrar el codigo ...." });
  const userInstance = await User.findByPk(emailCodeInstance.userId);
  userInstance.isVerified = true;
  await userInstance.save();
  await emailCodeInstance.destroy();
  return res.json(userInstance);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const userInstance = await User.findOne({ where: { email } });
  if (!userInstance) return res.json({ message: "no se encontró el usuario" });
  const verifyPw = await bcrypt.compare(password, userInstance.password);
  if (!verifyPw)
    return res.json({
      message: "Probablemente falló el cotejo de contraseñas",
    });

  if (!userInstance.isVerified) {
    return res
      .json({
        message: "¿Ya te verificaste? No puedes loguearte sin verificarte",
      })
      .status(401);
  }
  const token = jwt.sign({ userInstance }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });

  return res.json({ userInstance, token });
});

const getLoggedUser = catchError((req, res) => {
  const userInstance = req.user;
  console.log(userInstance);
  return res.json(userInstance);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser,
};
