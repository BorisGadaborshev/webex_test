const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { User, Token } = require('../db/models');

exports.registrationUser = async (req, res) => {
  console.log(req.body);

  const { login, password, email } = req.body;
  try {
    const candidate = await User.findOne({ where: { email } });
    if (candidate) {
      throw new Error(`пользователь с таким почтовым адресом ${email} уже существует`);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      login, password: hashedPassword, email
    });

    await nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      // ignoreTLS: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },

    }).sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: 'Приветственное письмо',
      text: '',
      html: `
      <div>
      <h3>Добро пожаловать ${user.login}</h3>
      </div>
      `,
    });
    const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '30m' });
    const refreshToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

    const tokenData = await Token.findOne({ where: { userId: user.id } });
    if (tokenData) {
      tokenData.refreshToken = refreshToken;
    }
    const token = await Token.create({ userId: user.id, refreshToken });
    res.cookie('refreshToken', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.json({
      login: user.login,
      id: user.id,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error(err);
    res.json('Ошибка регистрации');
  }
};

exports.authUser = async (req, res) => {
  const { login, password } = req.body;
  console.log(login, password);
  try {
    const user = await User.findOne({ where: { login } });
    // console.log(user);
    const isSame = await bcrypt.compare(password, user.password);
    if (user && isSame) {
      
      const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '30m' });
      const refreshToken = jwt.sign({ id: user.id, email: user.email}, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
      const tokenData = await Token.findOne({ where: { userId: user.id } });
      // console.log(refreshToken);
      if (tokenData) {
        tokenData.refreshToken = refreshToken;
        res.cookie('refreshToken', tokenData, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
      } else {
        const token = await Token.create({ userId: user.id, refreshToken });
        res.cookie('refreshToken', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
      }

      res.json({
        login: user.login,
        id: user.id,
        email: user.email,
        accessToken,
        refreshToken,
      });
    } else {
      res.json('Ошибка авторизации');
    }
  } catch (err) {
    console.error(err);
    res.send('Заполните поля').status(401).end();
  }
};



exports.getLogout = async (req, res) => {
  if (req.cookies.refreshToken) {
    const { refreshToken } = req.cookies.refreshToken;
    // console.log(refreshToken);
    res.clearCookie('refreshToken');
    try {
      const token = await Token.destroy({ where: { refreshToken } });
      res.json(token);
    } catch (error) {
      console.error(error);
    }
  } else {
    res.json('пользователь не найден');
  }
};

exports.getRefresh = async (req, res) => {
  try {
    if (req.cookies.refreshToken) {
      const { refreshToken } = req.cookies.refreshToken;
      console.log(req.cookies);

      if (!refreshToken) {
        throw new Error('не авторизованный пользователь');
      }
      const tokenVerify = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const tokenDB = Token.findOne({ where: { refreshToken } });
      if (!tokenVerify || !tokenDB) {
        throw new Error('не авторизованный пользователь');
      }
      const user = await User.findOne({ where: { id: req.cookies.refreshToken.id } });
      const accessToken = jwt.sign({ id: user.id, email: user.email}, process.env.JWT_ACCESS_SECRET, { expiresIn: '30m' });
      // const refreshToken = jwt.sign({ id: user.id, email: user.email}, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
      const tokenData = await Token.findOne({ where: { userId: user.id } });
      // console.log(refreshToken);
      if (tokenData) {
        tokenData.refreshToken = refreshToken;
        res.cookie('refreshToken', tokenData, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
      } else {
        const token = await Token.create({ userId: user.id, refreshToken });
        res.cookie('refreshToken', token, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
      }

      res.json({
        login: user.login,
        id: user.id,
        email: user.email,
        accessToken,
        refreshToken,
      });
    }
  } catch (error) {
    console.error(error);
  }
};