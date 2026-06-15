const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Configuração do e-mail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const autenticar = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try {
    const dados = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = dados;
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
};

app.get('/', (req, res) => {
  res.json({ mensagem: 'API Aspen Core funcionando!' });
});

// Cadastro
app.post('/auth/cadastro', async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha)
    return res.status(400).json({ erro: 'Preencha todos os campos' });
  if (senha.length < 8)
    return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres' });
  try {
    const [existe] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existe.length > 0)
      return res.status(409).json({ erro: 'E-mail já cadastrado' });
    const senhaCriptografada = await bcrypt.hash(senha, 10);
    const [resultado] = await db.query(
      'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
      [nome, email, senhaCriptografada]
    );
    const token = jwt.sign(
      { id: resultado.insertId, email, nome },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({
      mensagem: 'Conta criada com sucesso!',
      token,
      usuario: { id: resultado.insertId, nome, email, plano: 'basico' },
    });
  } catch (err) {
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha)
    return res.status(400).json({ erro: 'Preencha todos os campos' });
  try {
    const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (usuarios.length === 0)
      return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const usuario = usuarios[0];
    const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
    if (!senhaCorreta)
      return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, nome: usuario.nome },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      mensagem: 'Login realizado com sucesso!',
      token,
      usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, plano: usuario.plano },
    });
  } catch (err) {
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// Perfil
app.get('/usuario/perfil', autenticar, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, nome, email, plano, criado_em FROM usuarios WHERE id = ?',
      [req.usuario.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    res.json(rows[0]);
  } catch {
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// Solicitar recuperação de senha
app.post('/auth/esqueci-senha', async (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ erro: 'Informe o e-mail' });
  try {
    const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    // Sempre retorna sucesso para não revelar se o e-mail existe
    if (usuarios.length === 0)
      return res.json({ mensagem: 'Se este e-mail estiver cadastrado, você receberá as instruções.' });

    const usuario = usuarios[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expira = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

    // Remove tokens antigos do usuário
    await db.query('DELETE FROM recuperacao_senha WHERE usuario_id = ?', [usuario.id]);

    // Salva novo token
    await db.query(
      'INSERT INTO recuperacao_senha (usuario_id, token, expira_em) VALUES (?, ?, ?)',
      [usuario.id, token, expira]
    );

    // Envia e-mail
    await transporter.sendMail({
      from: `"Aspen Core" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Recuperação de senha — Aspen Core',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
          <div style="background: #0b6b6b; padding: 24px; border-radius: 12px 12px 0 0;">
            <h2 style="color: white; margin: 0;">🔐 Aspen Core</h2>
            <p style="color: rgba(255,255,255,0.8); margin: 4px 0 0;">Segurança Digital</p>
          </div>
          <div style="background: #f8fafc; padding: 32px; border-radius: 0 0 12px 12px; border: 1px solid #e2e8f0;">
            <h3 style="color: #0f172a;">Olá, ${usuario.nome}!</h3>
            <p style="color: #64748b;">Recebemos uma solicitação para redefinir a senha da sua conta.</p>
            <p style="color: #64748b;">Seu código de recuperação é:</p>
            <div style="background: #0b6b6b; color: white; font-size: 32px; font-weight: bold; text-align: center; padding: 20px; border-radius: 10px; letter-spacing: 8px; margin: 20px 0;">
              ${token.substring(0, 6).toUpperCase()}
            </div>
            <p style="color: #94a3b8; font-size: 13px;">Este código expira em <strong>1 hora</strong>.</p>
            <p style="color: #94a3b8; font-size: 13px;">Se você não solicitou isso, ignore este e-mail.</p>
          </div>
        </div>
      `,
    });

    res.json({ mensagem: 'Se este e-mail estiver cadastrado, você receberá as instruções.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao enviar e-mail' });
  }
});

// Verificar código e redefinir senha
app.post('/auth/redefinir-senha', async (req, res) => {
  const { email, codigo, novaSenha } = req.body;
  if (!email || !codigo || !novaSenha)
    return res.status(400).json({ erro: 'Preencha todos os campos' });
  if (novaSenha.length < 8)
    return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres' });
  try {
    const [usuarios] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (usuarios.length === 0)
      return res.status(404).json({ erro: 'E-mail não encontrado' });

    const usuario = usuarios[0];

    const [tokens] = await db.query(
      `SELECT * FROM recuperacao_senha 
       WHERE usuario_id = ? AND usado = FALSE AND expira_em > NOW()
       ORDER BY id DESC LIMIT 1`,
      [usuario.id]
    );

    if (tokens.length === 0)
      return res.status(400).json({ erro: 'Código inválido ou expirado' });

    const tokenSalvo = tokens[0].token.substring(0, 6).toUpperCase();
    if (codigo.toUpperCase() !== tokenSalvo)
      return res.status(400).json({ erro: 'Código incorreto' });

    const senhaCriptografada = await bcrypt.hash(novaSenha, 10);
    await db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaCriptografada, usuario.id]);
    await db.query('UPDATE recuperacao_senha SET usado = TRUE WHERE usuario_id = ?', [usuario.id]);

    res.json({ mensagem: 'Senha redefinida com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ API Aspen Core rodando em http://localhost:${PORT}`);
});