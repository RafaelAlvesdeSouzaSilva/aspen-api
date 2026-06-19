const express = require('express');
const cors = require('cors');
const { initializeApp } = require('firebase-admin/app');
const { cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================
// Inicialização do Firebase Admin
// ============================================================
// Em produção (Render), a credencial vem da variável de ambiente
// FIREBASE_SERVICE_ACCOUNT (o JSON da service account, em uma linha só).
// Como gerar: Firebase Console → Configurações do projeto →
// Contas de serviço → Gerar nova chave privada.

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

const firebaseApp = initializeApp({
  credential: cert(serviceAccount),
});

const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);

// ============================================================
// Middleware de autenticação — valida o ID token do Firebase
// ============================================================
const autenticar = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido' });
  try {
    const decoded = await auth.verifyIdToken(token);
    req.usuario = decoded; // contém uid, email, etc.
    next();
  } catch (err) {
    console.error('Token inválido:', err.message);
    res.status(401).json({ erro: 'Token inválido' });
  }
};

// ============================================================
// Rota raiz
// ============================================================
app.get('/', (req, res) => {
  res.json({ mensagem: 'API Aspen Core funcionando!' });
});

// ============================================================
// AUTH
// ============================================================

// Sincroniza o perfil no Firestore após o cadastro no Firebase Auth
app.post('/auth/sync-profile', autenticar, async (req, res) => {
  const { name } = req.body;
  const { uid, email } = req.usuario;
  try {
    const userRef = db.collection('users').doc(uid);
    const snap = await userRef.get();

    if (!snap.exists) {
      await userRef.set({
        name: name || '',
        email,
        plan: 'basico',
        plan_expires_at: null,
        plan_updated_at: null,
        created_at: new Date().toISOString(),
        last_login_at: null,
      });
    }

    res.status(201).json({ mensagem: 'Perfil sincronizado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao sincronizar perfil' });
  }
});

// Retorna o perfil do usuário logado
app.get('/auth/me', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    const snap = await db.collection('users').doc(uid).get();
    if (!snap.exists) return res.status(404).json({ erro: 'Usuário não encontrado' });

    await db.collection('users').doc(uid).update({
      last_login_at: new Date().toISOString(),
    });

    res.json({ id: uid, ...snap.data() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// Atualiza o plano do usuário
app.put('/auth/plan', autenticar, async (req, res) => {
  const { plan } = req.body;
  if (!['basico', 'padrao', 'premium'].includes(plan)) {
    return res.status(400).json({ erro: 'Plano inválido' });
  }
  try {
    const { uid } = req.usuario;
    await db.collection('users').doc(uid).update({
      plan,
      plan_updated_at: new Date().toISOString(),
    });
    res.json({ mensagem: 'Plano atualizado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// ============================================================
// DEVICES
// ============================================================

app.get('/devices', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    const snap = await db.collection('users').doc(uid).collection('devices').get();
    const devices = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    res.json(devices);
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.post('/devices', autenticar, async (req, res) => {
  const { name, type, os } = req.body;
  if (!name || !type) return res.status(400).json({ erro: 'Preencha nome e tipo do dispositivo' });
  try {
    const { uid } = req.usuario;
    const ref = await db.collection('users').doc(uid).collection('devices').add({
      name,
      type,
      os: os || null,
      status: 'ativo',
      last_access_at: null,
      created_at: new Date().toISOString(),
    });
    res.status(201).json({ id: ref.id, mensagem: 'Dispositivo adicionado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.get('/devices/:id', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    const snap = await db.collection('users').doc(uid).collection('devices').doc(req.params.id).get();
    if (!snap.exists) return res.status(404).json({ erro: 'Dispositivo não encontrado' });
    res.json({ id: snap.id, ...snap.data() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.delete('/devices/:id', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    await db.collection('users').doc(uid).collection('devices').doc(req.params.id).delete();
    res.json({ mensagem: 'Dispositivo removido com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// ============================================================
// PAYMENT METHODS
// ============================================================

app.get('/payment-methods', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    const snap = await db.collection('users').doc(uid).collection('payment_methods').get();
    const methods = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    res.json(methods);
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.post('/payment-methods/card', autenticar, async (req, res) => {
  const { card_last4, card_brand, card_expiry, card_holder, is_default, billing_day, auto_renew } = req.body;
  if (!card_last4 || !card_brand) {
    return res.status(400).json({ erro: 'Preencha os dados do cartão' });
  }
  try {
    const { uid } = req.usuario;
    const ref = await db.collection('users').doc(uid).collection('payment_methods').add({
      type: 'card',
      card_last4,
      card_brand,
      card_expiry: card_expiry || null,
      card_holder: card_holder || null,
      is_default: !!is_default,
      billing_day: billing_day || null,
      auto_renew: auto_renew !== undefined ? auto_renew : true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    res.status(201).json({ id: ref.id, mensagem: 'Cartão adicionado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.post('/payment-methods/pix', autenticar, async (req, res) => {
  const { is_default } = req.body;
  try {
    const { uid } = req.usuario;
    const ref = await db.collection('users').doc(uid).collection('payment_methods').add({
      type: 'pix',
      is_default: !!is_default,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    res.status(201).json({ id: ref.id, mensagem: 'Pix adicionado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.put('/payment-methods/:id', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    await db.collection('users').doc(uid).collection('payment_methods').doc(req.params.id).update({
      ...req.body,
      updated_at: new Date().toISOString(),
    });
    res.json({ mensagem: 'Método de pagamento atualizado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.delete('/payment-methods/:id', autenticar, async (req, res) => {
  try {
    const { uid } = req.usuario;
    await db.collection('users').doc(uid).collection('payment_methods').doc(req.params.id).delete();
    res.json({ mensagem: 'Método de pagamento removido com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// ============================================================
// CHECKOUT
// ============================================================

app.post('/payment/checkout', autenticar, async (req, res) => {
  const { plan } = req.body;
  if (!['basico', 'padrao', 'premium'].includes(plan)) {
    return res.status(400).json({ erro: 'Plano inválido' });
  }
  try {
    const { uid } = req.usuario;
    // Aqui entraria a integração real com um gateway de pagamento (Stripe, Pagar.me, etc.)
    // Por enquanto, apenas atualizamos o plano diretamente.
    await db.collection('users').doc(uid).update({
      plan,
      plan_updated_at: new Date().toISOString(),
    });
    res.json({ mensagem: 'Checkout realizado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao processar checkout' });
  }
});

// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ API Aspen Core rodando na porta ${PORT}`);
});