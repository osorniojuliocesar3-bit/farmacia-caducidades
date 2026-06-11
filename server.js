require('dotenv').config();

const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const XLSX     = require('xlsx');
const path     = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app    = express();
const PORT   = process.env.PORT || 3000;
const MONGO  = process.env.MONGODB_URI || 'mongodb://localhost:27017/farmacia';
const SECRET = process.env.SESSION_SECRET || 'farmacia-secret-2024';

// ── MongoDB ──────────────────────────────────────────────────────
let db;
async function connectDB() {
  const client = new MongoClient(MONGO);
  await client.connect();
  db = client.db();
  console.log('  🗄️   MongoDB conectado.');

  // Índices
  await db.collection('productos').createIndex({ nombre: 1 });
  await db.collection('productos').createIndex({ fecha_caducidad: 1 });
  await db.collection('usuarios').createIndex({ usuario: 1 }, { unique: true });

  // Admin por defecto
  const count = await db.collection('usuarios').countDocuments();
  if (count === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await db.collection('usuarios').insertOne({
      usuario:   'admin',
      nombre:    'Administrador',
      password:  hash,
      rol:       'admin',
      creado_en: new Date().toLocaleString('es-MX'),
    });
    console.log('  👤  Usuario por defecto creado: admin / admin123');
    console.log('  ⚠️   Cambia la contraseña después de iniciar sesión.');
  }
}

// ── Helpers ──────────────────────────────────────────────────────
function daysUntil(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d)) return null;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.floor((d - today) / 86400000);
}

function withDays(p) {
  const { _id, ...rest } = p;
  return { ...rest, id: _id.toString(), dias: daysUntil(p.fecha_caducidad) };
}

function statusOf(dias) {
  if (dias === null) return 'ok';
  if (dias < 0)   return 'expired';
  if (dias <= 30)  return 'critical';
  if (dias <= 90)  return 'warning';
  return 'ok';
}

function buildQuery(q) {
  if (!q) return {};
  const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  return { $or: [{ nombre: re }, { codigo: re }, { notas: re }] };
}

// ── Middleware ────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));

const upload = multer({ storage: multer.memoryStorage() });

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: 'No autenticado.' });
}
function requireAdmin(req, res, next) {
  if (req.session?.rol === 'admin') return next();
  res.status(403).json({ error: 'Se requieren permisos de administrador.' });
}

// ── Auth ─────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });

  const user = await db.collection('usuarios')
    .findOne({ usuario: new RegExp(`^${usuario}$`, 'i') });
  if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });

  req.session.userId  = user._id.toString();
  req.session.usuario = user.usuario;
  req.session.nombre  = user.nombre;
  req.session.rol     = user.rol;
  res.json({ ok: true, nombre: user.nombre, usuario: user.usuario, rol: user.rol });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ autenticado: false });
  res.json({ autenticado: true, usuario: req.session.usuario, nombre: req.session.nombre, rol: req.session.rol });
});

// ── Usuarios ─────────────────────────────────────────────────────
app.get('/api/usuarios', requireAuth, requireAdmin, async (req, res) => {
  const users = await db.collection('usuarios')
    .find({}, { projection: { password: 0 } }).toArray();
  res.json(users.map(u => ({ ...u, id: u._id.toString() })));
});

app.post('/api/usuarios', requireAuth, requireAdmin, async (req, res) => {
  const { usuario, nombre, password, rol } = req.body;
  if (!usuario || !password || !nombre)
    return res.status(400).json({ error: 'Usuario, nombre y contraseña son obligatorios.' });

  const existe = await db.collection('usuarios')
    .findOne({ usuario: new RegExp(`^${usuario}$`, 'i') });
  if (existe) return res.status(400).json({ error: 'El nombre de usuario ya existe.' });

  const hash  = await bcrypt.hash(password, 10);
  const nuevo = {
    usuario: usuario.trim(),
    nombre:  nombre.trim(),
    password: hash,
    rol: rol === 'admin' ? 'admin' : 'usuario',
    creado_en: new Date().toLocaleString('es-MX'),
  };
  const result = await db.collection('usuarios').insertOne(nuevo);
  res.json({ ...nuevo, id: result.insertedId.toString(), password: undefined });
});

app.put('/api/usuarios/:id/password', requireAuth, async (req, res) => {
  const id = req.params.id;
  const { password_actual, password_nuevo } = req.body;

  if (req.session.rol !== 'admin' && req.session.userId !== id)
    return res.status(403).json({ error: 'Sin permisos.' });
  if (!password_nuevo || password_nuevo.length < 4)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres.' });

  const user = await db.collection('usuarios').findOne({ _id: new ObjectId(id) });
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

  if (req.session.rol !== 'admin') {
    const match = await bcrypt.compare(password_actual || '', user.password);
    if (!match) return res.status(401).json({ error: 'Contraseña actual incorrecta.' });
  }

  await db.collection('usuarios').updateOne(
    { _id: new ObjectId(id) },
    { $set: { password: await bcrypt.hash(password_nuevo, 10) } }
  );
  res.json({ ok: true });
});

app.delete('/api/usuarios/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (id === req.session.userId)
    return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta.' });
  await db.collection('usuarios').deleteOne({ _id: new ObjectId(id) });
  res.json({ ok: true });
});

// ── Productos ─────────────────────────────────────────────────────
app.get('/api/productos', requireAuth, async (req, res) => {
  const { q = '', status = 'all' } = req.query;
  let rows = await db.collection('productos')
    .find(buildQuery(q))
    .sort({ fecha_caducidad: 1 })
    .toArray();

  rows = rows.map(withDays);
  if (status !== 'all') rows = rows.filter(p => statusOf(p.dias) === status);
  res.json(rows);
});

app.get('/api/resumen', requireAuth, async (req, res) => {
  const todos = await db.collection('productos').find({}).toArray();
  const counts = { expired: 0, critical: 0, warning: 0, ok: 0, total: todos.length };
  todos.forEach(p => { counts[statusOf(daysUntil(p.fecha_caducidad))]++; });
  res.json(counts);
});

app.post('/api/productos', requireAuth, async (req, res) => {
  const { codigo, nombre, fecha_caducidad, cantidad, notas } = req.body;
  if (!nombre) return res.status(400).json({ error: 'El nombre es obligatorio.' });

  const nuevo = {
    codigo:          codigo || '',
    nombre,
    fecha_caducidad: fecha_caducidad || '',
    cantidad:        cantidad != null ? Number(cantidad) : null,
    notas:           notas || '',
    registrado_por:  req.session.usuario,
    creado_en:       new Date().toLocaleString('es-MX'),
  };
  const result = await db.collection('productos').insertOne(nuevo);
  res.json(withDays({ ...nuevo, _id: result.insertedId }));
});

app.put('/api/productos/:id', requireAuth, async (req, res) => {
  const { codigo, nombre, fecha_caducidad, cantidad, notas } = req.body;
  if (!nombre) return res.status(400).json({ error: 'El nombre es obligatorio.' });

  const update = {
    codigo: codigo || '',
    nombre,
    fecha_caducidad: fecha_caducidad || '',
    cantidad: cantidad != null ? Number(cantidad) : null,
    notas: notas || '',
    actualizado_por: req.session.usuario,
    actualizado_en:  new Date().toLocaleString('es-MX'),
  };
  await db.collection('productos').updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: update }
  );
  const updated = await db.collection('productos').findOne({ _id: new ObjectId(req.params.id) });
  if (!updated) return res.status(404).json({ error: 'No encontrado.' });
  res.json(withDays(updated));
});

app.delete('/api/productos/:id', requireAuth, async (req, res) => {
  await db.collection('productos').deleteOne({ _id: new ObjectId(req.params.id) });
  res.json({ ok: true });
});

app.post('/api/productos/eliminar-lote', requireAuth, async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || !ids.length)
    return res.status(400).json({ error: 'Lista vacía.' });
  const objectIds = ids.map(id => new ObjectId(id));
  const result = await db.collection('productos').deleteMany({ _id: { $in: objectIds } });
  res.json({ ok: true, eliminados: result.deletedCount });
});

// ── Importar Excel ────────────────────────────────────────────────
app.post('/api/importar', requireAuth, upload.single('archivo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No se recibió archivo.' });

  const ALIASES = {
    nombre:          ['nombre','producto','medicamento','description','descripcion','name'],
    codigo:          ['codigo','code','sku','clave','ref','referencia'],
    fecha_caducidad: ['fecha caducidad','fecha_caducidad','caducidad','expiracion','expiry','expiration','vencimiento','fecha vencimiento','exp date'],
    cantidad:        ['cantidad','stock','qty','existencia','existencias','units'],
    notas:           ['notas','nota','presentacion','presentación','obs','observaciones'],
  };

  function guessCol(headers, field) {
    const norm = h => h.toString().toLowerCase().trim().replace(/[^a-záéíóúñü ]/g, '');
    for (const alias of ALIASES[field]) {
      const idx = headers.findIndex(h => norm(h) === alias);
      if (idx >= 0) return idx;
    }
    return -1;
  }

  function parseExcelDate(val) {
    if (!val) return '';
    if (val instanceof Date) {
      return `${val.getFullYear()}-${String(val.getMonth()+1).padStart(2,'0')}-${String(val.getDate()).padStart(2,'0')}`;
    }
    if (typeof val === 'number') {
      const d = XLSX.SSF.parse_date_code(val);
      if (d) return `${d.y}-${String(d.m).padStart(2,'0')}-${String(d.d).padStart(2,'0')}`;
    }
    const str = val.toString().trim();
    const m1 = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
    if (m1) return `${m1[3]}-${m1[2].padStart(2,'0')}-${m1[1].padStart(2,'0')}`;
    const m2 = str.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (m2) return m2[0];
    const m3 = str.match(/^(\d{1,2})[\/\-](\d{4})$/);
    if (m3) return `${m3[2]}-${m3[1].padStart(2,'0')}-01`;
    return str;
  }

  try {
    const wb   = XLSX.read(req.file.buffer, { type: 'buffer', cellDates: true });
    const ws   = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
    if (rows.length < 2) return res.status(400).json({ error: 'El archivo está vacío.' });

    const headers = rows[0].map(h => (h || '').toString());
    const colMap  = {};
    for (const field of Object.keys(ALIASES)) colMap[field] = guessCol(headers, field);
    if (colMap.nombre < 0) colMap.nombre = 0;

    const docs = [];
    let skipped = 0;
    for (let i = 1; i < rows.length; i++) {
      const row    = rows[i];
      const nombre = colMap.nombre >= 0 ? (row[colMap.nombre] || '').toString().trim() : '';
      if (!nombre) { skipped++; continue; }
      docs.push({
        codigo:          colMap.codigo   >= 0 ? (row[colMap.codigo]   || '').toString().trim() : '',
        nombre,
        fecha_caducidad: parseExcelDate(colMap.fecha_caducidad >= 0 ? row[colMap.fecha_caducidad] : '') || '',
        cantidad:        colMap.cantidad >= 0 && row[colMap.cantidad] !== '' ? Number(row[colMap.cantidad]) : null,
        notas:           colMap.notas    >= 0 ? (row[colMap.notas]    || '').toString().trim() : '',
        registrado_por:  req.session.usuario,
        creado_en:       new Date().toLocaleString('es-MX'),
      });
    }

    if (docs.length > 0) await db.collection('productos').insertMany(docs);
    res.json({ imported: docs.length, skipped });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al procesar el archivo.' });
  }
});

// ── Exportar Excel ────────────────────────────────────────────────
app.get('/api/exportar', requireAuth, async (req, res) => {
  const todos = await db.collection('productos')
    .find({}).sort({ fecha_caducidad: 1 }).toArray();

  const statusLabel = d => {
    if (d === null) return 'Sin fecha';
    if (d < 0)   return 'Caducado';
    if (d <= 30)  return 'Crítico';
    if (d <= 90)  return 'Próximo';
    return 'OK';
  };

  const data = todos.map(p => {
    const dias = daysUntil(p.fecha_caducidad);
    return {
      'Código':          p.codigo || '',
      'Nombre':          p.nombre,
      'Fecha Caducidad': p.fecha_caducidad || '',
      'Días Restantes':  dias ?? '',
      'Estado':          statusLabel(dias),
      'Cantidad':        p.cantidad ?? '',
      'Notas':           p.notas || '',
      'Registrado por':  p.registrado_por || '',
      'Fecha registro':  p.creado_en || '',
    };
  });

  const ws  = XLSX.utils.json_to_sheet(data);
  const wb2 = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb2, ws, 'Caducidades');
  const buf      = XLSX.write(wb2, { type: 'buffer', bookType: 'xlsx' });
  const filename = `caducidades_${new Date().toISOString().slice(0,10)}.xlsx`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

// ── Estáticos + SPA ───────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Arranque ──────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('  ✅  Farmacia — Control de Caducidades');
    console.log(`  🌐  Local: http://localhost:${PORT}`);
    const { networkInterfaces } = require('os');
    for (const nets of Object.values(networkInterfaces())) {
      for (const net of nets) {
        if (net.family === 'IPv4' && !net.internal)
          console.log(`  📱  Red local: http://${net.address}:${PORT}`);
      }
    }
    console.log('');
  });
}).catch(err => {
  console.error('❌ Error conectando a MongoDB:', err.message);
  process.exit(1);
});
