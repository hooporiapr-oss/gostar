const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new Database(process.env.DATABASE_PATH || './data/gostar.db');

// Initialize database tables
db.exec(`
    CREATE TABLE IF NOT EXISTS facilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        license_tier TEXT DEFAULT 'trial',
        resident_count INTEGER DEFAULT 0,
        license_start DATE,
        license_end DATE,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        facility_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'staff',
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (facility_id) REFERENCES facilities(id)
    );
    
    CREATE TABLE IF NOT EXISTS sessions_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        facility_id INTEGER,
        staff_id INTEGER,
        game_type TEXT,
        score INTEGER,
        difficulty TEXT,
        mode TEXT,
        played_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM admin_users WHERE email = ?').get('admin@gostardigital.com');
if (!adminExists) {
    const hashedPassword = bcrypt.hashSync('GoStar2025!', 10);
    db.prepare('INSERT INTO admin_users (email, password, name) VALUES (?, ?, ?)').run(
        'admin@gostardigital.com',
        hashedPassword,
        'GoStar Admin'
    );
    console.log('Default admin created: admin@gostardigital.com / GoStar2025!');
}

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        },
    },
}));
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'gostar-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Static files (public pages only)
app.use('/css', express.static(path.join(__dirname, 'public/css')));
app.use('/js', express.static(path.join(__dirname, 'public/js')));
app.use('/images', express.static(path.join(__dirname, 'public/images')));

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.user) {
        // Check license expiration for facility users
        if (req.session.user.type === 'facility' || req.session.user.type === 'staff') {
            const facility = db.prepare('SELECT * FROM facilities WHERE id = ?').get(req.session.user.facilityId);
            if (!facility || !facility.is_active) {
                req.session.destroy();
                return res.redirect('/login?error=inactive');
            }
            if (facility.license_end && new Date(facility.license_end) < new Date()) {
                return res.redirect('/login?error=expired');
            }
        }
        return next();
    }
    res.redirect('/login');
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.type === 'admin') {
        return next();
    }
    res.redirect('/admin/login');
}

// ============ PUBLIC ROUTES ============

// Homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

// About page
app.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/about.html'));
});

// Privacy & Terms
app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/privacy.html'));
});

app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/terms.html'));
});

// Login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/login.html'));
});

// ============ AUTH ROUTES ============

// Login POST
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Check facilities first
    const facility = db.prepare('SELECT * FROM facilities WHERE email = ?').get(email);
    if (facility && bcrypt.compareSync(password, facility.password)) {
        if (!facility.is_active) {
            return res.status(403).json({ error: 'Account is inactive. Contact support.' });
        }
        if (facility.license_end && new Date(facility.license_end) < new Date()) {
            return res.status(403).json({ error: 'License expired. Please renew.' });
        }
        
        req.session.user = {
            type: 'facility',
            id: facility.id,
            facilityId: facility.id,
            name: facility.name,
            email: facility.email,
            licenseTier: facility.license_tier
        };
        return res.json({ success: true, redirect: '/play' });
    }
    
    // Check staff
    const staff = db.prepare(`
        SELECT s.*, f.name as facility_name, f.is_active as facility_active, f.license_end 
        FROM staff s 
        JOIN facilities f ON s.facility_id = f.id 
        WHERE s.email = ?
    `).get(email);
    
    if (staff && bcrypt.compareSync(password, staff.password)) {
        if (!staff.is_active || !staff.facility_active) {
            return res.status(403).json({ error: 'Account is inactive. Contact your administrator.' });
        }
        if (staff.license_end && new Date(staff.license_end) < new Date()) {
            return res.status(403).json({ error: 'Facility license expired.' });
        }
        
        req.session.user = {
            type: 'staff',
            id: staff.id,
            facilityId: staff.facility_id,
            facilityName: staff.facility_name,
            name: staff.name,
            email: staff.email,
            role: staff.role
        };
        return res.json({ success: true, redirect: '/play' });
    }
    
    return res.status(401).json({ error: 'Invalid email or password' });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// ============ PROTECTED ROUTES ============

// Game page (protected)
app.get('/play', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views/sequence-memory.html'));
});

app.get('/sequence-memory', requireAuth, (req, res) => {
    res.redirect('/play');
});

// Get current user info
app.get('/api/me', requireAuth, (req, res) => {
    res.json({ user: req.session.user });
});

// Log game session
app.post('/api/log-session', requireAuth, (req, res) => {
    const { gameType, score, difficulty, mode } = req.body;
    
    db.prepare(`
        INSERT INTO sessions_log (facility_id, staff_id, game_type, score, difficulty, mode)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        req.session.user.facilityId,
        req.session.user.type === 'staff' ? req.session.user.id : null,
        gameType || 'sequence-memory',
        score,
        difficulty,
        mode
    );
    
    res.json({ success: true });
});

// ============ ADMIN ROUTES ============

app.get('/admin', (req, res) => {
    res.redirect('/admin/login');
});

app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin-login.html'));
});

app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    
    const admin = db.prepare('SELECT * FROM admin_users WHERE email = ?').get(email);
    if (admin && bcrypt.compareSync(password, admin.password)) {
        req.session.user = {
            type: 'admin',
            id: admin.id,
            name: admin.name,
            email: admin.email
        };
        return res.json({ success: true, redirect: '/admin/dashboard' });
    }
    
    return res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/admin/dashboard', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views/admin-dashboard.html'));
});

// Admin API - Get all facilities
app.get('/api/admin/facilities', requireAdmin, (req, res) => {
    const facilities = db.prepare(`
        SELECT id, name, email, license_tier, resident_count, license_start, license_end, is_active, created_at
        FROM facilities ORDER BY created_at DESC
    `).all();
    res.json({ facilities });
});

// Admin API - Create facility
app.post('/api/admin/facilities', requireAdmin, (req, res) => {
    const { name, email, password, licenseTier, residentCount, licenseEnd } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Name, email, and password required' });
    }
    
    const existing = db.prepare('SELECT id FROM facilities WHERE email = ?').get(email);
    if (existing) {
        return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
        INSERT INTO facilities (name, email, password, license_tier, resident_count, license_start, license_end)
        VALUES (?, ?, ?, ?, ?, DATE('now'), ?)
    `).run(name, email, hashedPassword, licenseTier || 'trial', residentCount || 0, licenseEnd || null);
    
    res.json({ success: true, id: result.lastInsertRowid });
});

// Admin API - Update facility
app.put('/api/admin/facilities/:id', requireAdmin, (req, res) => {
    const { name, licenseTier, residentCount, licenseEnd, isActive } = req.body;
    
    db.prepare(`
        UPDATE facilities 
        SET name = COALESCE(?, name),
            license_tier = COALESCE(?, license_tier),
            resident_count = COALESCE(?, resident_count),
            license_end = COALESCE(?, license_end),
            is_active = COALESCE(?, is_active)
        WHERE id = ?
    `).run(name, licenseTier, residentCount, licenseEnd, isActive, req.params.id);
    
    res.json({ success: true });
});

// Admin API - Delete facility
app.delete('/api/admin/facilities/:id', requireAdmin, (req, res) => {
    db.prepare('DELETE FROM staff WHERE facility_id = ?').run(req.params.id);
    db.prepare('DELETE FROM facilities WHERE id = ?').run(req.params.id);
    res.json({ success: true });
});

// Admin API - Get usage stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const totalFacilities = db.prepare('SELECT COUNT(*) as count FROM facilities').get().count;
    const activeFacilities = db.prepare('SELECT COUNT(*) as count FROM facilities WHERE is_active = 1').get().count;
    const totalSessions = db.prepare('SELECT COUNT(*) as count FROM sessions_log').get().count;
    const todaySessions = db.prepare(`
        SELECT COUNT(*) as count FROM sessions_log 
        WHERE DATE(played_at) = DATE('now')
    `).get().count;
    
    res.json({
        totalFacilities,
        activeFacilities,
        totalSessions,
        todaySessions
    });
});

// ============ ERROR HANDLING ============

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public/404.html'));
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// ============ START SERVER ============

// Create data directory if not exists
const fs = require('fs');
if (!fs.existsSync('./data')) {
    fs.mkdirSync('./data', { recursive: true });
}

app.listen(PORT, () => {
    console.log(`⭐ GoStar Digital running on port ${PORT}`);
    console.log(`   http://localhost:${PORT}`);
});
