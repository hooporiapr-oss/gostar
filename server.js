const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
let db;
const DB_PATH = process.env.DATABASE_PATH || './data/gostar.db';

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Save database to file
function saveDatabase() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_PATH, buffer);
    }
}

// Initialize database
async function initDatabase() {
    console.log('Initializing database...');
    console.log('DB_PATH:', DB_PATH);
    
    const SQL = await initSqlJs();
    
    // Load existing database or create new one
    if (fs.existsSync(DB_PATH)) {
        console.log('Loading existing database from:', DB_PATH);
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
        console.log('Database loaded from file');
    } else {
        console.log('Creating new database');
        db = new SQL.Database();
        console.log('New database created');
    }
    
    // Initialize tables
    console.log('Creating tables...');
    
    db.run(`
        CREATE TABLE IF NOT EXISTS facilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            license_tier TEXT DEFAULT 'trial',
            resident_count INTEGER DEFAULT 0,
            license_start TEXT,
            license_end TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            facility_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'staff',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (facility_id) REFERENCES facilities(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            facility_id INTEGER,
            staff_id INTEGER,
            game_type TEXT,
            score INTEGER,
            difficulty TEXT,
            mode TEXT,
            played_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    console.log('Tables created');
    
    // Create default admin if not exists
    try {
        const adminCheck = db.exec("SELECT id FROM admin_users WHERE email = 'admin@gostardigital.com'");
        console.log('Admin check result:', JSON.stringify(adminCheck));
        
        if (adminCheck.length === 0 || adminCheck[0].values.length === 0) {
            console.log('Creating default admin...');
            const hashedPassword = bcrypt.hashSync('GoStar2025!', 10);
            db.run("INSERT INTO admin_users (email, password, name) VALUES (?, ?, ?)", 
                ['admin@gostardigital.com', hashedPassword, 'GoStar Admin']);
            console.log('Default admin created: admin@gostardigital.com / GoStar2025!');
        } else {
            console.log('Admin already exists');
        }
    } catch (err) {
        console.error('Error checking/creating admin:', err);
    }
    
    saveDatabase();
    console.log('Database saved to disk');
    console.log('Database initialization complete');
}

// Helper functions for database queries
function dbGet(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        if (stmt.step()) {
            const row = stmt.getAsObject();
            stmt.free();
            return row;
        }
        stmt.free();
        return null;
    } catch (err) {
        console.error('dbGet error:', err, 'SQL:', sql);
        throw err;
    }
}

function dbAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const results = [];
        while (stmt.step()) {
            results.push(stmt.getAsObject());
        }
        stmt.free();
        return results;
    } catch (err) {
        console.error('dbAll error:', err, 'SQL:', sql);
        throw err;
    }
}

function dbRun(sql, params = []) {
    try {
        db.run(sql, params);
        saveDatabase();
        return { lastInsertRowid: db.exec("SELECT last_insert_rowid()")[0]?.values[0]?.[0] };
    } catch (err) {
        console.error('dbRun error:', err, 'SQL:', sql);
        throw err;
    }
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

// Trust proxy for Render
app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET || 'gostar-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
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
            const facility = dbGet('SELECT * FROM facilities WHERE id = ?', [req.session.user.facilityId]);
            if (!facility || !facility.is_active) {
                req.session.destroy(() => {});
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
    const facility = dbGet('SELECT * FROM facilities WHERE email = ?', [email]);
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
    const staff = dbGet(`
        SELECT s.*, f.name as facility_name, f.is_active as facility_active, f.license_end 
        FROM staff s 
        JOIN facilities f ON s.facility_id = f.id 
        WHERE s.email = ?
    `, [email]);
    
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
    req.session.destroy(() => {});
    res.redirect('/');
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {});
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
    
    dbRun(`
        INSERT INTO sessions_log (facility_id, staff_id, game_type, score, difficulty, mode)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [
        req.session.user.facilityId,
        req.session.user.type === 'staff' ? req.session.user.id : null,
        gameType || 'sequence-memory',
        score,
        difficulty,
        mode
    ]);
    
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
    try {
        const { email, password } = req.body;
        
        console.log('Admin login attempt:', email);
        
        const admin = dbGet('SELECT * FROM admin_users WHERE email = ?', [email]);
        console.log('Admin found:', admin ? 'yes' : 'no');
        
        if (admin && bcrypt.compareSync(password, admin.password)) {
            req.session.user = {
                type: 'admin',
                id: admin.id,
                name: admin.name,
                email: admin.email
            };
            console.log('Admin login successful');
            return res.json({ success: true, redirect: '/admin/dashboard' });
        }
        
        console.log('Admin login failed - invalid credentials');
        return res.status(401).json({ error: 'Invalid credentials' });
    } catch (err) {
        console.error('Admin login error:', err);
        return res.status(500).json({ error: 'Login error: ' + err.message });
    }
});

app.get('/admin/dashboard', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views/admin-dashboard.html'));
});

// Admin API - Get all facilities
app.get('/api/admin/facilities', requireAdmin, (req, res) => {
    const facilities = dbAll(`
        SELECT id, name, email, license_tier, resident_count, license_start, license_end, is_active, created_at
        FROM facilities ORDER BY created_at DESC
    `);
    res.json({ facilities });
});

// Admin API - Create facility
app.post('/api/admin/facilities', requireAdmin, (req, res) => {
    const { name, email, password, licenseTier, residentCount, licenseEnd } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Name, email, and password required' });
    }
    
    const existing = dbGet('SELECT id FROM facilities WHERE email = ?', [email]);
    if (existing) {
        return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = dbRun(`
        INSERT INTO facilities (name, email, password, license_tier, resident_count, license_start, license_end)
        VALUES (?, ?, ?, ?, ?, DATE('now'), ?)
    `, [name, email, hashedPassword, licenseTier || 'trial', residentCount || 0, licenseEnd || null]);
    
    res.json({ success: true, id: result.lastInsertRowid });
});

// Admin API - Update facility
app.put('/api/admin/facilities/:id', requireAdmin, (req, res) => {
    const { name, licenseTier, residentCount, licenseEnd, isActive } = req.body;
    const id = req.params.id;
    
    // Build update query dynamically
    const updates = [];
    const params = [];
    
    if (name !== undefined) { updates.push('name = ?'); params.push(name); }
    if (licenseTier !== undefined) { updates.push('license_tier = ?'); params.push(licenseTier); }
    if (residentCount !== undefined) { updates.push('resident_count = ?'); params.push(residentCount); }
    if (licenseEnd !== undefined) { updates.push('license_end = ?'); params.push(licenseEnd); }
    if (isActive !== undefined) { updates.push('is_active = ?'); params.push(isActive); }
    
    if (updates.length > 0) {
        params.push(id);
        dbRun(`UPDATE facilities SET ${updates.join(', ')} WHERE id = ?`, params);
    }
    
    res.json({ success: true });
});

// Admin API - Delete facility
app.delete('/api/admin/facilities/:id', requireAdmin, (req, res) => {
    dbRun('DELETE FROM staff WHERE facility_id = ?', [req.params.id]);
    dbRun('DELETE FROM facilities WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

// Admin API - Get usage stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const totalFacilities = dbGet('SELECT COUNT(*) as count FROM facilities')?.count || 0;
    const activeFacilities = dbGet('SELECT COUNT(*) as count FROM facilities WHERE is_active = 1')?.count || 0;
    const totalSessions = dbGet('SELECT COUNT(*) as count FROM sessions_log')?.count || 0;
    const todaySessions = dbGet(`
        SELECT COUNT(*) as count FROM sessions_log 
        WHERE DATE(played_at) = DATE('now')
    `)?.count || 0;
    
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

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`⭐ GoStar Digital running on port ${PORT}`);
        console.log(`   http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
