import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import cookieParser from 'cookie-parser';
import path from 'path'; 
import { fileURLToPath } from 'url';

// --- ESM path Fix ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Setup ---
dotenv.config();
const app = express();
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    console.error("🚨 Missing Supabase Environment Variables!");
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);


// --- Middleware ---
app.use(cors({
    origin: [
        'http://127.0.0.1:5500', 
        'http://localhost:5500', 
        'https://brkn-store.vercel.app' 
    ], 
    credentials: true 
}));

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// --- Serve Static Files ---

app.use(express.static(path.join(__dirname, '..')));

// --- Frontend Routes ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'brkn_website.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'login.html'));
});

console.log("✅ Express middleware and static routing configured.");

// ===================================
// --- STOREFRONT AUTH ROUTES ---
// ===================================

// POST /store/register
app.post('/store/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    try {
        const { data: authData, error: authError } = await supabase.auth.signUp({ email, password });
        if (authError) throw authError;

        const { error: profileError } = await supabase.from('users').insert({
            supabase_id: authData.user.id,
            name,
            phone,
            email,
            role: 'user'
        });
        if (profileError) throw profileError;

        res.status(201).json({ success: true, message: 'Check your email to confirm.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /store/login
app.post('/store/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: sessionData, error: authError } = await supabase.auth.signInWithPassword({ email, password });
        if (authError) throw authError;

        res.cookie('sf-token', sessionData.session.access_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'Lax',
            maxAge: sessionData.session.expires_in * 1000,
            path: '/'
        });

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

// GET /store/me
app.get('/store/me', async (req, res) => {
    const token = req.cookies['sf-token'];
    if (!token) return res.status(401).json({ error: 'No session' });

    try {
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data: profile } = await supabase.from('users').select('*').eq('supabase_id', user.id).single();
        res.status(200).json({ user: { ...user, profile } });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /store/logout
app.post('/store/logout', (req, res) => {
    res.clearCookie('sf-token', { path: '/' });
    res.status(200).json({ success: true });
});

// ===================================
// --- PUBLIC PRODUCT ROUTES ---
// ===================================

app.get('/products', async (req, res) => {
    const { data, error } = await supabase.from('products').select('*').eq('status', 'active');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`🚀 Local backend running on http://localhost:${PORT}`);
    });
}

export default app;
