import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import cookieParser from 'cookie-parser';

// --- Setup ---
dotenv.config();
const app = express();
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// --- Middleware ---
// --- Middleware ---
app.use(cors({
    // Allow the Live Server IP, the Localhost alias, and 'null' for local file opening
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500', 'null'], 
    credentials: true 
}));
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

console.log("✅ Express middleware configured.");

// ===================================
// --- (NEW) STOREFRONT AUTH ROUTES ---
// ===================================
// These routes are for regular users.

// POST /store/register - Handle storefront user registration
app.post('/store/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    console.log(`➡️ POST /store/register attempt for: ${email}`);

    try {
        // 1. Create the user in Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signUp({ email, password });
        if (authError) throw authError;
        if (!authData.user) throw new Error("Signup successful but no user data returned.");

        console.log("✅ Auth user created:", authData.user.id);

        // 2. Insert the user's profile into the 'users' table
        const { error: profileError } = await supabase.from('users').insert({
            supabase_id: authData.user.id, // ⚠️ Make sure 'supabase_id' is your column name
            name,
            phone,
            email,
            role: 'user' // Set role to 'user' by default
        });
        if (profileError) throw profileError;

        console.log(`✅ Profile for ${email} created.`);
        // Don't set a cookie here; user must confirm email first.
        res.status(201).json({ success: true, message: 'Registration successful. Please check your email to confirm.' });

    } catch (error) {
        console.error("💥 Error in POST /store/register:", error);
        res.status(500).json({ error: error.message || 'Registration failed' });
    }
});

// POST /store/login - Handle storefront user login
app.post('/store/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(`➡️ POST /store/login attempt for: ${email}`);

    try {
        // 1. Sign in user with Supabase
        const { data: sessionData, error: authError } = await supabase.auth.signInWithPassword({ email, password });
        if (authError) throw authError;

        const token = sessionData.session.access_token;

        // 2. Set the HttpOnly cookie for the storefront
        res.cookie('sf-token', token, { // Using 'sf-token' (storefront token)
            httpOnly: true,
            secure: false, // Set to false for localhost HTTP
            sameSite: 'Lax',
            maxAge: sessionData.session.expires_in * 1000,
            path: '/'
        });

        console.log(`✅ Storefront user ${email} logged in.`);
        res.status(200).json({ success: true, message: 'Login successful.' });

    } catch (error) {
        console.warn(`🚫 Storefront login failed for ${email}:`, error.message);
        res.status(401).json({ error: error.message || 'Invalid credentials' });
    }
});

// GET /store/me - Get the current storefront user's session
app.get('/store/me', async (req, res) => {
    console.log("➡️ GET /store/me (Storefront session check)");
    const token = req.cookies['sf-token']; // Check for 'sf-token'

    if (!token) {
        return res.status(401).json({ error: 'No active session' });
    }

    try {
        // 1. Get user from token
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) {
             res.clearCookie('sf-token', { path: '/' });
             return res.status(401).json({ error: 'Invalid session' });
        }

        // 2. Get user profile from 'users' table
        const { data: profile, error: profileError } = await supabase
            .from('users')
            .select('name, phone, email, created_at, role') // Select profile data
            .eq('supabase_id', user.id) // ⚠️ Make sure 'supabase_id' is correct
            .single();
        
        if (profileError || !profile) {
            return res.status(404).json({ error: 'User profile not found.' });
        }

        // 3. Return the full user object (auth data + profile data)
        const fullUser = {
            ...user,       // Auth data (id, email, created_at)
            profile: profile // Profile data (name, phone, role)
        };

        console.log(`✅ Active storefront session for ${fullUser.email}`);
        res.status(200).json({ user: fullUser });

    } catch (error) {
        console.error("💥 Error in GET /store/me:", error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /store/logout - Handle storefront user logout
app.post('/store/logout', (req, res) => {
    console.log(`➡️ POST /store/logout`);
    res.cookie('sf-token', '', { // Clear 'sf-token'
        httpOnly: true,
        secure: false, // false for localhost
        sameSite: 'Lax',
        expires: new Date(0),
        path: '/'
    });
    res.status(200).json({ success: true, message: 'Logged out.' });
});


// --- (NEW) STOREFRONT AUTH MIDDLEWARE ---
// This checks for the 'sf-token' and gets the user, but doesn't check for admin role
async function authenticateStorefrontUser(req, res, next) {
    console.log(`🔑 Storefront authentication attempt for: ${req.path}`);
    const token = req.cookies['sf-token']; // Check for 'sf-token'

    if (!token) {
        console.warn("🚫 Storefront Auth failed: Missing token cookie.");
        return res.status(401).json({ error: 'No active session' });
    }

    try {
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) {
             res.clearCookie('sf-token', { path: '/' });
             return res.status(401).json({ error: 'Invalid session' });
        }

        // Attach the user to the request
        req.user = user;
        console.log(`✅ Storefront user authenticated: ${user.email}`);
        next(); // Proceed

    } catch (error) {
        console.error("💥 Error in authenticateStorefrontUser:", error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}


// --- (NEW) STOREFRONT ORDERS ROUTE ---
// GET /store/orders - Get orders for the logged-in user
app.get('/store/orders', authenticateStorefrontUser, async (req, res) => {
    // req.user is attached by the authenticateStorefrontUser middleware
    console.log(`➡️ GET /store/orders requested by ${req.user.email}`);

    try {
        // Since RLS is disabled for testing, we MUST filter manually
        const { data, error } = await supabase
            .from('orders')
            .select('*')
            // This line is CRITICAL for security
            .eq('user_id', req.user.id) 
            .order('created_at', { ascending: false }); // Show newest orders first

        if (error) {
            console.error(`🚨 Database error fetching orders for user ${req.user.id}:`, error);
            throw error;
        }

        console.log(`✅ Successfully fetched ${data.length} orders for ${req.user.email}.`);
        res.status(200).json(data); // Send the list of orders

    } catch (error) {
        console.error(`💥 Error in GET /store/orders:`, error);
        res.status(500).json({ error: error.message || 'Failed to fetch orders' });
    }
});


//admin auth routes and middleware


// Middleware: Verify Admin JWT from Cookie
async function authenticateAdmin(req, res, next) {
    console.log(`🔑 ADMIN authentication for: ${req.path}`);
    const token = req.cookies.token; 
    if (!token) return res.status(401).json({ error: 'Missing admin token' });

    try {
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) return res.status(401).json({ error: 'Invalid admin token' });

        const { data: profile, error: profileError } = await supabase
            .from('users')
            .select('role')
            .eq('supabase_id', user.id) // ⚠️ Make sure 'supabase_id' is correct
            .single();
        
        if (profileError || !profile) return res.status(403).json({ error: 'Admin profile not found.' });
        if (profile.role !== 'admin') return res.status(403).json({ error: 'Access Denied: Not an admin.' });

        req.user = user;
        console.log(`✅ Admin user authenticated: ${user.email}`);
        next();
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
}

// POST /login - Handle admin login
app.post('/login', async (req, res) => {
    // ... (This function remains unchanged from before)
    const { email, password } = req.body;
    try {
        const { data: sessionData, error: authError } = await supabase.auth.signInWithPassword({ email, password });
        if (authError) return res.status(401).json({ error: authError.message });
        const { user, session } = sessionData;
        const { data: profile, error: profileError } = await supabase.from('users').select('role').eq('supabase_id', user.id).single();
        if (profileError || !profile) return res.status(403).json({ error: 'Profile not found.' });
        if (profile.role !== 'admin') return res.status(403).json({ error: 'Not an administrator.' });
        
        res.cookie('token', session.access_token, {
            httpOnly: true,
            secure: false, // false for localhost
            sameSite: 'Lax',
            maxAge: session.expires_in * 1000,
            path: '/'
        });
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /logout - Handle admin logout
app.post('/logout', (req, res) => {
    // ... (This function remains unchanged from before)
    res.cookie('token', '', {
        httpOnly: true,
        secure: false, // false for localhost
        sameSite: 'Lax',
        expires: new Date(0),
        path: '/'
    });
    res.status(200).json({ success: true, message: 'Logged out.' });
});


// ===================================
// --- PUBLIC PRODUCT ROUTES ---
// ===================================
// These are for the storefront

// GET /products - Public route
app.get('/products', async (req, res) => {
    // ... (This function remains unchanged)
    console.log(`➡️ GET /products (Public Access)`);
    try {
        const { data, error } = await supabase.from('products').select('*').eq('status', 'active').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /product/:id - Public route
app.get('/product/:id', async (req, res) => {
    // ... (This function remains unchanged)
    const { id } = req.params;
    console.log(`➡️ GET /product/${id} (Public Access)`);
    try {
        const { data, error } = await supabase.from('products').select('*').eq('id', id).eq('status', 'active').single();
        if (error) {
           if (error.code === 'PGRST116') return res.status(404).json({ error: 'Product not found or not active.' });
           throw error;
        }
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===================================
// --- (ADMIN) PROTECTED API ROUTES ---
// ===================================
// These routes are prefixed with /api and use authenticateAdmin middleware

// GET /api/products (Admin)
app.get('/api/products', authenticateAdmin, async (req, res) => {
    // ... (This function remains unchanged)
    console.log(`➡️ GET /api/products (Admin) requested by ${req.user.email}`);
    const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// POST /api/products (Admin)
app.post('/api/products', authenticateAdmin, async (req, res) => {
    // ... (This function remains unchanged)
    console.log(`➡️ POST /api/products (Admin) requested by ${req.user.email}`);
    const { name, description, status, images, price } = req.body;
    const { data, error } = await supabase.from('products').insert({ name, description, status, images, price }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data);
});

// PUT /api/products/:id (Admin)
app.put('/api/products/:id', authenticateAdmin, async (req, res) => {
    // ... (This function remains unchanged)
    const { id } = req.params;
    console.log(`➡️ PUT /api/products/${id} (Admin) requested by ${req.user.email}`);
    const { name, description, status, images, price } = req.body;
    const { data, error } = await supabase.from('products').update({ name, description, status, images, price, updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'Product not found' });
    res.json(data);
});

// DELETE /api/products/:id (Admin)
app.delete('/api/products/:id', authenticateAdmin, async (req, res) => {
    // ... (This function remains unchanged)
    const { id } = req.params;
    console.log(`➡️ DELETE /api/products/${id} (Admin) requested by ${req.user.email}`);
    const { error, count } = await supabase.from('products').delete({ count: 'exact' }).eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    if (count === 0) return res.status(404).json({ error: 'Product not found' });
    res.json({ success: true });
});

// GET /api/overview (Admin)
app.get('/api/overview', authenticateAdmin, async (req, res) => {
    // ... (This function remains unchanged)
    console.log(`➡️ GET /api/overview (Admin) requested by ${req.user.email}`);
    try {
        const { data, error } = await supabase.from('products').select('status, images, created_at, updated_at');
        if (error) throw error;
        // ... (stats calculation)
        const totalProducts = data.length;
        const activeProducts = data.filter(p => p.status === 'active').length;
        const totalImages = data.reduce((sum, p) => sum + (Array.isArray(p.images) ? p.images.length : 0), 0);
        let lastUpdated = null;
        if (data.length > 0) {
            const validTimestamps = data
                .map(p => p.updated_at || p.created_at)
                .filter(ts => ts)
                .map(ts => new Date(ts));
            if (validTimestamps.length > 0) {
                 lastUpdated = validTimestamps.sort((a, b) => b - a)[0].toISOString();
            }
        }
        res.json({ totalProducts, activeProducts, totalImages, lastUpdated });
    } catch (error) {
        console.error("💥 Error in GET /api/overview:", error);
        res.status(500).json({ error: error.message });
    }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Backend server (with HttpOnly cookies) running on http://localhost:${PORT}`);
});



