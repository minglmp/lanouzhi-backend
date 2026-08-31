import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify} from 'hono/jwt'; // Added verify
import bcrypt from 'bcryptjs';
import { decode } from 'hono/jwt';

// Define Types
const app = new Hono<{ 
  Bindings: { makerspace_db: any },
  Variables: { user: any } // Add a variable to pass User data after Token verification
}>();

app.use('/*', cors());

const SECRET_KEY = "super_secret_key";

// ==========================================
// Middleware for checking Token (Auth Guard)
// ==========================================
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ message: 'Please log in to continue' }, 401);
  }

  // 1. Add "as string" to fix TypeScript warnings
  const token = authHeader.split(' ')[1] as string; 
  
  try {
    const decodedPayload = await verify(token, SECRET_KEY, 'HS256');
    c.set('user', decodedPayload); 
    await next(); 
  } catch (error: any) {
    // 2. Output the exact error reason
    return c.json({ 
      message: 'Invalid or expired token', 
      error_detail: error.message, // State the exact cause
      received_token: token // Show the received token for debugging
    }, 401);
  }
};

// ==========================================
// 1. API to fetch all 3D models (Home page)
// ==========================================
app.get('/api/models', async (c) => {
  try {
    const db = c.env.makerspace_db;
    // Fetch all models, sorted from newest to oldest
    const { results } = await db.prepare('SELECT * FROM models ORDER BY created_at DESC').all();
    return c.json(results, 200);
  } catch (error: any) {
    return c.json({ message: 'An error occurred', error: error.message }, 500);
  }
});

// ==========================================
// API ดึงข้อมูลโมเดลรายชิ้น (สำหรับหน้า Detail)
// ==========================================
app.get('/api/models/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const db = c.env.makerspace_db;
    const model = await db.prepare('SELECT * FROM models WHERE id = ?').bind(id).first();
    
    if (!model) return c.json({ message: 'Model not found' }, 404);
    
    return c.json(model, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// 2. API to upload a new 3D model (Login required)
// ==========================================
app.post('/api/models', async (c) => {
  try {
    const { title, images, category } = await c.req.json();
    const db = c.env.makerspace_db;

    // 1. ดึงข้อมูลผู้ใช้จาก Token
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    
    // 👇 ใช้ฟังก์ชัน decode ของ Hono แทน atob
    const { payload } = decode(token!);
    const author = payload.username;

    // 👇 เติม globalThis. เข้าไปเพื่อให้ TypeScript รู้จัก
    const id = (globalThis as any).crypto.randomUUID();
    
    // เก็บเป็น JSON string: '["data:image/...", "data:image/..."]'
    const imageUrlsJson = JSON.stringify(images || []);

    await db.prepare(
      'INSERT INTO models (id, title, author, image_url, category) VALUES (?, ?, ?, ?, ?)'
    ).bind(id, title, author, imageUrlsJson, category || 'Art').run();

    return c.json({ message: 'Model uploaded successfully' }, 201);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API to delete a 3D model (Owner only)
// ==========================================
app.delete('/api/models/:id', authMiddleware, async (c) => {
  try {
    const modelId = c.req.param('id');
    const user = c.get('user'); // Get user data from Token
    const db = c.env.makerspace_db;

    // Check if the model exists and if the user is the "author"
    const model = await db.prepare('SELECT * FROM models WHERE id = ?').bind(modelId).first();
    
    if (!model) return c.json({ message: 'Model not found' }, 404);
    
    // 👇 Reject if the user is neither the owner nor an admin
    if (model.author !== user.username && user.role !== 'admin') {
      return c.json({ message: 'You do not have permission to delete this.' }, 403);
    }

    // Delete from D1 Database
    await db.prepare('DELETE FROM models WHERE id = ?').bind(modelId).run();

    return c.json({ message: 'Deleted successfully' }, 200);
  } catch (error: any) {
    return c.json({ message: 'An error occurred', error: error.message }, 500);
  }
});

// ==========================================
// API แก้ไขโมเดล 3D (เฉพาะเจ้าของผลงาน หรือ Admin)
// ==========================================
app.put('/api/models/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const { title, images, category } = await c.req.json();
    const db = c.env.makerspace_db;

    const imageUrlsJson = JSON.stringify(images || []);

    await db.prepare(
      'UPDATE models SET title = ?, image_url = ?, category = ? WHERE id = ?'
    ).bind(title, imageUrlsJson, category, id).run();

    return c.json({ message: 'Model updated successfully' }, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API for Registration and Login 
// ==========================================
app.post('/api/auth/register', async (c) => {
  try {
    // 👇 1. Changed from receiving email to phone_number
    const { username, phone_number, password } = await c.req.json();
    const db = c.env.makerspace_db;

    // 👇 2. Check for duplicate phone number instead of email
    const existingUser = await db.prepare('SELECT * FROM users WHERE phone_number = ?').bind(phone_number).first();
    if (existingUser) return c.json({ message: 'This phone number is already registered' }, 400);

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // @ts-ignore
    const userId = globalThis.crypto.randomUUID();

    // 👇 3. Save phone_number to database (set default role as 'user')
    await db.prepare('INSERT INTO users (id, username, phone_number, password, role) VALUES (?, ?, ?, ?, ?)')
            .bind(userId, username, phone_number, hashedPassword, 'user').run();

    return c.json({ message: 'Register successful!' }, 201);
  } catch (error: any) {
    return c.json({ message: 'Error', error: error.message }, 500);
  }
});

app.post('/api/auth/login', async (c) => {
  try {
    // 👇 1. Changed from receiving email to phone_number
    const { phone_number, password } = await c.req.json();
    const db = c.env.makerspace_db;

    // 👇 2. Find user by phone number
    const user = await db.prepare('SELECT * FROM users WHERE phone_number = ?').bind(phone_number).first();
    if (!user) return c.json({ message: 'Incorrect phone number or password' }, 401);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return c.json({ message: 'Incorrect phone number or password' }, 401);

    const payload = {
      userId: user.id,
      username: user.username,
      // 👇 3. Extract role and embed it in the Token for the frontend to know if the user is an admin or user
      role: user.role || 'user', 
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    };
    
    const token = await sign(payload, SECRET_KEY);

    return c.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, role: user.role }});
  } catch (error: any) {
    return c.json({ message: 'Error', error: error.message }, 500);
  }
});

app.get('/', (c) => {
  return c.json({ message: 'MakerSpace API is running 🚀' });
});

export default app;