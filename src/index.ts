import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify, decode } from 'hono/jwt';
import bcrypt from 'bcryptjs';

// Define Types
const app = new Hono<{ 
  Bindings: { 
    makerspace_db: any;
    IMAGE_BUCKET: R2Bucket; 
  },
  Variables: { user: any }
}>();

app.use('/*', cors());

const SECRET_KEY = "super_secret_key";

// 🌟 Helper Function: ดึงชื่อไฟล์ออกจาก URL (เช่น ดึง '123-cat.jpg' ออกจาก 'https://pub-xxx.r2.dev/123-cat.jpg')
const getFileNameFromUrl = (url: string) => {
  if (!url || !url.includes('r2.dev')) return null; // เช็กว่าเป็นลิงก์จาก R2 จริงๆ (ป้องกัน Error ถ้ามีรูป Base64 เก่าค้างอยู่)
  const parts = url.split('/');
  return parts[parts.length - 1]; 
};

// ==========================================
// Middleware for checking Token (Auth Guard)
// ==========================================
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ message: 'Please log in to continue' }, 401);
  }
  const token = authHeader.split(' ')[1] as string; 
  try {
    const decodedPayload = await verify(token, SECRET_KEY, 'HS256');
    c.set('user', decodedPayload); 
    await next(); 
  } catch (error: any) {
    return c.json({ message: 'Invalid or expired token', error_detail: error.message, received_token: token }, 401);
  }
};

// ==========================================
// API to fetch all 3D models (Home page)
// ==========================================
app.get('/api/models', async (c) => {
  try {
    const db = c.env.makerspace_db;
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
// API to upload a new 3D model (Login required)
// ==========================================
app.post('/api/models', async (c) => {
  try {
    const { title, images, category, description, price } = await c.req.json();
    const db = c.env.makerspace_db;

    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    const { payload } = decode(token!);
    const author = payload.username;
    const role = payload.role; // 🌟 ดึงสิทธิ์ (Role) ออกมาเช็ก

    // 🌟 กฎเหล็ก: ถ้าไม่ใช่ Admin และไม่ใช่ Creator ห้ามอัปโหลดเด็ดขาด!
    if (role !== 'admin' && role !== 'creator') {
      return c.json({ message: 'Forbidden: Only Creators and Admins can upload models.' }, 403);
    }

    const id = (globalThis as any).crypto.randomUUID();
    const imageUrlsJson = JSON.stringify(images || []);

    await db.prepare(
      'INSERT INTO models (id, title, author, image_url, category, description, price) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(id, title, author, imageUrlsJson, category || 'Art', description || '', Number(price) || 0).run();

    return c.json({ message: 'Model uploaded successfully' }, 201);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// 🌟 API ลบโมเดล 3D (เพิ่มระบบลบไฟล์ใน R2)
// ==========================================
app.delete('/api/models/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const db = c.env.makerspace_db;

    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    const { payload } = decode(token!);
    const requester = payload.username;
    const role = payload.role;

    // 1. ดึงข้อมูลโมเดลมาก่อนเพื่อเอาลิงก์รูปภาพ
    const model = await db.prepare('SELECT * FROM models WHERE id = ?').bind(id).first();
    if (!model) return c.json({ message: 'Model not found' }, 404);

    if (model.author !== requester && role !== 'admin') {
      return c.json({ message: 'Unauthorized: You can only delete your own models.' }, 403);
    }

    // 2. ตามไปลบไฟล์ในถัง R2
    const imageUrls = JSON.parse(model.image_url || '[]');
    for (const url of imageUrls) {
      const fileName = getFileNameFromUrl(url);
      if (fileName) {
        await c.env.IMAGE_BUCKET.delete(fileName); // 🗑️ สั่งลบไฟล์ทิ้ง
      }
    }

    // 3. ลบข้อมูลจาก Database D1
    await db.prepare('DELETE FROM models WHERE id = ?').bind(id).run();
    return c.json({ message: 'Model and images deleted successfully' }, 200);

  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// 🌟 API แก้ไขโมเดล 3D (เพิ่มระบบเช็กลบไฟล์เก่าใน R2)
// ==========================================
app.put('/api/models/:id', async (c) => {
  try {
    const id = c.req.param('id');
    // images ที่รับมาคือ "รูปรวมทั้งหมดที่ต้องการเก็บไว้ (รูปเก่าที่เหลือ + รูปใหม่)"
    const { title, images, category, description, price } = await c.req.json();
    const db = c.env.makerspace_db;

    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    const { payload } = decode(token!);
    const requester = payload.username;
    const role = payload.role;

    const model = await db.prepare('SELECT * FROM models WHERE id = ?').bind(id).first();
    if (!model) return c.json({ message: 'Model not found' }, 404);

    if (model.author !== requester && role !== 'admin') {
      return c.json({ message: 'Unauthorized: You cannot edit this model.' }, 403);
    }

    // 1. หากลุ่ม "รูปที่ถูกกดลบออก (Orphaned Images)"
    const oldImageUrls = JSON.parse(model.image_url || '[]');
    const newImageUrls = images || [];
    
    // กรองหาลิงก์เก่า ที่ไม่มีอยู่ในลิงก์ใหม่ (แปลว่าโดน User ลบออกไปตอน Edit)
    const deletedUrls = oldImageUrls.filter((oldUrl: string) => !newImageUrls.includes(oldUrl));

    // 2. ตามไปลบไฟล์ที่ไม่ได้ใช้แล้วในถัง R2
    for (const url of deletedUrls) {
      const fileName = getFileNameFromUrl(url);
      if (fileName) {
        await c.env.IMAGE_BUCKET.delete(fileName); // 🗑️ สั่งลบไฟล์ที่ถูกคัดออก
      }
    }

    // 3. อัปเดตข้อมูลใหม่ลง Database
    const imageUrlsJson = JSON.stringify(newImageUrls);
    await db.prepare(
      'UPDATE models SET title = ?, image_url = ?, category = ?, description = ?, price = ? WHERE id = ?'
    ).bind(title, imageUrlsJson, category, description || '', Number(price) || 0, id).run();

    return c.json({ message: 'Model updated successfully' }, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API สร้างออเดอร์ใหม่
// ==========================================
app.post('/api/orders', async (c) => {
  try {
    const { model_id } = await c.req.json(); 
    const db = c.env.makerspace_db;

    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    if (!token) return c.json({ message: 'Please login to order' }, 401);
    
    const { payload } = decode(token);
    const buyer = payload.username;
    const orderId = (globalThis as any).crypto.randomUUID();

    await db.prepare('INSERT INTO orders (id, model_id, buyer_username, slip_image) VALUES (?, ?, ?, ?)')
            .bind(orderId, model_id, buyer, 'no_slip_provided').run();

    return c.json({ message: 'Order submitted! Waiting for admin approval.', order_id: orderId }, 201);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API for Registration and Login 
// ==========================================
app.post('/api/auth/register', async (c) => {
  try {
    const { username, phone_number, password } = await c.req.json();
    const db = c.env.makerspace_db;

    const existingUser = await db.prepare('SELECT * FROM users WHERE phone_number = ?').bind(phone_number).first();
    if (existingUser) return c.json({ message: 'This phone number is already registered' }, 400);

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // @ts-ignore
    const userId = globalThis.crypto.randomUUID();

    await db.prepare('INSERT INTO users (id, username, phone_number, password, role) VALUES (?, ?, ?, ?, ?)')
            .bind(userId, username, phone_number, hashedPassword, 'user').run();

    return c.json({ message: 'Register successful!' }, 201);
  } catch (error: any) {
    return c.json({ message: 'Error', error: error.message }, 500);
  }
});

app.post('/api/auth/login', async (c) => {
  try {
    const { phone_number, password } = await c.req.json();
    const db = c.env.makerspace_db;

    const user = await db.prepare('SELECT * FROM users WHERE phone_number = ?').bind(phone_number).first();
    if (!user) return c.json({ message: 'Incorrect phone number or password' }, 401);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return c.json({ message: 'Incorrect phone number or password' }, 401);

    const payload = {
      userId: user.id,
      username: user.username,
      role: user.role || 'user', 
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
    };
    
    const token = await sign(payload, SECRET_KEY);

    return c.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, role: user.role }});
  } catch (error: any) {
    return c.json({ message: 'Error', error: error.message }, 500);
  }
});

// ==========================================
// API ดึงรายการออเดอร์ (แยกสิทธิ์ Admin / User)
// ==========================================
app.get('/api/orders', async (c) => {
  try {
    const db = c.env.makerspace_db;
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    if (!token) return c.json({ message: 'Unauthorized' }, 401);

    const { payload } = decode(token);
    const role = payload.role;
    const username = payload.username;

    let query = '';
    let results;

    if (role === 'admin') {
      // แอดมิน: ดึงออเดอร์ของทุกคน
      query = `
        SELECT orders.*, models.title as model_title 
        FROM orders 
        LEFT JOIN models ON orders.model_id = models.id 
        ORDER BY orders.created_at DESC
      `;
      const res = await db.prepare(query).all();
      results = res.results;
    } else {
      // ผู้ใช้ทั่วไป: ดึงเฉพาะออเดอร์ที่ตัวเองเป็นคนซื้อ
      query = `
        SELECT orders.*, models.title as model_title 
        FROM orders 
        LEFT JOIN models ON orders.model_id = models.id 
        WHERE orders.buyer_username = ?
        ORDER BY orders.created_at DESC
      `;
      const res = await db.prepare(query).bind(username).all();
      results = res.results;
    }

    return c.json(results, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API สำหรับอัปเดตสถานะออเดอร์ (Approve / Reject)
// ==========================================
app.put('/api/orders/:id/status', async (c) => {
  try {
    const id = c.req.param('id');
    const { status } = await c.req.json();
    const db = c.env.makerspace_db;

    const authHeader = c.req.header('Authorization');
    const token = authHeader?.split(' ')[1];
    const { payload } = decode(token!);
    if (payload.role !== 'admin') return c.json({ message: 'Forbidden' }, 403);

    await db.prepare('UPDATE orders SET status = ? WHERE id = ?').bind(status, id).run();

    return c.json({ message: `Order ${status} successfully` }, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API สำหรับอัปโหลดรูปภาพไปที่ R2
// ==========================================
app.post('/api/upload', async (c) => {
  try {
    const body = await c.req.parseBody();
    const file = body['file'] as File;
    
    if (!file) {
      return c.json({ error: 'No file uploaded' }, 400);
    }

    const fileName = `${Date.now()}-${file.name.replace(/\s+/g, '_')}`;

    await c.env.IMAGE_BUCKET.put(fileName, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type },
    });

    return c.json({ 
      message: 'Upload successful', 
      fileName: fileName 
    }, 200);

  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

app.get('/', (c) => {
  return c.json({ message: 'MakerSpace API is running 🚀' });
});

export default app;