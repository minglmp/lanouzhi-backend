import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';
import bcrypt from 'bcryptjs';

// Define Types
type AuthUser = { userId: string; username: string; role: string; exp: number };

const app = new Hono<{
  Bindings: {
    makerspace_db: any;
    IMAGE_BUCKET: R2Bucket;
    JWT_SECRET: string; // ตั้งค่าด้วย `wrangler secret put JWT_SECRET` (ห้ามใส่ในโค้ด)
  },
  Variables: { user: AuthUser }
}>();

app.use('/*', cors());

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

// 🔐 ดึง secret จาก environment ถ้ายังไม่ได้ตั้งค่า ให้ error ทันที (ไม่มีค่า default)
const getJwtSecret = (c: any): string => {
  const secret = c.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not configured');
  return secret;
};

// 🔐 ตรวจลายเซ็นและวันหมดอายุของ token จริง (ไม่ใช่แค่ decode)
// คืนค่า null ถ้าไม่มี token หรือ token ไม่ถูกต้อง
const getAuthUser = async (c: any): Promise<AuthUser | null> => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const secret = getJwtSecret(c);
  try {
    return (await verify(authHeader.slice(7), secret, 'HS256')) as unknown as AuthUser;
  } catch {
    return null;
  }
};

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
  const user = await getAuthUser(c);
  if (!user) {
    return c.json({ message: 'Please log in to continue (invalid or expired token)' }, 401);
  }
  c.set('user', user);
  await next();
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
app.post('/api/models', authMiddleware, async (c) => {
  try {
    const { title, images, category, description, price } = await c.req.json();
    const db = c.env.makerspace_db;

    const payload = c.get('user');
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
app.delete('/api/models/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id');
    const db = c.env.makerspace_db;

    const payload = c.get('user');
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
app.put('/api/models/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id');
    // images ที่รับมาคือ "รูปรวมทั้งหมดที่ต้องการเก็บไว้ (รูปเก่าที่เหลือ + รูปใหม่)"
    const { title, images, category, description, price } = await c.req.json();
    const db = c.env.makerspace_db;

    const payload = c.get('user');
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
app.post('/api/orders', authMiddleware, async (c) => {
  try {
    const { model_id } = await c.req.json();
    const db = c.env.makerspace_db;

    const payload = c.get('user');
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
    
    const token = await sign(payload, getJwtSecret(c), 'HS256');

    return c.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, role: user.role }});
  } catch (error: any) {
    return c.json({ message: 'Error', error: error.message }, 500);
  }
});

// ==========================================
// API ดึงรายการออเดอร์ (แยกสิทธิ์ Admin / User)
// ==========================================
app.get('/api/orders', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const payload = c.get('user');
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
app.put('/api/orders/:id/status', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id');
    const { status } = await c.req.json();
    const db = c.env.makerspace_db;

    const payload = c.get('user');
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
app.post('/api/upload', authMiddleware, async (c) => {
  try {
    const role = c.get('user').role;
    if (role !== 'admin' && role !== 'creator') {
      return c.json({ message: 'Forbidden: Only Creators and Admins can upload images.' }, 403);
    }

    const body = await c.req.parseBody();
    const file = body['file'];

    if (!file || typeof file === 'string') {
      return c.json({ error: 'No file uploaded' }, 400);
    }
    if (!file.type.startsWith('image/')) {
      return c.json({ error: 'Only image files are allowed' }, 400);
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      return c.json({ error: 'File is too large (max 10 MB)' }, 413);
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

// ==========================================
// API: กดไลก์ / ยกเลิกไลก์ โมเดล (Like & Unlike)
// ==========================================
app.post('/api/models/:id/like', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const modelId = c.req.param('id');

    // เช็กการล็อกอิน (คนกดไลก์ต้องล็อกอินก่อน) — ตรวจโดย authMiddleware แล้ว
    const payload = c.get('user');
    const username = payload.username;

    // เช็กว่าเคยกดไลก์ไปหรือยัง
    const existingLike = await db.prepare(
      'SELECT * FROM likes WHERE model_id = ? AND username = ?'
    ).bind(modelId, username).first();

    if (existingLike) {
      // ถ้าเคยกดแล้ว = ยกเลิกไลก์ (Unlike) เอาชื่อออกจากสมุด และลบยอด -1
      await db.batch([
        db.prepare('DELETE FROM likes WHERE model_id = ? AND username = ?').bind(modelId, username),
        db.prepare('UPDATE models SET likes = MAX(0, likes - 1) WHERE id = ?').bind(modelId)
      ]);
      return c.json({ message: 'Unliked', liked: false }, 200);
    } else {
      // ถ้ายังไม่เคยกด = กดไลก์ (Like) เพิ่มชื่อลงสมุด และบวกยอด +1
      const likeId = (globalThis as any).crypto.randomUUID();
      await db.batch([
        db.prepare('INSERT INTO likes (id, model_id, username) VALUES (?, ?, ?)').bind(likeId, modelId, username),
        db.prepare('UPDATE models SET likes = likes + 1 WHERE id = ?').bind(modelId)
      ]);
      return c.json({ message: 'Liked', liked: true }, 200);
    }
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API: ดึงรายการ ID โมเดลที่ User คนนี้เคยกดไลก์ไปแล้ว
// ==========================================
app.get('/api/user/likes', async (c) => {
  try {
    const db = c.env.makerspace_db;
    // ถ้าไม่ได้ล็อกอิน (หรือ token ไม่ถูกต้อง) ไม่ต้องโชว์หัวใจแดง ส่ง Array เปล่าๆ กลับไป
    const payload = await getAuthUser(c);
    if (!payload) return c.json([], 200);
    const username = payload.username;

    // ดึงเฉพาะไอดีโมเดลที่ยูสเซอร์คนนี้เคยกดไลก์
    const res = await db.prepare('SELECT model_id FROM likes WHERE username = ?').bind(username).all();
    const likedModelIds = res.results.map((r: any) => r.model_id);

    return c.json(likedModelIds, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API: ดึงรายละเอียดโมเดลที่กดไลก์ไว้ (My Favorites)
// ==========================================
app.get('/api/user/favorites', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const payload = c.get('user');
    const username = payload.username;

    // ดึงข้อมูลโมเดล โดย JOIN กับตาราง likes เรียงลำดับจากที่เพิ่งกดไลก์ล่าสุด
    const query = `
      SELECT models.* 
      FROM models 
      JOIN likes ON models.id = likes.model_id 
      WHERE likes.username = ? 
      ORDER BY likes.created_at DESC
    `;
    const res = await db.prepare(query).bind(username).all();

    return c.json(res.results, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// ==========================================
// API: ระบบ Chat (พูดคุย) [อัปเดตระบบแจ้งเตือน Unread]
// ==========================================

// 1. ดึงรายชื่อคนที่เคยคุยด้วย (พร้อมจำนวนข้อความที่ยังไม่ได้อ่าน)
app.get('/api/chat/contacts', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const payload = c.get('user');
    const username = payload.username;

    // 🌟 เพิ่ม COLLATE NOCASE ตรง GROUP BY เพื่อให้มันยุบรวม Admin และ admin เป็นคนเดียวกัน
    const res = await db.prepare(`
      SELECT 
        CASE WHEN LOWER(sender) = LOWER(?) THEN receiver ELSE sender END as contact_name,
        SUM(CASE WHEN LOWER(receiver) = LOWER(?) AND is_read = 0 THEN 1 ELSE 0 END) as unread_count
      FROM messages 
      WHERE LOWER(sender) = LOWER(?) OR LOWER(receiver) = LOWER(?)
      GROUP BY contact_name COLLATE NOCASE
    `).bind(username, username, username, username).all();
    
    let contacts = res.results.map((r: any) => ({
        name: r.contact_name,
        unread: r.unread_count || 0
    }));
    
    const hasAdmin = contacts.some((c: any) => c.name.toLowerCase() === 'admin');
    if (payload.role !== 'admin' && !hasAdmin) {
        contacts.unshift({ name: 'Admin', unread: 0 });
    }

    return c.json(contacts, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// 2. ดึงประวัติการแชท (และอัปเดตสถานะว่า "อ่านแล้ว")
app.get('/api/chat/:contact', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const contact = c.req.param('contact');
    const payload = c.get('user');
    const username = payload.username;

    // อัปเดตข้อความที่คนนี้ส่งมาหาเราให้เป็น "อ่านแล้ว"
    await db.prepare(`
      UPDATE messages SET is_read = 1 
      WHERE LOWER(sender) = LOWER(?) AND LOWER(receiver) = LOWER(?) AND is_read = 0
    `).bind(contact, username).run();

    const res = await db.prepare(`
      SELECT * FROM messages 
      WHERE (LOWER(sender) = LOWER(?) AND LOWER(receiver) = LOWER(?))
         OR (LOWER(sender) = LOWER(?) AND LOWER(receiver) = LOWER(?))
      ORDER BY created_at ASC
    `).bind(username, contact, contact, username).all();

    return c.json(res.results, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// 3. ส่งข้อความ
app.post('/api/chat', authMiddleware, async (c) => {
  try {
    const db = c.env.makerspace_db;
    const payload = c.get('user');
    const sender = payload.username;
    const { receiver, content } = await c.req.json();

    const id = (globalThis as any).crypto.randomUUID();
    await db.prepare(`
      INSERT INTO messages (id, sender, receiver, content) VALUES (?, ?, ?, ?)
    `).bind(id, sender, receiver, content).run();

    return c.json({ message: 'Sent successfully' }, 201);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

// 4. โหลดจำนวนข้อความใหม่รวมทั้งหมด (สำหรับโชว์ Badge ที่เมนู Sidebar)
app.get('/api/chat/unread/total', async (c) => {
  try {
    const db = c.env.makerspace_db;
    const payload = await getAuthUser(c);
    if (!payload) return c.json({ count: 0 }, 200);
    const username = payload.username;

    const res = await db.prepare(`
      SELECT COUNT(*) as count FROM messages 
      WHERE LOWER(receiver) = LOWER(?) AND is_read = 0
    `).bind(username).first();

    return c.json({ count: res?.count || 0 }, 200);
  } catch (error: any) {
    return c.json({ count: 0 }, 500);
  }
});

// ==========================================
// API: Forgot Password (รีเซ็ตรหัสผ่าน)
// ==========================================
// 🔐 ยังไม่มีระบบยืนยันตัวตน (เช่น OTP ทาง SMS) จึงอนุญาตให้รีเซ็ตได้เฉพาะ Admin เท่านั้น
// ไม่งั้นใครก็ตามที่รู้เบอร์โทร/username จะเปลี่ยนรหัสผ่านของคนอื่นได้
app.post('/api/auth/reset-password', async (c) => {
  try {
    const requester = await getAuthUser(c);
    if (!requester || requester.role !== 'admin') {
      return c.json({ message: 'Password reset is handled by an admin. Please contact Admin to reset your password.' }, 403);
    }

    const db = c.env.makerspace_db;
    const body = await c.req.json();
    
    const phone = body.phone_number || body.username;
    const newPassword = body.newPassword;

    if (!phone || !newPassword) {
      return c.json({ message: 'Please provide phone number and new password' }, 400);
    }

    const user = await db.prepare('SELECT * FROM users WHERE phone_number = ? OR username = ?').bind(phone, phone).first();
    if (!user) {
      return c.json({ message: 'Phone number not found in the system. Please check again.' }, 404);
    }

    // 🌟 ส่วนที่เพิ่มเข้ามา: ทำการเข้ารหัสผ่านใหม่ (Hash) ก่อนบันทึกลง Database
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(newPassword, salt);

    // 🌟 เปลี่ยนจากการเซฟ newPassword เป็น hashedPassword
    await db.prepare('UPDATE users SET password = ? WHERE phone_number = ? OR username = ?')
      .bind(hashedPassword, phone, phone)
      .run();

    return c.json({ message: 'Password reset successfully' }, 200);
  } catch (error: any) {
    return c.json({ error: error.message }, 500);
  }
});

export default app;