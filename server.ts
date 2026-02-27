import express from "express";
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database("messaging.db");

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec("ALTER TABLE users ADD COLUMN email TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN password_hash TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN verification_token TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN private_key_iv TEXT"); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT,
    user_id TEXT,
    encrypted_group_key TEXT, -- The group's symmetric key encrypted with the user's public key
    role TEXT DEFAULT 'member',
    PRIMARY KEY (group_id, user_id)
  );
`);

try { db.exec("ALTER TABLE group_members ADD COLUMN last_read_at DATETIME DEFAULT CURRENT_TIMESTAMP;"); } catch (e) {}
try { db.exec("ALTER TABLE messages ADD COLUMN reply_to_id TEXT;"); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS group_invites (
    token TEXT PRIMARY KEY,
    group_id TEXT,
    encrypted_group_key TEXT, -- Group key encrypted with the link's secret
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    group_id TEXT,
    sender_id TEXT,
    content TEXT, -- Encrypted content (base64)
    iv TEXT,      -- Initialization vector (base64)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reply_to_id TEXT
  );

  CREATE TABLE IF NOT EXISTS message_reactions (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    user_id TEXT,
    emoji TEXT,
    UNIQUE(message_id, user_id, emoji)
  );
`);

async function startServer() {
  const app = express();
  const httpServer = createServer(app);
  const wss = new WebSocketServer({ server: httpServer });
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/register", (req, res) => {
    const { username, email } = req.body;
    
    const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (existingUser) {
      return res.status(409).json({ error: "try new name and unique" });
    }

    try {
      const id = uuidv4();
      const token = uuidv4();
      db.prepare("INSERT INTO users (id, username, email, verification_token, is_verified) VALUES (?, ?, ?, ?, 0)").run(id, username, email, token);
      // In a real app, send an email here. For now, we return the token to simulate the email link.
      res.json({ id, username, email, verification_token: token });
    } catch (e) {
      res.status(400).json({ error: "Registration failed" });
    }
  });

  app.post("/api/verify", async (req, res) => {
    const { token, password, publicKey, encryptedPrivateKey, privateKeyIv } = req.body;
    
    const user = db.prepare("SELECT * FROM users WHERE verification_token = ? AND is_verified = 0").get(token) as any;
    if (!user) {
      return res.status(400).json({ error: "Invalid or expired verification token" });
    }

    try {
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      db.prepare(`
        UPDATE users 
        SET is_verified = 1, password_hash = ?, public_key = ?, encrypted_private_key = ?, private_key_iv = ?, verification_token = NULL 
        WHERE id = ?
      `).run(passwordHash, publicKey, encryptedPrivateKey, privateKeyIv, user.id);

      res.json({ id: user.id, username: user.username, public_key: publicKey, encrypted_private_key: encryptedPrivateKey, private_key_iv: privateKeyIv });
    } catch (e) {
      res.status(400).json({ error: "Verification failed" });
    }
  });

  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND is_verified = 1").get(username) as any;
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    res.json({ 
      id: user.id, 
      username: user.username, 
      public_key: user.public_key,
      encrypted_private_key: user.encrypted_private_key,
      private_key_iv: user.private_key_iv
    });
  });

  app.get("/api/users", (req, res) => {
    const users = db.prepare("SELECT id, username, public_key FROM users").all();
    res.json(users);
  });

  app.put("/api/users/:userId", (req, res) => {
    const { username } = req.body;
    db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, req.params.userId);
    res.json({ success: true });
  });

  app.put("/api/users/:userId/keys", (req, res) => {
    const { publicKey, encryptedPrivateKey, privateKeyIv } = req.body;
    db.prepare("UPDATE users SET public_key = ?, encrypted_private_key = ?, private_key_iv = ? WHERE id = ?").run(publicKey, encryptedPrivateKey, privateKeyIv, req.params.userId);
    res.json({ success: true });
  });

  app.put("/api/users/:userId/clear-unread", (req, res) => {
    db.prepare("UPDATE group_members SET last_read_at = CURRENT_TIMESTAMP WHERE user_id = ?").run(req.params.userId);
    res.json({ success: true });
  });

  app.post("/api/groups", (req, res) => {
    const { name, createdBy, encryptedGroupKey } = req.body;
    const groupId = uuidv4();
    try {
      db.transaction(() => {
        db.prepare("INSERT INTO groups (id, name, created_by) VALUES (?, ?, ?)").run(groupId, name, createdBy);
        db.prepare("INSERT INTO group_members (group_id, user_id, encrypted_group_key, role) VALUES (?, ?, ?, 'admin')").run(groupId, createdBy, encryptedGroupKey);
      })();
      res.json({ id: groupId, name });
    } catch (e: any) {
      if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        res.status(400).json({ error: "Group name already exists" });
      } else {
        res.status(500).json({ error: "Failed to create group" });
      }
    }
  });

  app.put("/api/groups/:groupId", (req, res) => {
    const { name } = req.body;
    try {
      db.prepare("UPDATE groups SET name = ? WHERE id = ?").run(name, req.params.groupId);
      res.json({ success: true });
    } catch (e: any) {
      res.status(400).json({ error: "Group name already exists or invalid" });
    }
  });

  app.put("/api/groups/:groupId/members/:userId/role", (req, res) => {
    const { role } = req.body;
    db.prepare("UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?").run(role, req.params.groupId, req.params.userId);
    res.json({ success: true });
  });

  app.get("/api/groups/:userId", (req, res) => {
    const groups = db.prepare(`
      SELECT g.*, gm.encrypted_group_key, gm.last_read_at,
             (SELECT content FROM messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message_content,
             (SELECT iv FROM messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message_iv,
             (SELECT COUNT(*) FROM messages WHERE group_id = g.id AND created_at > gm.last_read_at) as unread_count
      FROM groups g 
      JOIN group_members gm ON g.id = gm.group_id 
      WHERE gm.user_id = ?
    `).all(req.params.userId);
    res.json(groups);
  });

  app.post("/api/groups/:groupId/members", (req, res) => {
    const { userId, encryptedGroupKey } = req.body;
    db.prepare("INSERT INTO group_members (group_id, user_id, encrypted_group_key) VALUES (?, ?, ?)").run(req.params.groupId, userId, encryptedGroupKey);
    res.json({ success: true });
  });

  app.post("/api/groups/:groupId/rekey", (req, res) => {
    const { memberKeys } = req.body; // Array of { userId, encryptedGroupKey }
    const groupId = req.params.groupId;
    
    const update = db.transaction((keys) => {
      for (const { userId, encryptedGroupKey } of keys) {
        db.prepare("UPDATE group_members SET encrypted_group_key = ? WHERE group_id = ? AND user_id = ?")
          .run(encryptedGroupKey, groupId, userId);
      }
    });
    
    update(memberKeys);
    res.json({ success: true });
  });

  app.delete("/api/groups/:groupId/members/:userId", (req, res) => {
    db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(req.params.groupId, req.params.userId);
    res.json({ success: true });
  });

  app.get("/api/groups/:groupId/members", (req, res) => {
    const members = db.prepare(`
      SELECT gm.*, u.username, u.public_key 
      FROM group_members gm 
      JOIN users u ON gm.user_id = u.id 
      WHERE gm.group_id = ?
    `).all(req.params.groupId);
    res.json(members);
  });

  app.post("/api/groups/:groupId/invites", (req, res) => {
    const { encryptedGroupKey, expiresAt } = req.body;
    const token = uuidv4();
    db.prepare("INSERT INTO group_invites (token, group_id, encrypted_group_key, expires_at) VALUES (?, ?, ?, ?)")
      .run(token, req.params.groupId, encryptedGroupKey, expiresAt || null);
    res.json({ token });
  });

  app.get("/api/invites/:token", (req, res) => {
    const invite = db.prepare(`
      SELECT i.*, g.name as group_name 
      FROM group_invites i 
      JOIN groups g ON i.group_id = g.id 
      WHERE i.token = ? AND (i.expires_at IS NULL OR i.expires_at > CURRENT_TIMESTAMP)
    `).get(req.params.token) as any;
    if (!invite) return res.status(404).json({ error: "Invite not found or expired" });
    res.json(invite);
  });

  app.post("/api/invites/:token/join", (req, res) => {
    const { userId, encryptedGroupKey } = req.body;
    const invite = db.prepare(`
      SELECT group_id FROM group_invites 
      WHERE token = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    `).get(req.params.token) as any;
    if (!invite) return res.status(404).json({ error: "Invite not found or expired" });

    try {
      db.prepare("INSERT INTO group_members (group_id, user_id, encrypted_group_key) VALUES (?, ?, ?)")
        .run(invite.group_id, userId, encryptedGroupKey);
      res.json({ success: true, groupId: invite.group_id });
    } catch (e: any) {
      if (e.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
        res.json({ success: true, groupId: invite.group_id }); // Already a member
      } else {
        res.status(500).json({ error: "Failed to join group" });
      }
    }
  });

  app.get("/api/groups/:groupId/messages", (req, res) => {
    const messages = db.prepare(`
      SELECT m.*, u.username as sender_name,
             pm.content as reply_to_content, pm.iv as reply_to_iv, pu.username as reply_to_sender_name
      FROM messages m 
      JOIN users u ON m.sender_id = u.id 
      LEFT JOIN messages pm ON m.reply_to_id = pm.id
      LEFT JOIN users pu ON pm.sender_id = pu.id
      WHERE m.group_id = ? 
      ORDER BY m.created_at ASC 
      LIMIT 100
    `).all(req.params.groupId);

    const messageIds = messages.map((m: any) => m.id);
    if (messageIds.length > 0) {
      const placeholders = messageIds.map(() => '?').join(',');
      const reactions = db.prepare(`
        SELECT mr.*, u.username 
        FROM message_reactions mr
        JOIN users u ON mr.user_id = u.id
        WHERE mr.message_id IN (${placeholders})
      `).all(...messageIds);
      
      const reactionsByMsg = reactions.reduce((acc: any, r: any) => {
        if (!acc[r.message_id]) acc[r.message_id] = [];
        acc[r.message_id].push(r);
        return acc;
      }, {});
      
      messages.forEach((m: any) => {
        m.reactions = reactionsByMsg[m.id] || [];
      });
    } else {
      messages.forEach((m: any) => m.reactions = []);
    }

    res.json(messages);
  });

  app.post("/api/messages/:messageId/reactions/toggle", (req, res) => {
    const { userId, emoji } = req.body;
    const existing = db.prepare("SELECT id FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?").get(req.params.messageId, userId, emoji) as any;
    
    if (existing) {
      db.prepare("DELETE FROM message_reactions WHERE id = ?").run(existing.id);
      res.json({ action: 'removed', emoji, userId });
    } else {
      const id = uuidv4();
      db.prepare("INSERT INTO message_reactions (id, message_id, user_id, emoji) VALUES (?, ?, ?, ?)").run(id, req.params.messageId, userId, emoji);
      res.json({ action: 'added', emoji, userId, id });
    }
  });

  app.post("/api/groups/:groupId/read", (req, res) => {
    const { userId } = req.body;
    db.prepare("UPDATE group_members SET last_read_at = CURRENT_TIMESTAMP WHERE group_id = ? AND user_id = ?")
      .run(req.params.groupId, userId);
    res.json({ success: true });
  });

  // WebSocket logic
  const clients = new Map<string, WebSocket>();

  wss.on("connection", (ws) => {
    let currentUserId: string | null = null;

    ws.on("message", (data) => {
      const message = JSON.parse(data.toString());

      if (message.type === "auth") {
        currentUserId = message.userId;
        clients.set(currentUserId!, ws);
      }

      if (message.type === "chat") {
        const { groupId, senderId, content, iv, replyToId } = message;
        const msgId = uuidv4();
        db.prepare("INSERT INTO messages (id, group_id, sender_id, content, iv, reply_to_id) VALUES (?, ?, ?, ?, ?, ?)").run(msgId, groupId, senderId, content, iv, replyToId || null);
        
        const sender = db.prepare("SELECT username FROM users WHERE id = ?").get(senderId) as any;
        
        let replyToData = null;
        if (replyToId) {
          const parentMsg = db.prepare(`
            SELECT m.content, m.iv, u.username as sender_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.id = ?
          `).get(replyToId) as any;
          if (parentMsg) {
            replyToData = {
              content: parentMsg.content,
              iv: parentMsg.iv,
              senderName: parentMsg.sender_name
            };
          }
        }

        // Broadcast to group members
        const members = db.prepare("SELECT user_id FROM group_members WHERE group_id = ?").all(groupId) as any[];
        const payload = JSON.stringify({
          type: "chat",
          id: msgId,
          groupId,
          senderId,
          senderName: sender.username,
          content,
          iv,
          replyToId,
          replyToContent: replyToData?.content,
          replyToIv: replyToData?.iv,
          replyToSenderName: replyToData?.senderName,
          created_at: new Date().toISOString()
        });

        members.forEach(member => {
          const client = clients.get(member.user_id);
          if (client && client.readyState === WebSocket.OPEN) {
            client.send(payload);
          }
        });
      }

      if (message.type === "typing") {
        const { groupId, userId, username, isTyping } = message;
        const members = db.prepare("SELECT user_id FROM group_members WHERE group_id = ?").all(groupId) as any[];
        
        const payload = JSON.stringify({
          type: "typing",
          groupId,
          userId,
          username,
          isTyping
        });

        members.forEach(member => {
          if (member.user_id !== userId) {
            const client = clients.get(member.user_id);
            if (client && client.readyState === WebSocket.OPEN) {
              client.send(payload);
            }
          }
        });
      }
      if (message.type === "reaction") {
        const { groupId, messageId, userId, username, emoji, action } = message;
        const members = db.prepare("SELECT user_id FROM group_members WHERE group_id = ?").all(groupId) as any[];
        
        const payload = JSON.stringify({
          type: "reaction",
          groupId,
          messageId,
          userId,
          username,
          emoji,
          action
        });

        members.forEach(member => {
          const client = clients.get(member.user_id);
          if (client && client.readyState === WebSocket.OPEN) {
            client.send(payload);
          }
        });
      }
    });

    ws.on("close", () => {
      if (currentUserId) clients.delete(currentUserId);
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
