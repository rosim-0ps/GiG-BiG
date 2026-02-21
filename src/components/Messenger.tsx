import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  generateIdentityKeyPair, 
  exportPublicKey, 
  importPublicKey, 
  generateGroupKey, 
  encryptGroupKey, 
  decryptGroupKey, 
  encryptMessage, 
  decryptMessage,
  importGroupKey,
  exportGroupKey,
  exportIdentityPrivateKey,
  importIdentityPrivateKey,
  encryptGroupKeyWithSecret,
  decryptGroupKeyWithSecret
} from '../lib/crypto';
import { Shield, Users, MessageSquare, Send, Plus, Lock, UserPlus, LogOut, Link, Copy, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface User {
  id: string;
  username: string;
  public_key: string;
}

interface Group {
  id: string;
  name: string;
  encrypted_group_key: string;
}

interface Message {
  id: string;
  groupId: string;
  senderId: string;
  senderName: string;
  content: string;
  iv: string;
  created_at: string;
  decryptedContent?: string;
}

export default function Messenger() {
  const [user, setUser] = useState<User | null>(null);
  const [usernameInput, setUsernameInput] = useState('');
  const [groups, setGroups] = useState<Group[]>([]);
  const [activeGroup, setActiveGroup] = useState<Group | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [newMessage, setNewMessage] = useState('');
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [showAddMember, setShowAddMember] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [groupSearchQuery, setGroupSearchQuery] = useState('');
  const [showUserSearch, setShowUserSearch] = useState(false);
  const [inviteLink, setInviteLink] = useState('');
  const [copied, setCopied] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [pendingInvite, setPendingInvite] = useState<{ token: string, secret: string, groupName: string } | null>(null);
  
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const groupKeysRef = useRef<Map<string, CryptoKey>>(new Map());
  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // On mount, check for existing user and pending invites
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('invite');
    const secret = window.location.hash.slice(1);

    if (token && secret) {
      fetch(`/api/invites/${token}`)
        .then(res => res.json())
        .then(data => {
          if (data.group_name) {
            setPendingInvite({ token, secret, groupName: data.group_name });
          }
        });
    }

    const savedUser = localStorage.getItem('gig_big_user');
    if (savedUser) {
      const parsed = JSON.parse(savedUser);
      importIdentityPrivateKey(parsed.privateKey).then(key => {
        privateKeyRef.current = key;
        setUser(parsed);
        fetchGroups(parsed.id);
        fetchAllUsers(parsed.id);
      }).catch(err => {
        console.error("Failed to restore session", err);
        localStorage.removeItem('gig_big_user');
      });
    }
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Initialize WebSocket
  useEffect(() => {
    if (user) {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${protocol}//${window.location.host}`);
      
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'auth', userId: user.id }));
      };

      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'chat') {
          const groupKey = groupKeysRef.current.get(data.groupId);
          if (groupKey) {
            try {
              const decrypted = await decryptMessage(data.content, data.iv, groupKey);
              setMessages(prev => [...prev, { ...data, decryptedContent: decrypted }]);
            } catch (e) {
              console.error("Failed to decrypt message", e);
            }
          }
        }
      };

      wsRef.current = ws;
      return () => ws.close();
    }
  }, [user]);

  const handleRegister = async () => {
    if (!usernameInput) return;
    const keyPair = await generateIdentityKeyPair();
    privateKeyRef.current = keyPair.privateKey;
    const publicKey = await exportPublicKey(keyPair.publicKey);

    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameInput, publicKey }),
    });
    const userData = await res.json();
    setUser(userData);
    localStorage.setItem('gig_big_user', JSON.stringify({ 
      ...userData, 
      privateKey: await exportIdentityPrivateKey(keyPair.privateKey) 
    }));
    
    // Fetch initial data
    fetchGroups(userData.id);
    fetchAllUsers(userData.id);
  };

  const fetchGroups = async (userId: string) => {
    const res = await fetch(`/api/groups/${userId}`);
    const data = await res.json();
    setGroups(data);
    
    // Decrypt group keys
    for (const group of data) {
      if (privateKeyRef.current) {
        const key = await decryptGroupKey(group.encrypted_group_key, privateKeyRef.current);
        groupKeysRef.current.set(group.id, key);
      }
    }
  };

  const fetchAllUsers = async (currentUserId?: string) => {
    const res = await fetch('/api/users');
    const data = await res.json();
    const idToFilter = currentUserId || user?.id;
    setAllUsers(data.filter((u: User) => u.id !== idToFilter));
  };

  const handleCreateGroup = async () => {
    if (!newGroupName || !user || !privateKeyRef.current) return;
    
    const groupKey = await generateGroupKey();
    const myPublicKey = await importPublicKey(user.public_key);
    const encryptedKey = await encryptGroupKey(groupKey, myPublicKey);

    const res = await fetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newGroupName,
        createdBy: user.id,
        encryptedGroupKey: encryptedKey
      }),
    });

    if (!res.ok) {
      const errorData = await res.json();
      alert(errorData.error || "Failed to create group");
      return;
    }

    const newGroup = await res.json();
    groupKeysRef.current.set(newGroup.id, groupKey);
    setGroups(prev => [...prev, { ...newGroup, encrypted_group_key: encryptedKey }]);
    setNewGroupName('');
    setShowCreateGroup(false);
    setActiveGroup(newGroup);
  };

  const handleAddMember = async (targetUser: User) => {
    if (!activeGroup || !user) return;
    const groupKey = groupKeysRef.current.get(activeGroup.id);
    if (!groupKey) return;

    const targetPublicKey = await importPublicKey(targetUser.public_key);
    const encryptedKey = await encryptGroupKey(groupKey, targetPublicKey);

    await fetch(`/api/groups/${activeGroup.id}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: targetUser.id,
        encryptedGroupKey: encryptedKey
      }),
    });
    setShowAddMember(false);
    setUserSearchQuery('');
    fetchGroupMembers(activeGroup.id);
  };

  const handleStartDM = async (targetUser: User) => {
    if (!user || !privateKeyRef.current) return;
    
    // 1. Generate group key for the DM
    const groupKey = await generateGroupKey();
    
    // 2. Encrypt for me
    const myPublicKey = await importPublicKey(user.public_key);
    const myEncryptedKey = await encryptGroupKey(groupKey, myPublicKey);

    // 3. Create the group
    const res = await fetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `DM: ${targetUser.username} (${user.username})`, // Make it more unique
        createdBy: user.id,
        encryptedGroupKey: myEncryptedKey
      }),
    });

    if (!res.ok) {
      // If it fails, maybe it already exists, let's just find it in the list
      const existing = groups.find(g => g.name === `DM: ${targetUser.username} (${user.username})`);
      if (existing) {
        selectGroup(existing);
        setShowUserSearch(false);
        setUserSearchQuery('');
        return;
      }
      const errorData = await res.json();
      alert(errorData.error || "Failed to start DM");
      return;
    }

    const newGroup = await res.json();
    
    // 4. Encrypt for target user and add them
    const targetPublicKey = await importPublicKey(targetUser.public_key);
    const targetEncryptedKey = await encryptGroupKey(groupKey, targetPublicKey);

    await fetch(`/api/groups/${newGroup.id}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: targetUser.id,
        encryptedGroupKey: targetEncryptedKey
      }),
    });

    // 5. Update state
    groupKeysRef.current.set(newGroup.id, groupKey);
    setGroups(prev => [...prev, { ...newGroup, encrypted_group_key: myEncryptedKey }]);
    setShowUserSearch(false);
    setUserSearchQuery('');
    selectGroup(newGroup);
  };

  const filteredUsers = allUsers.filter(u => 
    u.username.toLowerCase().includes(userSearchQuery.toLowerCase())
  );

  const filteredGroups = groups.filter(g => 
    g.name.toLowerCase().includes(groupSearchQuery.toLowerCase())
  );

  const sendMessage = async () => {
    if (!newMessage || !activeGroup || !user || !wsRef.current) return;
    const groupKey = groupKeysRef.current.get(activeGroup.id);
    if (!groupKey) return;

    const encrypted = await encryptMessage(newMessage, groupKey);
    
    wsRef.current.send(JSON.stringify({
      type: 'chat',
      groupId: activeGroup.id,
      senderId: user.id,
      content: encrypted.content,
      iv: encrypted.iv
    }));

    setNewMessage('');
  };

  const [showMembers, setShowMembers] = useState(false);
  const [groupMembers, setGroupMembers] = useState<any[]>([]);

  const fetchGroupMembers = async (groupId: string) => {
    const res = await fetch(`/api/groups/${groupId}/members`);
    const data = await res.json();
    setGroupMembers(data);
  };

  const handleRemoveMember = async (targetUserId: string) => {
    if (!activeGroup || !user) return;
    
    // 1. Remove member from DB
    await fetch(`/api/groups/${activeGroup.id}/members/${targetUserId}`, { method: 'DELETE' });
    
    // 2. Re-key the group for security
    const newGroupKey = await generateGroupKey();
    const remainingMembers = groupMembers.filter(m => m.user_id !== targetUserId);
    
    const memberKeys = await Promise.all(remainingMembers.map(async (m) => {
      const pubKey = await importPublicKey(m.public_key);
      const encKey = await encryptGroupKey(newGroupKey, pubKey);
      return { userId: m.user_id, encryptedGroupKey: encKey };
    }));

    await fetch(`/api/groups/${activeGroup.id}/rekey`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ memberKeys }),
    });

    // 3. Update local state
    groupKeysRef.current.set(activeGroup.id, newGroupKey);
    fetchGroupMembers(activeGroup.id);
    
    // Notify others via WS (optional, but good for real-time re-keying)
    wsRef.current?.send(JSON.stringify({
      type: 'chat',
      groupId: activeGroup.id,
      senderId: user.id,
      content: btoa(String.fromCharCode(...new TextEncoder().encode("SYSTEM: Group has been re-keyed for security."))),
      iv: btoa(String.fromCharCode(...window.crypto.getRandomValues(new Uint8Array(12))))
    }));
  };

  const handleGenerateInvite = async () => {
    if (!activeGroup || !user) return;
    const groupKey = groupKeysRef.current.get(activeGroup.id);
    if (!groupKey) return;

    const secret = btoa(String.fromCharCode(...window.crypto.getRandomValues(new Uint8Array(16))));
    const encrypted = await encryptGroupKeyWithSecret(groupKey, secret);

    const res = await fetch(`/api/groups/${activeGroup.id}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryptedGroupKey: JSON.stringify(encrypted)
      }),
    });
    const { token } = await res.json();
    const link = `${window.location.origin}${window.location.pathname}?invite=${token}#${secret}`;
    setInviteLink(link);
    setShowInviteModal(true);
  };

  const handleJoinByInvite = async () => {
    if (!pendingInvite || !user || !privateKeyRef.current) return;

    try {
      const res = await fetch(`/api/invites/${pendingInvite.token}`);
      const inviteData = await res.json();
      const { encryptedKey, iv } = JSON.parse(inviteData.encrypted_group_key);
      
      const groupKey = await decryptGroupKeyWithSecret(encryptedKey, iv, pendingInvite.secret);
      const myPublicKey = await importPublicKey(user.public_key);
      const myEncryptedKey = await encryptGroupKey(groupKey, myPublicKey);

      const joinRes = await fetch(`/api/invites/${pendingInvite.token}/join`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: user.id,
          encryptedGroupKey: myEncryptedKey
        }),
      });
      const joinData = await joinRes.json();
      
      if (joinData.success) {
        groupKeysRef.current.set(joinData.groupId, groupKey);
        fetchGroups(user.id);
        setPendingInvite(null);
        window.history.replaceState({}, '', window.location.pathname);
      }
    } catch (e) {
      console.error("Failed to join by invite", e);
      alert("Invalid or expired invite link.");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('gig_big_user');
    setUser(null);
    setGroups([]);
    setActiveGroup(null);
    privateKeyRef.current = null;
    groupKeysRef.current.clear();
    if (wsRef.current) wsRef.current.close();
  };

  const selectGroup = async (group: Group) => {
    setActiveGroup(group);
    fetchGroupMembers(group.id);
    const res = await fetch(`/api/groups/${group.id}/messages`);
    const data = await res.json();
    
    const groupKey = groupKeysRef.current.get(group.id);
    const decryptedMessages = await Promise.all(data.map(async (m: any) => {
      if (groupKey) {
        try {
          const decrypted = await decryptMessage(m.content, m.iv, groupKey);
          return { ...m, decryptedContent: decrypted };
        } catch (e) {
          return { ...m, decryptedContent: "[Decryption Failed]" };
        }
      }
      return m;
    }));
    
    setMessages(decryptedMessages);
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-[#E4E3E0] flex items-center justify-center p-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-md w-full bg-white p-8 rounded-2xl shadow-xl border border-black/5"
        >
          <div className="flex justify-center mb-6">
            <div className="w-16 h-16 bg-black rounded-2xl flex items-center justify-center">
              <Shield className="text-white w-8 h-8" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-center mb-2 tracking-tight">GiG BiG</h1>
          <p className="text-center text-gray-500 mb-8 italic serif">Trust Your Message.</p>
          
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Username</label>
              <input 
                type="text" 
                value={usernameInput}
                onChange={(e) => setUsernameInput(e.target.value)}
                className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all"
                placeholder="Enter your handle..."
              />
            </div>
            <button 
              onClick={handleRegister}
              className="w-full py-3 bg-black text-white rounded-xl font-semibold hover:bg-gray-800 transition-colors flex items-center justify-center gap-2"
            >
              Initialize Identity <Lock size={18} />
            </button>
          </div>
          <p className="mt-6 text-[10px] text-gray-400 text-center uppercase tracking-widest leading-relaxed">
            End-to-End Encrypted • Peer-to-Peer Key Exchange • Zero-Knowledge Storage
          </p>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#E4E3E0] flex flex-col md:flex-row h-screen overflow-hidden">
      {/* Sidebar */}
      <div className="w-full md:w-80 bg-white border-r border-black/10 flex flex-col">
        <div className="p-6 border-bottom border-black/5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-black rounded-xl flex items-center justify-center">
              <Shield className="text-white w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold tracking-tight">GiG BiG</h2>
              <p className="text-[10px] uppercase tracking-widest text-emerald-500 font-bold">Secure Session</p>
            </div>
          </div>
          <button onClick={handleLogout} className="text-gray-400 hover:text-black transition-colors">
            <LogOut size={18} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <div className="flex items-center justify-between mb-4 px-2">
            <span className="text-[11px] font-bold uppercase tracking-widest text-gray-400">Encrypted Groups</span>
            <div className="flex items-center gap-1">
              <button 
                onClick={() => {
                  if (user) fetchAllUsers(user.id);
                  setShowUserSearch(true);
                }}
                className="p-1 hover:bg-gray-100 rounded-lg transition-colors text-gray-400 hover:text-black"
                title="New Direct Message"
              >
                <MessageSquare size={18} />
              </button>
              <button 
                onClick={() => setShowCreateGroup(true)}
                className="p-1 hover:bg-gray-100 rounded-lg transition-colors text-gray-400 hover:text-black"
                title="New Group"
              >
                <Plus size={18} />
              </button>
            </div>
          </div>

          <div className="px-2 mb-4">
            <div className="relative">
              <input 
                type="text" 
                value={groupSearchQuery}
                onChange={(e) => setGroupSearchQuery(e.target.value)}
                placeholder="Search groups..."
                className="w-full pl-8 pr-3 py-2 bg-gray-50 border border-black/5 rounded-lg text-xs focus:outline-none focus:ring-1 focus:ring-black/10 transition-all"
              />
              <Users size={14} className="absolute left-2.5 top-2.5 text-gray-400" />
            </div>
          </div>

          {filteredGroups.map(group => (
            <button
              key={group.id}
              onClick={() => selectGroup(group)}
              className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all ${
                activeGroup?.id === group.id ? 'bg-black text-white' : 'hover:bg-gray-50 text-gray-600'
              }`}
            >
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                activeGroup?.id === group.id ? 'bg-white/10' : 'bg-gray-100'
              }`}>
                <Users size={18} />
              </div>
              <div className="text-left">
                <p className="font-semibold text-sm truncate">{group.name}</p>
                <p className={`text-[10px] uppercase tracking-tighter ${
                  activeGroup?.id === group.id ? 'text-white/50' : 'text-gray-400'
                }`}>E2EE Active</p>
              </div>
            </button>
          ))}
        </div>

        <div className="p-4 bg-gray-50 border-t border-black/5">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-emerald-500 rounded-full flex items-center justify-center text-white text-xs font-bold">
              {user.username[0].toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-bold truncate">{user.username}</p>
              <p className="text-[10px] text-gray-400 truncate font-mono">{user.id.slice(0, 8)}...</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-[#F5F5F4]">
        {activeGroup ? (
          <>
            <div className="h-16 bg-white border-b border-black/5 px-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Users size={20} className="text-gray-400" />
                <h3 className="font-bold tracking-tight">{activeGroup.name}</h3>
                <div className="flex items-center gap-1 px-2 py-0.5 bg-emerald-50 text-emerald-600 rounded-full">
                  <Lock size={10} />
                  <span className="text-[9px] font-bold uppercase tracking-widest">End-to-End Encrypted</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => {
                    fetchGroupMembers(activeGroup.id);
                    setShowMembers(true);
                  }}
                  className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-xs font-bold"
                >
                  <Users size={14} /> Members ({groupMembers.length})
                </button>
                <button 
                  onClick={() => {
                    if (user) fetchAllUsers(user.id);
                    setShowAddMember(true);
                  }}
                  className="flex items-center gap-2 px-3 py-1.5 bg-black text-white hover:bg-gray-800 rounded-lg transition-colors text-xs font-bold"
                >
                  <UserPlus size={14} /> Add
                </button>
                <button 
                  onClick={handleGenerateInvite}
                  className="p-1.5 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-gray-600"
                  title="Generate Invite Link"
                >
                  <Link size={16} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <AnimatePresence initial={false}>
                {messages.map((msg) => (
                  <motion.div
                    key={msg.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`flex flex-col ${msg.senderId === user.id ? 'items-end' : 'items-start'}`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
                        {msg.senderId === user.id ? 'You' : msg.senderName}
                      </span>
                      <span className="text-[9px] font-mono text-gray-300">
                        {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <div className={`max-w-[80%] px-4 py-2.5 rounded-2xl text-sm shadow-sm ${
                      msg.senderId === user.id 
                        ? 'bg-black text-white rounded-tr-none' 
                        : 'bg-white text-gray-800 rounded-tl-none border border-black/5'
                    }`}>
                      {msg.decryptedContent}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              <div ref={messagesEndRef} />
            </div>

            <div className="p-6 bg-white border-t border-black/5">
              <div className="relative flex items-center">
                <input
                  type="text"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                  placeholder="Type an encrypted message..."
                  className="w-full pl-4 pr-12 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all text-sm"
                />
                <button 
                  onClick={sendMessage}
                  className="absolute right-2 p-2 bg-black text-white rounded-lg hover:bg-gray-800 transition-colors"
                >
                  <Send size={18} />
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
            <div className="w-20 h-20 bg-gray-100 rounded-3xl flex items-center justify-center mb-6">
              <MessageSquare className="text-gray-300 w-10 h-10" />
            </div>
            <h3 className="text-xl font-bold tracking-tight mb-2">Select a secure channel</h3>
            <p className="text-gray-400 text-sm max-w-xs serif italic">
              All communications are encrypted locally before transmission. No plaintext ever touches our servers.
            </p>
          </div>
        )}
      </div>

      {/* Modals */}
      <AnimatePresence>
        {showCreateGroup && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-sm w-full"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Create Secure Group</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1">Group Name</label>
                  <input 
                    type="text" 
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none"
                    placeholder="e.g. Project Alpha"
                  />
                </div>
                <div className="flex gap-3">
                  <button 
                    onClick={() => setShowCreateGroup(false)}
                    className="flex-1 py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleCreateGroup}
                    className="flex-1 py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
                  >
                    Create
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}

        {showMembers && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full max-h-[80vh] flex flex-col"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Group Members</h3>
              <div className="flex-1 overflow-y-auto space-y-2 mb-6">
                {groupMembers.map(m => (
                  <div
                    key={m.user_id}
                    className="w-full flex items-center justify-between p-4 bg-gray-50 rounded-xl border border-black/5"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-black rounded-full flex items-center justify-center font-bold text-white text-xs">
                        {m.username[0].toUpperCase()}
                      </div>
                      <div className="text-left">
                        <p className="font-bold text-sm">{m.username} {m.role === 'admin' && <span className="text-[9px] bg-black text-white px-1.5 py-0.5 rounded ml-1">ADMIN</span>}</p>
                        <p className="text-[10px] font-mono text-gray-400">{m.user_id.slice(0, 12)}...</p>
                      </div>
                    </div>
                    {m.user_id !== user.id && (
                      <button 
                        onClick={() => handleRemoveMember(m.user_id)}
                        className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                        title="Remove and Re-key"
                      >
                        <LogOut size={18} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <button 
                onClick={() => setShowMembers(false)}
                className="w-full py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
              >
                Close
              </button>
            </motion.div>
          </div>
        )}

        {showAddMember && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full max-h-[80vh] flex flex-col"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Invite to {activeGroup?.name}</h3>
              
              <div className="mb-4">
                <input 
                  type="text" 
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none text-sm"
                  placeholder="Search users..."
                />
              </div>

              <div className="flex-1 overflow-y-auto space-y-2 mb-6">
                {filteredUsers.length > 0 ? filteredUsers.map(u => (
                  <button
                    key={u.id}
                    onClick={() => handleAddMember(u)}
                    className="w-full flex items-center justify-between p-4 hover:bg-gray-50 rounded-xl border border-transparent hover:border-black/5 transition-all"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center font-bold text-gray-400">
                        {u.username[0].toUpperCase()}
                      </div>
                      <div className="text-left">
                        <p className="font-bold text-sm">{u.username}</p>
                        <p className="text-[10px] font-mono text-gray-400">{u.id.slice(0, 12)}...</p>
                      </div>
                    </div>
                    <UserPlus size={18} className="text-gray-300" />
                  </button>
                )) : (
                  <p className="text-center text-gray-400 py-8 italic serif">No other users found on the network.</p>
                )}
              </div>
              <button 
                onClick={() => {
                  setShowAddMember(false);
                  setUserSearchQuery('');
                }}
                className="w-full py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
              >
                Close
              </button>
            </motion.div>
          </div>
        )}

        {showUserSearch && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full max-h-[80vh] flex flex-col"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">New Direct Message</h3>
              
              <div className="mb-4">
                <input 
                  type="text" 
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none text-sm"
                  placeholder="Search users by handle..."
                />
              </div>

              <div className="flex-1 overflow-y-auto space-y-2 mb-6">
                {filteredUsers.length > 0 ? filteredUsers.map(u => (
                  <button
                    key={u.id}
                    onClick={() => handleStartDM(u)}
                    className="w-full flex items-center justify-between p-4 hover:bg-gray-50 rounded-xl border border-transparent hover:border-black/5 transition-all"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-emerald-100 rounded-full flex items-center justify-center font-bold text-emerald-600 text-xs">
                        {u.username[0].toUpperCase()}
                      </div>
                      <div className="text-left">
                        <p className="font-bold text-sm">{u.username}</p>
                        <p className="text-[10px] font-mono text-gray-400">{u.id.slice(0, 12)}...</p>
                      </div>
                    </div>
                    <Send size={18} className="text-gray-300" />
                  </button>
                )) : (
                  <p className="text-center text-gray-400 py-8 italic serif">
                    {userSearchQuery ? "No matching users found." : "Search for a user to start a secure DM."}
                  </p>
                )}
              </div>
              <button 
                onClick={() => {
                  setShowUserSearch(false);
                  setUserSearchQuery('');
                }}
                className="w-full py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
              >
                Close
              </button>
            </motion.div>
          </div>
        )}

        {showInviteModal && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Group Invite Link</h3>
              <p className="text-sm text-gray-500 mb-6 italic serif">
                Anyone with this link can join the group and access the shared encryption key. Share it securely.
              </p>
              
              <div className="flex items-center gap-2 p-3 bg-gray-50 border border-black/5 rounded-xl mb-6">
                <input 
                  type="text" 
                  readOnly 
                  value={inviteLink}
                  className="flex-1 bg-transparent border-none focus:outline-none text-xs font-mono truncate"
                />
                <button 
                  onClick={() => {
                    navigator.clipboard.writeText(inviteLink);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="p-2 hover:bg-gray-200 rounded-lg transition-colors text-gray-600"
                >
                  {copied ? <Check size={18} className="text-emerald-500" /> : <Copy size={18} />}
                </button>
              </div>

              <button 
                onClick={() => setShowInviteModal(false)}
                className="w-full py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
              >
                Done
              </button>
            </motion.div>
          </div>
        )}

        {pendingInvite && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-sm w-full text-center"
            >
              <div className="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Users className="text-emerald-600 w-8 h-8" />
              </div>
              <h3 className="text-xl font-bold mb-2 tracking-tight">Join Group?</h3>
              <p className="text-sm text-gray-500 mb-6">
                You've been invited to join <span className="font-bold text-black">{pendingInvite.groupName}</span>.
              </p>
              
              <div className="flex gap-3">
                <button 
                  onClick={() => {
                    setPendingInvite(null);
                    window.history.replaceState({}, '', window.location.pathname);
                  }}
                  className="flex-1 py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                >
                  Decline
                </button>
                <button 
                  onClick={handleJoinByInvite}
                  className="flex-1 py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
                >
                  Join Group
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
