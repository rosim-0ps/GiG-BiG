import { useState, useEffect, useCallback, useRef, ChangeEvent } from 'react';
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
  decryptGroupKeyWithSecret,
  encryptPrivateKeyWithPassword,
  decryptPrivateKeyWithPassword,
  uint8ArrayToBase64
} from '../lib/crypto';
import { Shield, Users, MessageSquare, Send, Plus, Lock, UserPlus, LogOut, Link, Copy, Check, Reply, X, Settings, User as UserIcon, RefreshCw } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import Logo from './Logo';
import AnimatedLock from './AnimatedLock';
import TypewriterText from './TypewriterText';

interface User {
  id: string;
  username: string;
  public_key: string;
}

interface Group {
  id: string;
  name: string;
  encrypted_group_key: string;
  last_message_content?: string;
  last_message_iv?: string;
  last_message_decrypted?: string;
  unread_count: number;
}

interface Reaction {
  id: string;
  user_id: string;
  username: string;
  emoji: string;
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
  replyToId?: string;
  replyToContent?: string;
  replyToIv?: string;
  replyToSenderName?: string;
  decryptedReplyContent?: string;
  reactions?: Reaction[];
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
  const [showInviteConfig, setShowInviteConfig] = useState(false);
  const [inviteExpiration, setInviteExpiration] = useState('1h');
  const [pendingInvite, setPendingInvite] = useState<{ token: string, secret: string, groupName: string } | null>(null);
  const [undoLeave, setUndoLeave] = useState<{ groupId: string, groupName: string, timer: any } | null>(null);
  const [typingUsers, setTypingUsers] = useState<Record<string, string[]>>({});
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [showProfile, setShowProfile] = useState(false);
  const [profileUsername, setProfileUsername] = useState('');
  const [isRotating, setIsRotating] = useState(false);
  const [registerError, setRegisterError] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [confirmPasswordInput, setConfirmPasswordInput] = useState('');
  const [authMode, setAuthMode] = useState<'login' | 'register' | 'verify'>('login');
  const [verificationToken, setVerificationToken] = useState('');
  const [verificationMessage, setVerificationMessage] = useState('');
  
  const [showUserIds, setShowUserIds] = useState(() => localStorage.getItem('gig_show_ids') === 'true');
  const [notificationsEnabled, setNotificationsEnabled] = useState(() => localStorage.getItem('gig_notifications') !== 'false');
  const [soundEnabled, setSoundEnabled] = useState(() => localStorage.getItem('gig_sound') !== 'false');
  const [showGroupSettings, setShowGroupSettings] = useState(false);
  const [messageSearchQuery, setMessageSearchQuery] = useState('');
  
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const groupKeysRef = useRef<Map<string, CryptoKey>>(new Map());
  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const activeGroupRef = useRef<Group | null>(null);
  const typingTimeoutRef = useRef<any>(null);

  useEffect(() => {
    activeGroupRef.current = activeGroup;
  }, [activeGroup]);

  // On mount, check for existing user and pending invites
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('invite');
    const secret = window.location.hash.slice(1);
    const vToken = params.get('verify');

    if (vToken) {
      setAuthMode('verify');
      setVerificationToken(vToken);
    }

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
              let decryptedReply = undefined;
              if (data.replyToContent && data.replyToIv) {
                try {
                  decryptedReply = await decryptMessage(data.replyToContent, data.replyToIv, groupKey);
                } catch (e) {
                  decryptedReply = "[Encrypted Reply]";
                }
              }
              
              // If this is the active group, add to messages
              if (activeGroupRef.current?.id === data.groupId) {
                setMessages(prev => [...prev, { ...data, decryptedContent: decrypted, decryptedReplyContent: decryptedReply }]);
                // Mark as read on server
                fetch(`/api/groups/${data.groupId}/read`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ userId: user.id })
                });
              } else {
                // Play sound/vibrate if notifications enabled
                const notificationsEnabled = localStorage.getItem('gig_notifications') !== 'false';
                const soundEnabled = localStorage.getItem('gig_sound') !== 'false';
                
                if (notificationsEnabled) {
                  if (soundEnabled) {
                    try {
                      // A simple beep using Web Audio API
                      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
                      const osc = ctx.createOscillator();
                      osc.type = 'sine';
                      osc.frequency.setValueAtTime(880, ctx.currentTime);
                      osc.connect(ctx.destination);
                      osc.start();
                      osc.stop(ctx.currentTime + 0.1);
                    } catch (e) {}
                  }
                  if (navigator.vibrate) {
                    navigator.vibrate(200);
                  }
                }
              }
              
              // Update groups list (last message and unread count)
              setGroups(prev => prev.map(g => {
                if (g.id === data.groupId) {
                  return { 
                    ...g, 
                    last_message_decrypted: decrypted,
                    unread_count: activeGroupRef.current?.id === data.groupId ? 0 : (g.unread_count || 0) + 1
                  };
                }
                return g;
              }));
            } catch (e) {
              console.error("Failed to decrypt message", e);
            }
          }
        } else if (data.type === 'typing') {
          setTypingUsers(prev => {
            const groupTyping = prev[data.groupId] || [];
            if (data.isTyping) {
              if (!groupTyping.includes(data.username)) {
                return { ...prev, [data.groupId]: [...groupTyping, data.username] };
              }
            } else {
              return { ...prev, [data.groupId]: groupTyping.filter(u => u !== data.username) };
            }
            return prev;
          });
        } else if (data.type === 'reaction') {
          if (activeGroupRef.current?.id === data.groupId) {
            setMessages(prev => prev.map(m => {
              if (m.id === data.messageId) {
                const reactions = m.reactions || [];
                if (data.action === 'added') {
                  return { ...m, reactions: [...reactions, { id: data.id || Date.now().toString(), user_id: data.userId, username: data.username, emoji: data.emoji }] };
                } else {
                  return { ...m, reactions: reactions.filter(r => !(r.user_id === data.userId && r.emoji === data.emoji)) };
                }
              }
              return m;
            }));
          }
        }
      };

      wsRef.current = ws;
      return () => ws.close();
    }
  }, [user]);

  const handleRegister = async () => {
    if (!usernameInput || !emailInput) return;
    setRegisterError('');

    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameInput, email: emailInput }),
    });
    
    if (!res.ok) {
      const errorData = await res.json();
      setRegisterError(errorData.error || 'Registration failed');
      return;
    }
    
    const data = await res.json();
    setVerificationMessage(`In a real app, a verification link would be emailed to ${data.email}. For this demo, we've automatically verified your email and moved you to the next step.`);
    setVerificationToken(data.verification_token);
    setAuthMode('verify');
  };

  const handleVerify = async () => {
    if (!passwordInput || passwordInput !== confirmPasswordInput) {
      setRegisterError("Passwords do not match");
      return;
    }
    setRegisterError('');

    const keyPair = await generateIdentityKeyPair();
    privateKeyRef.current = keyPair.privateKey;
    const publicKey = await exportPublicKey(keyPair.publicKey);
    
    const encryptedPrivKey = await encryptPrivateKeyWithPassword(keyPair.privateKey, passwordInput);

    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        token: verificationToken, 
        password: passwordInput,
        publicKey,
        encryptedPrivateKey: encryptedPrivKey.encryptedKey,
        privateKeyIv: encryptedPrivKey.iv
      }),
    });

    if (!res.ok) {
      const errorData = await res.json();
      setRegisterError(errorData.error || 'Verification failed');
      return;
    }

    setAuthMode('login');
    setVerificationMessage('Account verified successfully. Please log in.');
    setVerificationToken('');
    setPasswordInput('');
    setConfirmPasswordInput('');
    
    // Remove verify token from URL
    const url = new URL(window.location.href);
    url.searchParams.delete('verify');
    window.history.replaceState({}, '', url.toString());
  };

  const handleLogin = async () => {
    if (!usernameInput || !passwordInput) return;
    setRegisterError('');

    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameInput, password: passwordInput }),
    });

    if (!res.ok) {
      const errorData = await res.json();
      setRegisterError(errorData.error || 'Login failed');
      return;
    }

    const userData = await res.json();
    
    try {
      const privateKey = await decryptPrivateKeyWithPassword(userData.encrypted_private_key, userData.private_key_iv, passwordInput);
      privateKeyRef.current = privateKey;
      
      setUser(userData);
      localStorage.setItem('gig_big_user', JSON.stringify({ 
        ...userData, 
        privateKey: await exportIdentityPrivateKey(privateKey) 
      }));
      
      fetchGroups(userData.id);
      fetchAllUsers(userData.id);
    } catch (e) {
      setRegisterError('Failed to decrypt identity. Incorrect password?');
    }
  };

  const fetchGroups = async (userId: string) => {
    const res = await fetch(`/api/groups/${userId}`);
    const data = await res.json();
    
    // Decrypt group keys and last messages
    const processedGroups = await Promise.all(data.map(async (group: Group) => {
      if (privateKeyRef.current) {
        try {
          const key = await decryptGroupKey(group.encrypted_group_key, privateKeyRef.current);
          groupKeysRef.current.set(group.id, key);
          
          let decryptedSnippet = undefined;
          if (group.last_message_content && group.last_message_iv) {
            try {
              decryptedSnippet = await decryptMessage(group.last_message_content, group.last_message_iv, key);
            } catch (e) {
              decryptedSnippet = "[Encrypted]";
            }
          }
          
          return { ...group, last_message_decrypted: decryptedSnippet, unread_count: group.unread_count || 0 };
        } catch (e) {
          console.error("Failed to decrypt group key", e);
        }
      }
      return { ...group, unread_count: group.unread_count || 0 };
    }));

    setGroups(processedGroups);
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

  const handleReaction = async (messageId: string, emoji: string) => {
    if (!user || !activeGroup) return;
    try {
      const res = await fetch(`/api/messages/${messageId}/reactions/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id, emoji })
      });
      if (res.ok) {
        const data = await res.json();
        // Send via websocket
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({
            type: 'reaction',
            groupId: activeGroup.id,
            messageId,
            userId: user.id,
            username: user.username,
            emoji,
            action: data.action,
            id: data.id
          }));
        }
      }
    } catch (e) {
      console.error("Failed to toggle reaction", e);
    }
  };

  const handleTyping = (e: ChangeEvent<HTMLInputElement>) => {
    setNewMessage(e.target.value);
    
    if (!activeGroup || !user || !wsRef.current) return;

    // Send typing start
    wsRef.current.send(JSON.stringify({
      type: 'typing',
      groupId: activeGroup.id,
      userId: user.id,
      username: user.username,
      isTyping: true
    }));

    // Clear existing timeout
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);

    // Set timeout to send typing stop
    typingTimeoutRef.current = setTimeout(() => {
      wsRef.current?.send(JSON.stringify({
        type: 'typing',
        groupId: activeGroup.id,
        userId: user.id,
        username: user.username,
        isTyping: false
      }));
    }, 3000);
  };

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
      iv: encrypted.iv,
      replyToId: replyingTo?.id
    }));

    setNewMessage('');
    setReplyingTo(null);
    
    // Clear typing status
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
    wsRef.current.send(JSON.stringify({
      type: 'typing',
      groupId: activeGroup.id,
      userId: user.id,
      username: user.username,
      isTyping: false
    }));
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
    const systemMsg = "SYSTEM: Group has been re-keyed for security.";
    const encryptedSystemMsg = await encryptMessage(systemMsg, newGroupKey);
    wsRef.current?.send(JSON.stringify({
      type: 'chat',
      groupId: activeGroup.id,
      senderId: user.id,
      content: encryptedSystemMsg.content,
      iv: encryptedSystemMsg.iv
    }));
  };

  const handleGenerateInvite = async () => {
    if (!activeGroup || !user) return;
    const groupKey = groupKeysRef.current.get(activeGroup.id);
    if (!groupKey) return;

    const secret = uint8ArrayToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
    const encrypted = await encryptGroupKeyWithSecret(groupKey, secret);

    let expiresAt: string | null = null;
    if (inviteExpiration !== 'never') {
      const now = new Date();
      if (inviteExpiration === '1h') now.setHours(now.getHours() + 1);
      else if (inviteExpiration === '1d') now.setDate(now.getDate() + 1);
      else if (inviteExpiration === '7d') now.setDate(now.getDate() + 7);
      expiresAt = now.toISOString().replace('T', ' ').split('.')[0]; // SQLite format
    }

    const res = await fetch(`/api/groups/${activeGroup.id}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encryptedGroupKey: JSON.stringify(encrypted),
        expiresAt
      }),
    });
    const { token } = await res.json();
    const link = `${window.location.origin}${window.location.pathname}?invite=${token}#${secret}`;
    setInviteLink(link);
    setShowInviteConfig(false);
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

  const handleLeaveGroup = async () => {
    if (!activeGroup || !user) return;
    
    // Clear any existing undo timer
    if (undoLeave) {
      clearTimeout(undoLeave.timer);
    }

    const groupId = activeGroup.id;
    const groupName = activeGroup.name;

    // 1. Optimistically remove from UI
    setGroups(prev => prev.filter(g => g.id !== groupId));
    setActiveGroup(null);
    setShowMembers(false);

    // 2. Set up undo timer
    const timer = setTimeout(async () => {
      try {
        // Fetch latest members to re-key correctly
        const membersRes = await fetch(`/api/groups/${groupId}/members`);
        const latestMembers = await membersRes.json();
        
        // Re-key for remaining members
        const newGroupKey = await generateGroupKey();
        const remainingMembers = latestMembers.filter((m: any) => m.user_id !== user.id);
        
        if (remainingMembers.length > 0) {
          const memberKeys = await Promise.all(remainingMembers.map(async (m: any) => {
            const pubKey = await importPublicKey(m.public_key);
            const encKey = await encryptGroupKey(newGroupKey, pubKey);
            return { userId: m.user_id, encryptedGroupKey: encKey };
          }));

          await fetch(`/api/groups/${groupId}/rekey`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ memberKeys }),
          });

          const systemMsg = `SYSTEM: ${user.username} has left the group. Group re-keyed.`;
          const encryptedSystemMsg = await encryptMessage(systemMsg, newGroupKey);

          wsRef.current?.send(JSON.stringify({
            type: 'chat',
            groupId: groupId,
            senderId: user.id,
            content: encryptedSystemMsg.content,
            iv: encryptedSystemMsg.iv
          }));
        }

        // Remove self from DB
        await fetch(`/api/groups/${groupId}/members/${user.id}`, { method: 'DELETE' });
        groupKeysRef.current.delete(groupId);
        setUndoLeave(null);
      } catch (e) {
        console.error("Delayed leave failed", e);
      }
    }, 5000);

    setUndoLeave({ groupId, groupName, timer });
  };

  const handleUndoLeave = () => {
    if (!undoLeave || !user) return;
    clearTimeout(undoLeave.timer);
    
    // Restore group to list
    fetchGroups(user.id);
    setUndoLeave(null);
  };

  const handleUpdateProfile = async () => {
    if (!user || !profileUsername) return;
    try {
      const res = await fetch(`/api/users/${user.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: profileUsername })
      });
      if (res.ok) {
        const updatedUser = { ...user, username: profileUsername };
        setUser(updatedUser);
        localStorage.setItem('gig_big_user', JSON.stringify(updatedUser));
        setShowProfile(false);
      }
    } catch (e) {
      console.error("Failed to update profile", e);
    }
  };

  const handleRotateIdentity = async () => {
    if (!user) return;
    
    const password = prompt("Please enter your password to secure your new identity keys:");
    if (!password) return;

    if (!confirm("WARNING: Rotating your identity will generate a new public/private key pair. You will NOT be able to read existing messages in your current groups until they are re-keyed for your new identity. Continue?")) return;

    setIsRotating(true);
    try {
      const { publicKey, privateKey } = await generateIdentityKeyPair();
      const pubKeyBase64 = await exportPublicKey(publicKey);
      const privKeyBase64 = await exportIdentityPrivateKey(privateKey);
      
      const encryptedPrivKey = await encryptPrivateKeyWithPassword(privateKey, password);

      const res = await fetch(`/api/users/${user.id}/keys`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          publicKey: pubKeyBase64,
          encryptedPrivateKey: encryptedPrivKey.encryptedKey,
          privateKeyIv: encryptedPrivKey.iv
        })
      });

      if (res.ok) {
        privateKeyRef.current = privateKey;
        const updatedUser = { 
          ...user, 
          publicKey: pubKeyBase64, 
          privateKey: privKeyBase64,
          encrypted_private_key: encryptedPrivKey.encryptedKey,
          private_key_iv: encryptedPrivKey.iv
        };
        setUser(updatedUser);
        localStorage.setItem('gig_big_user', JSON.stringify(updatedUser));
        alert("Identity rotated successfully. You may need to be re-invited to groups to read new messages.");
      }
    } catch (e) {
      console.error("Failed to rotate identity", e);
      alert("Failed to rotate identity. Please check your password and try again.");
    } finally {
      setIsRotating(false);
    }
  };

  const handleClearAllUnread = async () => {
    if (!user) return;
    if (!confirm("Are you sure you want to mark all messages in all groups as read?")) return;

    try {
      const res = await fetch(`/api/users/${user.id}/clear-unread`, {
        method: 'PUT'
      });
      if (res.ok) {
        fetchGroups(user.id);
      }
    } catch (e) {
      console.error("Failed to clear unread counts", e);
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
    
    // Mark as read
    if (user) {
      fetch(`/api/groups/${group.id}/read`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id })
      });
      setGroups(prev => prev.map(g => g.id === group.id ? { ...g, unread_count: 0 } : g));
    }

    const res = await fetch(`/api/groups/${group.id}/messages`);
    const data = await res.json();
    
    const groupKey = groupKeysRef.current.get(group.id);
    const decryptedMessages = await Promise.all(data.map(async (m: any) => {
      if (groupKey) {
        try {
          const decrypted = await decryptMessage(m.content, m.iv, groupKey);
          let decryptedReply = undefined;
          if (m.reply_to_content && m.reply_to_iv) {
            try {
              decryptedReply = await decryptMessage(m.reply_to_content, m.reply_to_iv, groupKey);
            } catch (e) {
              decryptedReply = "[Encrypted Reply]";
            }
          }
          return { 
            ...m, 
            decryptedContent: decrypted, 
            decryptedReplyContent: decryptedReply,
            replyToSenderName: m.reply_to_sender_name 
          };
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
            <div className="w-20 h-20 bg-black rounded-3xl flex items-center justify-center shadow-2xl shadow-black/20">
              <Logo className="text-white" size="lg" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-center mb-2 tracking-tight">GiG</h1>
          <p className="text-center text-gray-500 mb-8 italic serif">Trust Your Message.</p>
          
          {verificationMessage && (
            <div className="mb-6 p-4 bg-emerald-50 text-emerald-700 rounded-xl text-sm border border-emerald-100">
              {verificationMessage}
            </div>
          )}

          <div className="space-y-4">
            {authMode === 'register' && (
              <>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Username</label>
                  <input 
                    type="text" 
                    value={usernameInput}
                    onChange={(e) => {
                      setUsernameInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Enter your handle..."
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Email</label>
                  <input 
                    type="email" 
                    value={emailInput}
                    onChange={(e) => {
                      setEmailInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Enter your email..."
                  />
                </div>
                {registerError && (
                  <p className="text-red-500 text-xs mt-2">{registerError}</p>
                )}
                <button 
                  onClick={handleRegister}
                  className="w-full py-3 bg-black text-white rounded-xl font-semibold hover:bg-gray-800 transition-colors flex items-center justify-center gap-3"
                >
                  <TypewriterText text="Register" /> <AnimatedLock />
                </button>
                <p className="text-center text-sm text-gray-500 mt-4">
                  Already have an account? <button onClick={() => setAuthMode('login')} className="text-black font-semibold underline">Log in</button>
                </p>
              </>
            )}

            {authMode === 'login' && (
              <>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Username</label>
                  <input 
                    type="text" 
                    value={usernameInput}
                    onChange={(e) => {
                      setUsernameInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Enter your handle..."
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Password</label>
                  <input 
                    type="password" 
                    value={passwordInput}
                    onChange={(e) => {
                      setPasswordInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Enter your password..."
                  />
                </div>
                {registerError && (
                  <p className="text-red-500 text-xs mt-2">{registerError}</p>
                )}
                <button 
                  onClick={handleLogin}
                  className="w-full py-3 bg-black text-white rounded-xl font-semibold hover:bg-gray-800 transition-colors flex items-center justify-center gap-3"
                >
                  <TypewriterText text="Log In" /> <AnimatedLock />
                </button>
                <p className="text-center text-sm text-gray-500 mt-4">
                  Don't have an account? <button onClick={() => setAuthMode('register')} className="text-black font-semibold underline">Register</button>
                </p>
              </>
            )}

            {authMode === 'verify' && (
              <>
                <div className="mb-4">
                  <p className="text-sm text-gray-600">Please set a password to secure your identity key. This password will be required to log in on any device.</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Password</label>
                  <input 
                    type="password" 
                    value={passwordInput}
                    onChange={(e) => {
                      setPasswordInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Create a strong password..."
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-1">Confirm Password</label>
                  <input 
                    type="password" 
                    value={confirmPasswordInput}
                    onChange={(e) => {
                      setConfirmPasswordInput(e.target.value);
                      setRegisterError('');
                    }}
                    className={`w-full px-4 py-3 bg-gray-50 border ${registerError ? 'border-red-500' : 'border-gray-200'} rounded-xl focus:outline-none focus:ring-2 focus:ring-black/5 transition-all`}
                    placeholder="Confirm your password..."
                  />
                </div>
                {registerError && (
                  <p className="text-red-500 text-xs mt-2">{registerError}</p>
                )}
                <button 
                  onClick={handleVerify}
                  className="w-full py-3 bg-black text-white rounded-xl font-semibold hover:bg-gray-800 transition-colors flex items-center justify-center gap-3"
                >
                  <TypewriterText text="Verify & Initialize Identity" /> <AnimatedLock />
                </button>
              </>
            )}
          </div>
          <p className="mt-6 text-[10px] text-gray-400 text-center uppercase tracking-widest leading-relaxed">
            GiG Messaging Network
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
            <div className="w-12 h-12 bg-black rounded-xl flex items-center justify-center shadow-lg shadow-black/10">
              <Logo className="text-white" size="sm" />
            </div>
            <div>
              <h2 className="font-bold tracking-tight text-lg">GiG</h2>
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
                onClick={handleClearAllUnread}
                className="p-1 hover:bg-gray-100 rounded-lg transition-colors text-gray-400 hover:text-black"
                title="Mark all as read"
              >
                <Check size={18} />
              </button>
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
              <div className="text-left flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className={`font-semibold text-sm truncate ${
                    activeGroup?.id === group.id ? 'text-white' : (group.unread_count > 0 ? 'text-black' : 'text-gray-700')
                  }`}>{group.name}</p>
                  {group.unread_count > 0 && activeGroup?.id !== group.id && (
                    <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full shrink-0" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <p className={`text-[10px] truncate flex-1 ${
                    activeGroup?.id === group.id ? 'text-white/70' : 'text-gray-400'
                  }`}>
                    {group.last_message_decrypted || "No messages yet"}
                  </p>
                  {group.unread_count > 0 && (
                    <span className="ml-2 px-1.5 py-0.5 bg-emerald-500 text-white text-[9px] font-bold rounded-full min-w-[18px] text-center">
                      {group.unread_count}
                    </span>
                  )}
                  <p className={`text-[9px] uppercase tracking-tighter ml-2 shrink-0 ${
                    activeGroup?.id === group.id ? 'text-white/40' : 'text-gray-300'
                  }`}>E2EE</p>
                </div>
              </div>
            </button>
          ))}
        </div>

        <div className="p-4 bg-gray-50 border-t border-black/5">
          <div className="flex items-center justify-between">
            <button 
              onClick={() => {
                setProfileUsername(user.username);
                setShowProfile(true);
              }}
              className="flex items-center gap-3 hover:bg-gray-100 p-1 rounded-lg transition-all flex-1 min-w-0"
            >
              <div className="w-8 h-8 bg-emerald-500 rounded-full flex items-center justify-center text-white text-xs font-bold shrink-0">
                {user.username[0].toUpperCase()}
              </div>
              <div className="text-left min-w-0">
                <p className="text-xs font-bold truncate">{user.username}</p>
                <p className="text-[10px] text-gray-400 truncate font-mono">{user.id.slice(0, 8)}...</p>
              </div>
            </button>
            <button 
              onClick={handleLogout}
              className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all"
              title="Logout"
            >
              <LogOut size={16} />
            </button>
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
                <input
                  type="text"
                  placeholder="Search messages..."
                  value={messageSearchQuery}
                  onChange={(e) => setMessageSearchQuery(e.target.value)}
                  className="px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-lg text-xs focus:outline-none focus:ring-1 focus:ring-emerald-500 w-40"
                />
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
                  onClick={() => setShowInviteConfig(true)}
                  className="p-1.5 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-gray-600"
                  title="Generate Invite Link"
                >
                  <Link size={16} />
                </button>
                <button 
                  onClick={() => setShowGroupSettings(true)}
                  className="p-1.5 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors text-gray-600"
                  title="Group Settings"
                >
                  <Settings size={16} />
                </button>
                <button 
                  onClick={handleLeaveGroup}
                  className="p-1.5 bg-red-50 hover:bg-red-100 rounded-lg transition-colors text-red-600"
                  title="Leave Group"
                >
                  <LogOut size={16} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <AnimatePresence initial={false}>
                {messages.filter(m => !messageSearchQuery || m.decryptedContent?.toLowerCase().includes(messageSearchQuery.toLowerCase())).map((msg) => (
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
                    <div className={`max-w-[80%] px-4 py-2.5 rounded-2xl text-sm shadow-sm relative group ${
                      msg.senderId === user.id 
                        ? 'bg-black text-white rounded-tr-none' 
                        : 'bg-white text-gray-800 rounded-tl-none border border-black/5'
                    }`}>
                      {msg.decryptedReplyContent && (
                        <div className={`mb-2 p-2 rounded-lg text-[10px] border-l-2 ${
                          msg.senderId === user.id ? 'bg-white/10 border-white/30' : 'bg-gray-50 border-gray-300'
                        }`}>
                          <p className="font-bold mb-1">{msg.replyToSenderName}</p>
                          <p className="opacity-70 truncate">{msg.decryptedReplyContent}</p>
                        </div>
                      )}
                      {msg.decryptedContent}
                      
                      <div className={`absolute top-0 flex gap-1 p-1.5 bg-white shadow-md rounded-full opacity-0 group-hover:opacity-100 transition-opacity ${
                        msg.senderId === user.id ? '-left-24' : '-right-24'
                      }`}>
                        <button 
                          onClick={() => setReplyingTo(msg)}
                          className="p-1 hover:bg-gray-100 rounded-full text-black"
                          title="Reply"
                        >
                          <Reply size={14} />
                        </button>
                        <button onClick={() => handleReaction(msg.id, '👍')} className="p-1 hover:bg-gray-100 rounded-full">👍</button>
                        <button onClick={() => handleReaction(msg.id, '❤️')} className="p-1 hover:bg-gray-100 rounded-full">❤️</button>
                      </div>

                      {msg.reactions && msg.reactions.length > 0 && (
                        <div className={`absolute -bottom-3 flex gap-1 ${msg.senderId === user.id ? 'right-0' : 'left-0'}`}>
                          {Array.from(new Set(msg.reactions.map(r => r.emoji))).map(emoji => {
                            const count = msg.reactions!.filter(r => r.emoji === emoji).length;
                            const hasReacted = msg.reactions!.some(r => r.emoji === emoji && r.user_id === user.id);
                            return (
                              <button
                                key={emoji}
                                onClick={() => handleReaction(msg.id, emoji)}
                                className={`text-[10px] px-1.5 py-0.5 rounded-full border ${hasReacted ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-white border-gray-200 text-gray-600'} shadow-sm`}
                              >
                                {emoji} {count > 1 && count}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              <div ref={messagesEndRef} />
            </div>

            <div className="p-6 bg-white border-t border-black/5">
              {replyingTo && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-4 p-3 bg-gray-50 border border-black/5 rounded-xl flex items-center justify-between"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1">Replying to {replyingTo.senderName}</p>
                    <p className="text-xs text-gray-600 truncate">{replyingTo.decryptedContent}</p>
                  </div>
                  <button 
                    onClick={() => setReplyingTo(null)}
                    className="p-1 hover:bg-gray-200 rounded-full transition-colors text-gray-400"
                  >
                    <X size={16} />
                  </button>
                </motion.div>
              )}
              {activeGroup && typingUsers[activeGroup.id]?.length > 0 && (
                <motion.div 
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-2 text-[10px] text-emerald-600 font-medium flex items-center gap-2"
                >
                  <div className="flex gap-0.5">
                    <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ repeat: Infinity, duration: 1, times: [0, 0.5, 1] }} className="w-1 h-1 bg-emerald-500 rounded-full" />
                    <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ repeat: Infinity, duration: 1, delay: 0.2, times: [0, 0.5, 1] }} className="w-1 h-1 bg-emerald-500 rounded-full" />
                    <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ repeat: Infinity, duration: 1, delay: 0.4, times: [0, 0.5, 1] }} className="w-1 h-1 bg-emerald-500 rounded-full" />
                  </div>
                  {typingUsers[activeGroup.id].length === 1 
                    ? `${typingUsers[activeGroup.id][0]} is typing...`
                    : `${typingUsers[activeGroup.id].length} people are typing...`}
                </motion.div>
              )}
              <div className="relative flex items-center">
                <input
                  type="text"
                  value={newMessage}
                  onChange={handleTyping}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                  placeholder="Type a message..."
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
            <h3 className="text-xl font-bold tracking-tight mb-2">Select a channel</h3>
            <p className="text-gray-400 text-sm max-w-xs serif italic">
              Start a conversation with your contacts.
            </p>
          </div>
        )}
      </div>

      {/* Modals */}
      <AnimatePresence>
        {showProfile && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full"
            >
              <div className="flex items-center gap-4 mb-6">
                <div className="w-16 h-16 bg-emerald-500 rounded-2xl flex items-center justify-center text-white text-2xl font-bold shadow-lg shadow-emerald-200">
                  {user.username[0].toUpperCase()}
                </div>
                <div>
                  <h3 className="text-xl font-bold tracking-tight">User Profile</h3>
                  <p className="text-xs text-gray-400 font-mono">{user.id}</p>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1">Display Name</label>
                  <input 
                    type="text" 
                    value={profileUsername}
                    onChange={(e) => setProfileUsername(e.target.value)}
                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500/20 transition-all"
                    placeholder="Your handle"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1">Public Identity Key</label>
                  <div className="relative">
                    <textarea 
                      readOnly
                      value={user.publicKey}
                      className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-[10px] font-mono h-24 focus:outline-none resize-none"
                    />
                    <button 
                      onClick={() => {
                        navigator.clipboard.writeText(user.publicKey);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className="absolute right-2 top-2 p-1.5 bg-white border border-black/5 rounded-lg hover:bg-gray-50 transition-colors text-gray-400"
                    >
                      {copied ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                    </button>
                  </div>
                  <p className="mt-2 text-[10px] text-gray-400 italic serif">
                    This is your unique cryptographic identity. Others use this to encrypt messages for you.
                  </p>
                </div>

                <div className="pt-4 border-t border-black/5 space-y-4">
                  <h4 className="text-[10px] font-bold uppercase tracking-widest text-gray-400">Preferences</h4>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">Show User IDs</span>
                    <button 
                      onClick={() => {
                        const newVal = !showUserIds;
                        setShowUserIds(newVal);
                        localStorage.setItem('gig_show_ids', newVal.toString());
                      }}
                      className={`w-10 h-6 rounded-full transition-colors relative ${showUserIds ? 'bg-emerald-500' : 'bg-gray-300'}`}
                    >
                      <div className={`w-4 h-4 bg-white rounded-full absolute top-1 transition-transform ${showUserIds ? 'translate-x-5' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">Enable Notifications</span>
                    <button 
                      onClick={() => {
                        const newVal = !notificationsEnabled;
                        setNotificationsEnabled(newVal);
                        localStorage.setItem('gig_notifications', newVal.toString());
                      }}
                      className={`w-10 h-6 rounded-full transition-colors relative ${notificationsEnabled ? 'bg-emerald-500' : 'bg-gray-300'}`}
                    >
                      <div className={`w-4 h-4 bg-white rounded-full absolute top-1 transition-transform ${notificationsEnabled ? 'translate-x-5' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">Notification Sounds</span>
                    <button 
                      onClick={() => {
                        const newVal = !soundEnabled;
                        setSoundEnabled(newVal);
                        localStorage.setItem('gig_sound', newVal.toString());
                      }}
                      disabled={!notificationsEnabled}
                      className={`w-10 h-6 rounded-full transition-colors relative ${soundEnabled && notificationsEnabled ? 'bg-emerald-500' : 'bg-gray-300'} ${!notificationsEnabled && 'opacity-50 cursor-not-allowed'}`}
                    >
                      <div className={`w-4 h-4 bg-white rounded-full absolute top-1 transition-transform ${soundEnabled && notificationsEnabled ? 'translate-x-5' : 'translate-x-1'}`} />
                    </button>
                  </div>
                </div>

                <div className="pt-4 border-t border-black/5 space-y-3">
                  <button 
                    onClick={handleRotateIdentity}
                    disabled={isRotating}
                    className="w-full py-3 bg-white border border-black/10 text-gray-700 rounded-xl font-bold hover:bg-gray-50 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    <RefreshCw size={16} className={isRotating ? 'animate-spin' : ''} />
                    {isRotating ? 'Rotating...' : 'Rotate Identity Keys'}
                  </button>
                  
                  <div className="flex gap-3">
                    <button 
                      onClick={() => setShowProfile(false)}
                      className="flex-1 py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                    >
                      Cancel
                    </button>
                    <button 
                      onClick={handleUpdateProfile}
                      className="flex-1 py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
                    >
                      Save Changes
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        )}

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

        {showGroupSettings && activeGroup && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-md w-full max-h-[80vh] flex flex-col"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Group Settings</h3>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1">Group Name</label>
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      value={newGroupName || activeGroup.name}
                      onChange={(e) => setNewGroupName(e.target.value)}
                      className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500/20 transition-all"
                      placeholder="Group Name"
                      disabled={groupMembers.find(gm => gm.user_id === user?.id)?.role !== 'admin'}
                    />
                    {groupMembers.find(gm => gm.user_id === user?.id)?.role === 'admin' && (
                      <button 
                        onClick={async () => {
                          if (!newGroupName || newGroupName === activeGroup.name) return;
                          try {
                            const res = await fetch(`/api/groups/${activeGroup.id}`, {
                              method: 'PUT',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({ name: newGroupName })
                            });
                            if (res.ok) {
                              setActiveGroup({ ...activeGroup, name: newGroupName });
                              fetchGroups(user!.id);
                              alert("Group name updated");
                            }
                          } catch (e) {
                            console.error(e);
                          }
                        }}
                        className="px-4 py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
                      >
                        Save
                      </button>
                    )}
                  </div>
                </div>

                {groupMembers.find(gm => gm.user_id === user?.id)?.role === 'admin' && (
                  <div>
                    <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-2">Manage Admins</label>
                    <div className="max-h-40 overflow-y-auto space-y-2">
                      {groupMembers.map(m => (
                        <div key={m.user_id} className="flex items-center justify-between p-3 bg-gray-50 rounded-xl border border-black/5">
                          <span className="text-sm font-semibold">{m.username}</span>
                          {m.user_id !== user?.id && (
                            <button
                              onClick={async () => {
                                const newRole = m.role === 'admin' ? 'member' : 'admin';
                                try {
                                  const res = await fetch(`/api/groups/${activeGroup.id}/members/${m.user_id}/role`, {
                                    method: 'PUT',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ role: newRole })
                                  });
                                  if (res.ok) {
                                    fetchGroupMembers(activeGroup.id);
                                  }
                                } catch (e) {
                                  console.error(e);
                                }
                              }}
                              className={`text-[10px] px-2 py-1 rounded-full border font-bold ${m.role === 'admin' ? 'bg-emerald-50 text-emerald-600 border-emerald-200' : 'bg-white text-gray-500 border-gray-200'}`}
                            >
                              {m.role === 'admin' ? 'ADMIN' : 'MAKE ADMIN'}
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-6">
                <button 
                  onClick={() => {
                    setShowGroupSettings(false);
                    setNewGroupName('');
                  }}
                  className="w-full py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                >
                  Close
                </button>
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
                        {showUserIds && <p className="text-[10px] font-mono text-gray-400">{m.user_id.slice(0, 12)}...</p>}
                      </div>
                    </div>
                    {m.user_id !== user.id && groupMembers.find(gm => gm.user_id === user.id)?.role === 'admin' && (
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
              <div className="flex gap-3">
                <button 
                  onClick={() => setShowMembers(false)}
                  className="flex-1 py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                >
                  Close
                </button>
                <button 
                  onClick={handleLeaveGroup}
                  className="flex-1 py-3 bg-red-50 text-red-600 rounded-xl font-bold hover:bg-red-100 transition-colors flex items-center justify-center gap-2"
                >
                  Leave Group <LogOut size={18} />
                </button>
              </div>
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
                        {showUserIds && <p className="text-[10px] font-mono text-gray-400">{u.id.slice(0, 12)}...</p>}
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
                        {showUserIds && <p className="text-[10px] font-mono text-gray-400">{u.id.slice(0, 12)}...</p>}
                      </div>
                    </div>
                    <Send size={18} className="text-gray-300" />
                  </button>
                )) : (
                  <p className="text-center text-gray-400 py-8 italic serif">
                    {userSearchQuery ? "No matching users found." : "Search for a user to start a DM."}
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

        {showInviteConfig && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white p-8 rounded-2xl shadow-2xl max-w-sm w-full"
            >
              <h3 className="text-xl font-bold mb-4 tracking-tight">Invite Settings</h3>
              <p className="text-sm text-gray-500 mb-6 italic serif">
                Choose how long the invite link should remain valid.
              </p>
              
              <div className="space-y-4 mb-8">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-2">Expiration</label>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { id: '1h', label: '1 Hour' },
                      { id: '1d', label: '1 Day' },
                      { id: '7d', label: '7 Days' },
                      { id: 'never', label: 'Never' }
                    ].map((opt) => (
                      <button
                        key={opt.id}
                        onClick={() => setInviteExpiration(opt.id)}
                        className={`py-2 px-3 rounded-xl text-xs font-bold transition-all border ${
                          inviteExpiration === opt.id 
                            ? 'bg-black text-white border-black' 
                            : 'bg-gray-50 text-gray-600 border-black/5 hover:bg-gray-100'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex gap-3">
                <button 
                  onClick={() => setShowInviteConfig(false)}
                  className="flex-1 py-3 bg-gray-100 text-gray-600 rounded-xl font-bold hover:bg-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleGenerateInvite}
                  className="flex-1 py-3 bg-black text-white rounded-xl font-bold hover:bg-gray-800 transition-colors"
                >
                  Generate
                </button>
              </div>
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
                Anyone with this link can join the group. Share it with people you want to invite.
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
        {undoLeave && (
          <div className="fixed bottom-8 left-1/2 -translate-x-1/2 z-50">
            <motion.div 
              initial={{ y: 100, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: 100, opacity: 0 }}
              className="bg-black text-white px-6 py-4 rounded-2xl shadow-2xl flex items-center gap-6 min-w-[320px] justify-between"
            >
              <div className="flex items-center gap-3">
                <Users size={20} className="text-emerald-400" />
                <p className="text-sm font-medium">Left <span className="font-bold">{undoLeave.groupName}</span></p>
              </div>
              <button 
                onClick={handleUndoLeave}
                className="text-emerald-400 font-black text-xs uppercase tracking-widest hover:text-emerald-300 transition-colors px-3 py-1 border border-emerald-400/30 rounded-lg"
              >
                Undo
              </button>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
