/* ===================================================================
   Password Strength Analyzer — Application Logic
   =================================================================== */

// ─── Common Password Patterns & Dictionary ───
const COMMON_PASSWORDS = [
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
  'dragon', 'login', 'princess', 'football', 'shadow', 'sunshine', 'trustno1',
  'iloveyou', 'batman', 'access', 'hello', 'charlie', 'donald', '123456789',
  'password1', 'password123', 'admin', 'letmein', 'welcome', '1234567',
  'starwars', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'qwerty123', 'administrator',
  '1234567890', '123123', '000000', '111111', 'hunter', 'baseball', 'soccer',
  'ashley', 'michael', 'superman', 'mustang', 'harley', 'ranger', 'buster',
  'daniel', 'robert', 'thomas', 'soccer1', 'george', 'jennifer', 'pass1234'
];

const COMMON_PATTERNS = [
  /^(.)\1+$/,              // All same character
  /^(012|123|234|345|456|567|678|789)+$/,  // Sequential numbers
  /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i,
  /^(qwerty|asdf|zxcv|wasd)/i,
  /^[a-z]+\d+$/i,          // Letters then numbers
  /^(.{1,3})\1+$/,         // Short repeated pattern
];

const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertz', 'azerty', 'asdf', 'zxcv', 'wasd',
  '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik',
  'qweasd', 'asdqwe', 'zxcasd'
];

const LEET_MAP = {
  '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
  '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't'
};

const SECURITY_TIPS = [
  {
    emoji: '🔑',
    title: 'Use a Passphrase',
    desc: 'Combine 4+ random words like "correct-horse-battery-staple" for easy-to-remember, hard-to-crack passwords.'
  },
  {
    emoji: '🎲',
    title: 'Embrace Randomness',
    desc: 'Truly random passwords are exponentially harder to crack than human-created ones.'
  },
  {
    emoji: '🔒',
    title: 'Use a Password Manager',
    desc: 'Store unique passwords for every account. You only need to remember one master password.'
  },
  {
    emoji: '📏',
    title: 'Length Over Complexity',
    desc: 'A 16-char lowercase password is stronger than an 8-char mixed password. Length wins.'
  },
  {
    emoji: '🚫',
    title: 'Avoid Personal Info',
    desc: 'Never use birthdays, names, pets, or addresses. Attackers check these first.'
  },
  {
    emoji: '🔄',
    title: 'Enable 2FA',
    desc: 'Two-factor authentication adds a second layer even if your password is compromised.'
  },
  {
    emoji: '⚡',
    title: 'Entropy Matters',
    desc: 'Each bit of entropy doubles the cracking time. Aim for 60+ bits for online accounts, 80+ for critical ones.'
  },
  {
    emoji: '🛡️',
    title: 'Check for Breaches',
    desc: 'Use haveibeenpwned.com to check if your passwords have appeared in data breaches.'
  }
];

// ─── DOM Elements ───
const passwordInput = document.getElementById('password-input');
const toggleVisibility = document.getElementById('toggle-visibility');
const inputWrapper = document.querySelector('.input-wrapper');
const meterBar = document.getElementById('meter-bar');
const meterLabel = document.getElementById('meter-label');
const meterScore = document.getElementById('meter-score');
const crackTimeContainer = document.getElementById('crack-time-container');
const crackTimeValue = document.getElementById('crack-time-value');
const suggestionsList = document.getElementById('suggestions-list');
const btnRegenerate = document.getElementById('btn-regenerate');
const historyList = document.getElementById('history-list');
const btnSavePassword = document.getElementById('btn-save-password');
const btnClearHistory = document.getElementById('btn-clear-history');
const themeToggle = document.getElementById('theme-toggle');
const toast = document.getElementById('toast');
const toastMessage = document.getElementById('toast-message');
const tipsList = document.getElementById('tips-list');
const canvas = document.getElementById('particles-canvas');

// Stat elements
const statCharcount = document.getElementById('stat-charcount');
const statUniqueChars = document.getElementById('stat-unique-chars');
const statEntropy = document.getElementById('stat-entropy');
const statPool = document.getElementById('stat-pool');
const distributionBars = document.getElementById('distribution-bars');

// Criteria elements
const criteriaElements = {
  length: document.getElementById('criteria-length'),
  uppercase: document.getElementById('criteria-uppercase'),
  lowercase: document.getElementById('criteria-lowercase'),
  numbers: document.getElementById('criteria-numbers'),
  special: document.getElementById('criteria-special'),
  unique: document.getElementById('criteria-unique'),
  'no-common': document.getElementById('criteria-no-common'),
  entropy: document.getElementById('criteria-entropy')
};

// ─── State ───
let passwordHistory = JSON.parse(localStorage.getItem('passwordHistory') || '[]');
let debounceTimer = null;

// ─── Initialization ───
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initParticles();
  renderTips();
  generateSuggestions();
  renderHistory();

  passwordInput.addEventListener('input', handlePasswordInput);
  toggleVisibility.addEventListener('click', handleToggleVisibility);
  btnRegenerate.addEventListener('click', generateSuggestions);
  btnSavePassword.addEventListener('click', handleSavePassword);
  btnClearHistory.addEventListener('click', handleClearHistory);
  themeToggle.addEventListener('click', toggleTheme);
});

// ─── Password Analysis ───
function handlePasswordInput() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    const password = passwordInput.value;
    if (!password) {
      resetAnalysis();
      return;
    }
    analyzePassword(password);
  }, 50);
}

function analyzePassword(password) {
  const analysis = getDetailedAnalysis(password);
  updateUI(analysis);
}

function getDetailedAnalysis(password) {
  const length = password.length;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  // Character counts
  const uppercaseCount = (password.match(/[A-Z]/g) || []).length;
  const lowercaseCount = (password.match(/[a-z]/g) || []).length;
  const numberCount = (password.match(/[0-9]/g) || []).length;
  const specialCount = (password.match(/[^A-Za-z0-9]/g) || []).length;

  // Character pool size
  let poolSize = 0;
  if (hasLowercase) poolSize += 26;
  if (hasUppercase) poolSize += 26;
  if (hasNumbers) poolSize += 10;
  if (hasSpecial) poolSize += 33;

  // Entropy calculation
  const entropy = poolSize > 0 ? Math.floor(length * Math.log2(poolSize)) : 0;

  // Unique characters
  const uniqueChars = new Set(password).size;

  // Check common passwords (including leet speak variants)
  const isCommon = checkCommonPassword(password);

  // Check patterns
  const hasPattern = checkPatterns(password);

  // Check uniqueness against history
  const isUnique = !isInHistory(password);

  // Calculate score (0-100)
  const score = calculateScore({
    length, hasUppercase, hasLowercase, hasNumbers, hasSpecial,
    entropy, uniqueChars, isCommon, hasPattern, isUnique
  });

  // Crack time estimate
  const crackTime = estimateCrackTime(entropy);

  // Strength level
  const strength = getStrengthLevel(score);

  return {
    password,
    length,
    hasUppercase,
    hasLowercase,
    hasNumbers,
    hasSpecial,
    uppercaseCount,
    lowercaseCount,
    numberCount,
    specialCount,
    poolSize,
    entropy,
    uniqueChars,
    isCommon,
    hasPattern,
    isUnique,
    score,
    crackTime,
    strength
  };
}

function checkCommonPassword(password) {
  const lower = password.toLowerCase();

  // Direct match
  if (COMMON_PASSWORDS.includes(lower)) return true;

  // Leet speak reversal
  let deleet = lower;
  for (const [key, val] of Object.entries(LEET_MAP)) {
    deleet = deleet.split(key).join(val);
  }
  if (COMMON_PASSWORDS.includes(deleet)) return true;

  // Keyboard patterns
  for (const pattern of KEYBOARD_PATTERNS) {
    if (lower.includes(pattern)) return true;
  }

  return false;
}

function checkPatterns(password) {
  for (const pattern of COMMON_PATTERNS) {
    if (pattern.test(password)) return true;
  }

  // Check for sequential characters
  let sequential = 0;
  for (let i = 1; i < password.length; i++) {
    if (password.charCodeAt(i) - password.charCodeAt(i - 1) === 1) {
      sequential++;
      if (sequential >= 3) return true;
    } else {
      sequential = 0;
    }
  }

  // Check for repeated characters (more than 3 in a row)
  if (/(.)\1{3,}/.test(password)) return true;

  return false;
}

function calculateScore(params) {
  const { length, hasUppercase, hasLowercase, hasNumbers, hasSpecial,
          entropy, uniqueChars, isCommon, hasPattern, isUnique } = params;

  let score = 0;

  // Length scoring (0-30)
  if (length >= 16) score += 30;
  else if (length >= 12) score += 22;
  else if (length >= 10) score += 16;
  else if (length >= 8) score += 10;
  else if (length >= 6) score += 5;
  else score += Math.floor(length * 0.5);

  // Character diversity (0-20)
  const diversityCount = [hasUppercase, hasLowercase, hasNumbers, hasSpecial].filter(Boolean).length;
  score += diversityCount * 5;

  // Entropy bonus (0-25)
  if (entropy >= 80) score += 25;
  else if (entropy >= 60) score += 20;
  else if (entropy >= 40) score += 12;
  else if (entropy >= 20) score += 6;
  else score += Math.floor(entropy * 0.2);

  // Uniqueness of characters (0-10)
  const uniqueRatio = length > 0 ? uniqueChars / length : 0;
  score += Math.floor(uniqueRatio * 10);

  // Penalties
  if (isCommon) score -= 30;
  if (hasPattern) score -= 15;
  if (!isUnique) score -= 10;

  // Bonus for history uniqueness
  if (isUnique && length > 0) score += 5;

  return Math.max(0, Math.min(100, score));
}

function getStrengthLevel(score) {
  if (score >= 80) return { level: 'excellent', label: 'Excellent', color: 'var(--color-excellent)', gradient: 'var(--gradient-excellent)' };
  if (score >= 60) return { level: 'strong', label: 'Strong', color: 'var(--color-strong)', gradient: 'var(--gradient-strong)' };
  if (score >= 40) return { level: 'fair', label: 'Fair', color: 'var(--color-fair)', gradient: 'var(--gradient-fair)' };
  if (score >= 20) return { level: 'weak', label: 'Weak', color: 'var(--color-weak)', gradient: 'var(--gradient-weak)' };
  return { level: 'danger', label: 'Very Weak', color: 'var(--color-danger)', gradient: 'var(--gradient-danger)' };
}

function estimateCrackTime(entropy) {
  // Assume 10 billion guesses per second (modern GPU cluster)
  const guessesPerSecond = 10_000_000_000;
  const totalCombinations = Math.pow(2, entropy);
  const seconds = totalCombinations / guessesPerSecond / 2; // Average case

  if (seconds < 0.001) return 'Instantly';
  if (seconds < 1) return 'Less than a second';
  if (seconds < 60) return `${Math.floor(seconds)} seconds`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)} days`;
  if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} months`;

  const years = seconds / 31536000;
  if (years < 1000) return `${Math.floor(years)} years`;
  if (years < 1_000_000) return `${(years / 1000).toFixed(1)}K years`;
  if (years < 1_000_000_000) return `${(years / 1_000_000).toFixed(1)}M years`;
  if (years < 1e12) return `${(years / 1_000_000_000).toFixed(1)}B years`;
  if (years < 1e15) return `${(years / 1e12).toFixed(1)}T years`;
  return 'Virtually forever';
}

// ─── Hashing (Simple SHA-256 via Web Crypto) ───
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function isInHistory(password) {
  const hash = await hashPassword(password);
  return passwordHistory.some(entry => entry.hash === hash);
}

// Synchronous version for quick check (uses cached comparison)
function isInHistorySync(password) {
  // This is a simple check — for async hash, we update criteria after await
  return false; // Will be updated asynchronously
}

// ─── UI Updates ───
function updateUI(analysis) {
  const { strength, score, crackTime } = analysis;

  // Update meter bar
  meterBar.style.width = `${score}%`;
  meterBar.style.background = strength.gradient;

  // Update labels
  meterLabel.textContent = strength.label;
  meterLabel.style.color = strength.color;
  meterScore.textContent = `${score}/100`;

  // Update crack time
  crackTimeContainer.classList.add('active');
  crackTimeValue.textContent = crackTime;
  crackTimeValue.style.color = strength.color;

  // Update criteria
  setCriteria('length', analysis.length >= 12);
  setCriteria('uppercase', analysis.hasUppercase);
  setCriteria('lowercase', analysis.hasLowercase);
  setCriteria('numbers', analysis.hasNumbers);
  setCriteria('special', analysis.hasSpecial);
  setCriteria('no-common', !analysis.isCommon && !analysis.hasPattern);
  setCriteria('entropy', analysis.entropy >= 60);

  // Update async criteria (uniqueness)
  hashPassword(analysis.password).then(hash => {
    const isUnique = !passwordHistory.some(entry => entry.hash === hash);
    setCriteria('unique', isUnique);
    btnSavePassword.disabled = !analysis.password;
  });

  // Update stats
  statCharcount.textContent = analysis.length;
  statUniqueChars.textContent = analysis.uniqueChars;
  statEntropy.textContent = analysis.entropy;
  statPool.textContent = analysis.poolSize;

  // Update distribution bars
  renderDistribution(analysis);
}

function setCriteria(id, met) {
  const el = criteriaElements[id];
  if (el) {
    el.setAttribute('data-met', met.toString());
  }
}

function resetAnalysis() {
  meterBar.style.width = '0%';
  meterLabel.textContent = 'Enter a password';
  meterLabel.style.color = 'var(--text-secondary)';
  meterScore.textContent = '';
  crackTimeContainer.classList.remove('active');
  crackTimeValue.textContent = '—';
  crackTimeValue.style.color = 'var(--text-primary)';
  btnSavePassword.disabled = true;

  Object.keys(criteriaElements).forEach(key => setCriteria(key, false));

  statCharcount.textContent = '0';
  statUniqueChars.textContent = '0';
  statEntropy.textContent = '0';
  statPool.textContent = '0';
  distributionBars.innerHTML = '';
}

function renderDistribution(analysis) {
  const total = analysis.length || 1;
  const categories = [
    { label: 'Uppercase', count: analysis.uppercaseCount, className: 'uppercase' },
    { label: 'Lowercase', count: analysis.lowercaseCount, className: 'lowercase' },
    { label: 'Numbers', count: analysis.numberCount, className: 'numbers' },
    { label: 'Special', count: analysis.specialCount, className: 'special' }
  ];

  distributionBars.innerHTML = categories.map(cat => `
    <div class="dist-row">
      <span class="dist-label">${cat.label}</span>
      <div class="dist-bar-bg">
        <div class="dist-bar-fill ${cat.className}" style="width: ${(cat.count / total) * 100}%"></div>
      </div>
      <span class="dist-count">${cat.count}</span>
    </div>
  `).join('');
}

// ─── Password Visibility Toggle ───
function handleToggleVisibility() {
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  inputWrapper.classList.toggle('password-visible', isPassword);
}

// ─── Password Suggestions ───
function generateSuggestions() {
  const suggestions = [
    generateStrongPassword(16, true),
    generateStrongPassword(20, true),
    generatePassphrase(4),
    generateStrongPassword(24, false),
    generatePassphrase(5)
  ];

  suggestionsList.innerHTML = suggestions.map(pwd => {
    const analysis = getDetailedAnalysis(pwd);
    return `
      <div class="suggestion-item" onclick="copySuggestion('${pwd.replace(/'/g, "\\'")}')">
        <span class="suggestion-password">${escapeHTML(pwd)}</span>
        <span class="suggestion-strength ${analysis.strength.level}">${analysis.strength.label}</span>
      </div>
    `;
  }).join('');
}

function generateStrongPassword(length, includeSpecial) {
  const lowercase = 'abcdefghijkmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const numbers = '23456789';
  const special = '!@#$%^&*_+-=';

  let chars = lowercase + uppercase + numbers;
  if (includeSpecial) chars += special;

  // Ensure at least one of each required type
  let password = '';
  password += lowercase[cryptoRandom(lowercase.length)];
  password += uppercase[cryptoRandom(uppercase.length)];
  password += numbers[cryptoRandom(numbers.length)];
  if (includeSpecial) {
    password += special[cryptoRandom(special.length)];
  }

  // Fill remaining
  while (password.length < length) {
    password += chars[cryptoRandom(chars.length)];
  }

  // Shuffle
  return shuffleString(password);
}

function generatePassphrase(wordCount) {
  const words = [
    'alpha', 'bravo', 'castle', 'delta', 'eagle', 'forest', 'globe', 'harbor',
    'ivory', 'jungle', 'knight', 'lunar', 'marble', 'nexus', 'orbit', 'prism',
    'quartz', 'river', 'storm', 'tiger', 'ultra', 'vapor', 'whale', 'xenon',
    'yacht', 'zenith', 'blade', 'coral', 'frost', 'grain', 'haze', 'light',
    'mist', 'neon', 'ocean', 'peak', 'rain', 'silk', 'trek', 'vine',
    'wren', 'zeal', 'arch', 'bolt', 'crest', 'dusk', 'ember', 'flame',
    'glow', 'helm', 'iris', 'jade', 'kite', 'latch', 'moss', 'nova',
    'opal', 'plume', 'ridge', 'sable', 'torch', 'umbra', 'veil', 'wisp'
  ];

  const separators = ['-', '.', '_', '+'];
  const sep = separators[cryptoRandom(separators.length)];

  let passphrase = [];
  const usedIndices = new Set();
  for (let i = 0; i < wordCount; i++) {
    let idx;
    do {
      idx = cryptoRandom(words.length);
    } while (usedIndices.has(idx));
    usedIndices.add(idx);

    let word = words[idx];
    // Randomly capitalize some words
    if (cryptoRandom(3) === 0) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    passphrase.push(word);
  }

  // Add a random number somewhere
  const numPos = cryptoRandom(passphrase.length + 1);
  const num = cryptoRandom(90) + 10;
  passphrase.splice(numPos, 0, num.toString());

  return passphrase.join(sep);
}

function cryptoRandom(max) {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return array[0] % max;
}

function shuffleString(str) {
  const arr = str.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = cryptoRandom(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function copySuggestion(password) {
  navigator.clipboard.writeText(password).then(() => {
    showToast('Password copied to clipboard!');
  }).catch(() => {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = password;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast('Password copied to clipboard!');
  });
}

// ─── Password History ───
async function handleSavePassword() {
  const password = passwordInput.value;
  if (!password) return;

  const hash = await hashPassword(password);

  // Check if already saved
  if (passwordHistory.some(entry => entry.hash === hash)) {
    showToast('This password is already saved!');
    return;
  }

  const analysis = getDetailedAnalysis(password);

  passwordHistory.unshift({
    hash: hash,
    preview: hash.substring(0, 16) + '...',
    date: new Date().toISOString(),
    strength: analysis.strength.level,
    score: analysis.score
  });

  // Keep last 50 entries
  if (passwordHistory.length > 50) {
    passwordHistory = passwordHistory.slice(0, 50);
  }

  localStorage.setItem('passwordHistory', JSON.stringify(passwordHistory));
  renderHistory();

  // Re-analyze to update uniqueness
  analyzePassword(password);

  showToast('Password hash saved securely!');
}

function handleClearHistory() {
  if (passwordHistory.length === 0) return;
  passwordHistory = [];
  localStorage.setItem('passwordHistory', JSON.stringify(passwordHistory));
  renderHistory();

  // Re-analyze current password if exists
  if (passwordInput.value) {
    analyzePassword(passwordInput.value);
  }

  showToast('History cleared');
}

function renderHistory() {
  if (passwordHistory.length === 0) {
    historyList.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <p>No passwords saved yet</p>
        <span>Analyzed passwords will appear here</span>
      </div>
    `;
    return;
  }

  historyList.innerHTML = passwordHistory.map(entry => {
    const strengthColors = {
      excellent: 'var(--color-excellent)',
      strong: 'var(--color-strong)',
      fair: 'var(--color-fair)',
      weak: 'var(--color-weak)',
      danger: 'var(--color-danger)'
    };
    const color = strengthColors[entry.strength] || 'var(--text-muted)';
    const date = new Date(entry.date);
    const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    return `
      <div class="history-item">
        <span class="history-hash" title="${entry.hash}">${entry.preview}</span>
        <span class="history-date">${dateStr}</span>
        <span class="history-strength-dot" style="background: ${color}" title="${entry.strength}"></span>
      </div>
    `;
  }).join('');
}

// ─── Security Tips ───
function renderTips() {
  tipsList.innerHTML = SECURITY_TIPS.map(tip => `
    <div class="tip-item">
      <span class="tip-emoji">${tip.emoji}</span>
      <div class="tip-content">
        <span class="tip-title">${tip.title}</span>
        <span class="tip-desc">${tip.desc}</span>
      </div>
    </div>
  `).join('');
}

// ─── Theme ───
function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  } else {
    // Default dark
    document.documentElement.setAttribute('data-theme', 'dark');
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}

// ─── Toast ───
function showToast(message) {
  toastMessage.textContent = message;
  toast.classList.add('visible');
  setTimeout(() => toast.classList.remove('visible'), 2500);
}

// ─── Particle Background ───
function initParticles() {
  const ctx = canvas.getContext('2d');
  let animationId;
  let particles = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  window.addEventListener('resize', resize);
  resize();

  class Particle {
    constructor() {
      this.reset();
    }

    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.size = Math.random() * 2 + 0.5;
      this.speedX = (Math.random() - 0.5) * 0.5;
      this.speedY = (Math.random() - 0.5) * 0.5;
      this.opacity = Math.random() * 0.4 + 0.1;
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;

      if (this.x < 0 || this.x > canvas.width) this.speedX *= -1;
      if (this.y < 0 || this.y > canvas.height) this.speedY *= -1;
    }

    draw() {
      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = isDark
        ? `rgba(129, 140, 248, ${this.opacity})`
        : `rgba(99, 102, 241, ${this.opacity * 0.5})`;
      ctx.fill();
    }
  }

  // Create particles
  const count = Math.min(80, Math.floor(window.innerWidth * window.innerHeight / 15000));
  for (let i = 0; i < count; i++) {
    particles.push(new Particle());
  }

  function connectParticles() {
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 120) {
          const opacity = (1 - dist / 120) * 0.15;
          ctx.beginPath();
          ctx.strokeStyle = isDark
            ? `rgba(129, 140, 248, ${opacity})`
            : `rgba(99, 102, 241, ${opacity * 0.5})`;
          ctx.lineWidth = 0.5;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => {
      p.update();
      p.draw();
    });
    connectParticles();
    animationId = requestAnimationFrame(animate);
  }

  animate();
}

// Make copySuggestion globally available (used in onclick)
window.copySuggestion = copySuggestion;
