import {
  App,
  ButtonComponent,
  DropdownComponent,
  Modal,
  Notice,
  Platform,
  Plugin,
  PluginSettingTab,
  Setting,

  requestUrl,
  TFile,
  normalizePath,
  setIcon,
} from "obsidian";


const QUILDEN_BASE = "https://quilden.com";

interface QuildenSyncSettings {
  githubToken: string;
  githubRefreshToken: string;
  githubUsername: string;
  repoOwner: string;
  repoName: string;
  branch: string;
  autoSyncInterval: number;
  syncOnSave: boolean;
  encryptionEnabled: boolean;
  encryptionScope: "markdown" | "media" | "all";
  syncOnStartup: boolean;
  excludePatterns: string[];
  commitMessage: string;
  conflictStrategy: "local" | "remote" | "newer";
  notificationLocation: "notice" | "statusbar" | "none";
  /** Git provider: "github" (default) or "gitea" for self-hosted */
  provider: "github" | "gitea";
  /** Base URL of the Gitea instance, e.g. https://git.example.com */
  giteaBaseUrl: string;
}

interface SyncedFileState {
  mtime: number;
  size: number;
  remoteSha?: string; // last known remote blob SHA — used to skip unchanged files on pull
}

interface SyncHistoryEntry {
  time: string;    // ISO timestamp
  pushed: number;
  pulled: number;
  files: string[]; // changed file paths (union of pushed + pulled)
}

interface PersistedPluginData {
  settings?: Partial<QuildenSyncSettings>;
  syncState?: {
    repoKey: string;
    files: Record<string, SyncedFileState>;
  };
  // Small AES-GCM ciphertext of "LM_ENCRYPTION_VERIFY" — used to validate
  // that the user's password matches the one originally used to encrypt the repo.
  encryptionVerifyToken?: string;
  // Exported AES-GCM key bytes (base64). Stored in data.json which lives under
  // .obsidian/ — already excluded from GitHub sync — so it never reaches the remote.
  // Storing key bytes (not the password) means this file alone cannot reveal credentials.
  encryptionKeyBytes?: string;
  syncHistory?: SyncHistoryEntry[];
}

type IncrementalCandidateReason = "dirty-path" | "missing-sync-state" | "metadata-changed";

interface IncrementalCandidateDiagnostic {
  path: string;
  reason: IncrementalCandidateReason;
  previous?: SyncedFileState;
  current: SyncedFileState;
}

const MAX_SYNC_DIAGNOSTIC_SAMPLE = 20;

const DEFAULT_SETTINGS: QuildenSyncSettings = {
  githubToken: "",
  githubRefreshToken: "",
  githubUsername: "",
  repoOwner: "",
  repoName: "",
  branch: "main",
  autoSyncInterval: 0,
  syncOnSave: true,
  encryptionEnabled: false,
  encryptionScope: "markdown" as const,
  syncOnStartup: true,
  excludePatterns: [".obsidian/", ".trash/", ".DS_Store"],
  commitMessage: "Quilden Sync: Update from Obsidian",
  conflictStrategy: "newer",
  notificationLocation: "statusbar",
  provider: "github",
  giteaBaseUrl: "",
};

const REQUIRED_EXCLUDE_PATTERNS = [".obsidian/", ".trash/", ".DS_Store"];


const ENCRYPTED_PREFIX = "QENC:1:";
const PBKDF2_ITERATIONS = 600_000;
const IV_LENGTH = 12;

let derivedKey: CryptoKey | null = null;

// Salt derived from user identity — nothing stored in the repo.
// Must match the same logic in the Quilden website's crypto.ts.
async function contextSalt(login: string, owner: string, repo: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`quilden:${login}/${owner}/${repo}`);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

async function buildKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,  // extractable — required to persist key bytes to data.json across restarts
    ["encrypt", "decrypt"]
  );
}

async function setupEncryptionKey(password: string, login: string, owner: string, repo: string): Promise<void> {
  const salt = await contextSalt(login, owner, repo);
  derivedKey = await buildKey(password, salt);
}

function clearEncryptionKey(): void {
  derivedKey = null;
}

/** Export the current derivedKey as base64 for local storage. */
async function exportDerivedKey(): Promise<string | null> {
  if (!derivedKey) return null;
  try {
    const raw = await crypto.subtle.exportKey('raw', derivedKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  } catch { return null; }
}

/** Import base64 key bytes and set as the active derivedKey. */
async function importDerivedKey(base64: string): Promise<boolean> {
  try {
    const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    derivedKey = await crypto.subtle.importKey(
      'raw', bytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
    );
    return true;
  } catch { return false; }
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function encryptContent(plaintext: string): Promise<string> {
  if (!derivedKey) throw new Error("Encryption not configured");
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, derivedKey, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);
  return ENCRYPTED_PREFIX + toBase64(combined);
}

const LEGACY_ENCRYPTED_PREFIX = "LMENC:1:";

async function decryptContent(encrypted: string): Promise<string | null> {
  if (!derivedKey) return null;
  const prefix = encrypted.startsWith(ENCRYPTED_PREFIX) ? ENCRYPTED_PREFIX
    : encrypted.startsWith(LEGACY_ENCRYPTED_PREFIX) ? LEGACY_ENCRYPTED_PREFIX
    : null;
  if (!prefix) return null;
  try {
    const bytes = fromBase64(encrypted.slice(prefix.length));
    const iv = bytes.slice(0, IV_LENGTH);
    const ciphertext = bytes.slice(IV_LENGTH);
    const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, derivedKey, ciphertext);
    return new TextDecoder().decode(plainBuffer);
  } catch {
    return null;
  }
}

function isEncryptedContent(content: string): boolean {
  return content.startsWith(ENCRYPTED_PREFIX) || content.startsWith(LEGACY_ENCRYPTED_PREFIX);
}

const ENCRYPTION_VERIFY_PLAINTEXT = "LM_ENCRYPTION_VERIFY";

// Returns { ok: true, token } on success, { ok: false } on wrong password.
// Pass storedToken=undefined the first time (no token yet) — any password is accepted
// and a fresh verification token is returned for storage.
async function verifyOrInitEncryption(
  password: string,
  login: string,
  owner: string,
  repo: string,
  storedToken: string | undefined
): Promise<{ ok: boolean; token: string | null; isNew: boolean }> {
  const salt = await contextSalt(login, owner, repo);
  const candidateKey = await buildKey(password, salt);

  if (storedToken) {
    // Temporarily swap in the candidate key so decryptContent can use it.
    const previousKey = derivedKey;
    derivedKey = candidateKey;
    const result = await decryptContent(storedToken);
    derivedKey = previousKey;

    if (result === ENCRYPTION_VERIFY_PLAINTEXT) {
      derivedKey = candidateKey;
      return { ok: true, token: storedToken, isNew: false };
    }
    return { ok: false, token: null, isNew: false };
  }

  // First time — accept the password and create the token.
  derivedKey = candidateKey;
  const token = await encryptContent(ENCRYPTION_VERIFY_PLAINTEXT);
  return { ok: true, token, isNew: true };
}

// Compute the same SHA-1 git uses for blob objects: SHA1("blob {size}\0{content}")
// Lets us compare local files against the remote tree without fetching content.
async function gitBlobSha(bytes: Uint8Array): Promise<string> {
  const header = new TextEncoder().encode(`blob ${bytes.length}\0`);
  const combined = new Uint8Array(header.length + bytes.length);
  combined.set(header);
  combined.set(bytes, header.length);
  const hash = await crypto.subtle.digest("SHA-1", combined);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "tif", "svg",
  "pdf", "zip", "gz", "tar", "7z", "rar",
  "mp3", "mp4", "wav", "ogg", "m4a", "flac", "aac",
  "mov", "avi", "mkv", "webm",
  "woff", "woff2", "ttf", "otf", "eot",
  "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "db", "sqlite", "exe", "dll", "so", "dylib",
]);

function isBinaryPath(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return BINARY_EXTENSIONS.has(ext);
}

const MEDIA_ENCRYPT_EXTENSIONS = new Set([
  "md", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "svg", "pdf",
]);

function shouldEncryptPath(path: string, scope: "markdown" | "media" | "all"): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  if (scope === "markdown") return ext === "md";
  if (scope === "media") return MEDIA_ENCRYPT_EXTENSIONS.has(ext);
  return true; // "all"
}

// ── Line-level diff ──────────────────────────────────────────────────────────

type DiffLineType = "add" | "remove" | "context" | "collapse";

interface DiffLine {
  type: DiffLineType;
  content: string;
  oldLine: number | null;
  newLine: number | null;
  collapseCount?: number;
}

function computeLineDiff(oldText: string, newText: string, ctx = 3): DiffLine[] {
  const a = oldText === "" ? [] : oldText.split("\n");
  const b = newText === "" ? [] : newText.split("\n");
  if (a.length + b.length > 5000) {
    return [{ type: "context", content: `(File too large for inline diff — ${a.length} + ${b.length} lines)`, oldLine: null, newLine: null }];
  }

  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  const raw: Array<{ op: "keep" | "add" | "remove"; text: string }> = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) { raw.push({ op: "keep", text: a[i - 1] }); i--; j--; }
    else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) { raw.push({ op: "add", text: b[j - 1] }); j--; }
    else { raw.push({ op: "remove", text: a[i - 1] }); i--; }
  }
  raw.reverse();

  const lines: DiffLine[] = [];
  let oldNo = 1, newNo = 1;
  for (const r of raw) {
    if (r.op === "keep") { lines.push({ type: "context", content: r.text, oldLine: oldNo++, newLine: newNo++ }); }
    else if (r.op === "add") { lines.push({ type: "add", content: r.text, oldLine: null, newLine: newNo++ }); }
    else { lines.push({ type: "remove", content: r.text, oldLine: oldNo++, newLine: null }); }
  }

  // Context collapsing
  if (lines.every(l => l.type === "context")) {
    if (lines.length <= 2 * ctx + 1) return lines;
    return [
      ...lines.slice(0, ctx),
      { type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: lines.length - 2 * ctx },
      ...lines.slice(lines.length - ctx),
    ];
  }

  const keep = new Set<number>();
  lines.forEach((l, idx) => {
    if (l.type !== "context") {
      for (let k = Math.max(0, idx - ctx); k <= Math.min(lines.length - 1, idx + ctx); k++) keep.add(k);
    }
  });

  const result: DiffLine[] = [];
  let collapseFrom = -1;
  for (let idx = 0; idx < lines.length; idx++) {
    if (keep.has(idx)) {
      if (collapseFrom >= 0) {
        result.push({ type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: idx - collapseFrom });
        collapseFrom = -1;
      }
      result.push(lines[idx]);
    } else if (collapseFrom < 0) {
      collapseFrom = idx;
    }
  }
  if (collapseFrom >= 0) {
    result.push({ type: "collapse", content: "", oldLine: null, newLine: null, collapseCount: lines.length - collapseFrom });
  }
  return result;
}


const GH_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "quilden-sync/1.0",
};

const GITEA_HEADERS = {
  Accept: "application/json",
  "User-Agent": "quilden-sync/1.0",
};

function ghHeaders(token: string, extra?: Record<string, string>): Record<string, string> {
  return { ...GH_HEADERS, Authorization: `Bearer ${token}`, ...extra };
}

function apiHeaders(token: string, apiBase: string, extra?: Record<string, string>): Record<string, string> {
  const base = apiBase.includes("api.github.com") ? GH_HEADERS : GITEA_HEADERS;
  return { ...base, Authorization: `token ${token}`, ...extra };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function computeGitBlobSha(content: string, encoding: "utf-8" | "base64"): Promise<string> {
  const contentBytes = encoding === "base64"
    ? fromBase64(content)
    : new TextEncoder().encode(content);
  const prefixBytes = new TextEncoder().encode(`blob ${contentBytes.length}\0`);
  const payload = new Uint8Array(prefixBytes.length + contentBytes.length);
  payload.set(prefixBytes, 0);
  payload.set(contentBytes, prefixBytes.length);
  const digest = await crypto.subtle.digest("SHA-1", payload);
  return bytesToHex(new Uint8Array(digest));
}

interface RepoPermissionSummary {
  admin?: boolean;
  maintain?: boolean;
  push?: boolean;
}

async function uploadBatchBlobs(
  api: GitHubAPI,
  batch: Array<{ path: string; content: string; encoding: "utf-8" | "base64" }>,
  batchNumber: number
): Promise<Array<{ path: string; sha: string; mode: string }>> {
  const concurrency = Math.min(8, batch.length);
  const treeItems = new Array<{ path: string; sha: string; mode: string }>(batch.length);
  let nextIndex = 0;
  let completed = 0;

  const worker = async (): Promise<void> => {
    while (nextIndex < batch.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;

      const file = batch[currentIndex];
      const blobSha = await api.createBlob(file.content, file.encoding);
      console.log(`[LM]   blob ${file.path} → ${blobSha}`);
      treeItems[currentIndex] = { path: file.path, sha: blobSha, mode: "100644" };

      completed += 1;
      if (completed % 5 === 0 || completed === batch.length) {
        console.log(`[LM] batch ${batchNumber}: uploaded ${completed}/${batch.length} blobs`);
      }
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return treeItems;
}

class GitHubAPI {
  private token: string;
  private owner: string;
  private repo: string;
  private branch: string;
  private apiBase: string;
  private webBase: string;

  constructor(
    token: string,
    owner: string,
    repo: string,
    branch: string,
    apiBase = "https://api.github.com",
    webBase = "https://github.com",
  ) {
    this.token = token;
    this.owner = owner;
    this.repo = repo;
    this.branch = branch;
    this.apiBase = apiBase.replace(/\/$/, "");
    this.webBase = webBase.replace(/\/$/, "");
  }

  private async request(method: string, path: string, body?: unknown, _attempt = 0): Promise<any> {
    const url = `${this.apiBase}${path}`;
    const MAX_RETRIES = 4;
    const RETRY_DELAYS_MS = [1000, 3000, 8000, 20000]; // exponential-ish backoff

    let res: { status: number; text: string; headers?: Record<string, string> };
    try {
      res = await requestUrl({
        url,
        method,
        headers: apiHeaders(this.token, this.apiBase, body ? { "Content-Type": "application/json" } : {}),
        body: body ? JSON.stringify(body) : undefined,
        throw: false,
      });
    } catch (networkErr: any) {
      // Transient network error (ERR_NETWORK_CHANGED, ERR_INTERNET_DISCONNECTED, etc.)
      if (_attempt < MAX_RETRIES) {
        const delay = RETRY_DELAYS_MS[_attempt];
        console.warn(`[LM] network error on ${method} ${path} (attempt ${_attempt + 1}), retrying in ${delay}ms:`, networkErr?.message ?? networkErr);
        await new Promise(r => setTimeout(r, delay));
        return this.request(method, path, body, _attempt + 1);
      }
      throw networkErr;
    }

    // Parse response body safely — some providers return non-JSON on errors
    let parsed: any = null;
    try {
      if (res.text) parsed = JSON.parse(res.text);
    } catch {
      // Non-JSON response — leave parsed as null
    }

    // Rate-limited — respect Retry-After header or back off
    if (res.status === 429 || res.status === 403) {
      const retryAfter = res.headers?.["retry-after"];
      const waitMs = retryAfter ? Number(retryAfter) * 1000 : RETRY_DELAYS_MS[_attempt] ?? 20000;
      if (_attempt < MAX_RETRIES) {
        console.warn(`[LM] rate limited on ${method} ${path}, waiting ${waitMs}ms`);
        await new Promise(r => setTimeout(r, waitMs));
        return this.request(method, path, body, _attempt + 1);
      }
    }

    // 5xx server errors — retry
    if (res.status >= 500 && _attempt < MAX_RETRIES) {
      const delay = RETRY_DELAYS_MS[_attempt];
      console.warn(`[LM] server error ${res.status} on ${method} ${path} (attempt ${_attempt + 1}), retrying in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
      return this.request(method, path, body, _attempt + 1);
    }

    if (res.status >= 400) {
      const msg = parsed?.message ?? res.text?.slice(0, 200) ?? res.status;
      console.error(`[LM] API ${method} ${path} → ${res.status}:`, msg);
      throw new Error(`GitHub API error ${res.status} on ${method} ${path}: ${msg}`);
    }
    return parsed;
  }

  static async verifyToken(token: string, apiBase = "https://api.github.com"): Promise<{ login: string; avatar_url: string }> {
    const res = await requestUrl({
      url: `${apiBase}/user`,
      method: "GET",
      headers: apiHeaders(token, apiBase),
      throw: false,
    });
    console.log(`[Quilden] verifyToken status=${res.status} body=`, JSON.stringify(res.json ?? res.text ?? "").slice(0, 200));
    if (res.status === 403) {
      const msg = res.json?.message ?? "";
      if (msg.includes("scope")) throw new Error(`Token missing required scopes. Enable user (Read) + repository (Read and Write) when generating the token.`);
      throw new Error(`Token rejected (403). Check scopes: user (Read) + repository (Read and Write).`);
    }
    if (res.status !== 200) throw new Error(`Invalid token (${res.status})`);
    return res.json;
  }

  static async fetchRepos(token: string, apiBase = "https://api.github.com"): Promise<Array<{ full_name: string; private: boolean }>> {
    const isGitea = apiBase !== "https://api.github.com";
    const url = isGitea
      ? `${apiBase}/repos/search?limit=50&sort=updated&order=desc&token=${encodeURIComponent(token)}`
      : `${apiBase}/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator`;
    const res = await requestUrl({ url, method: "GET", headers: apiHeaders(token, apiBase), throw: false });
    const scopes = res.headers?.["x-oauth-scopes"] ?? "n/a";
    const remaining = res.headers?.["x-ratelimit-remaining"] ?? "?";
    const resetEpoch = res.headers?.["x-ratelimit-reset"];
    const resetTime = resetEpoch ? new Date(Number(resetEpoch) * 1000).toLocaleTimeString() : "unknown";
    console.log(`[LM] fetchRepos status=${res.status} scopes="${scopes}" rate=${remaining} remaining reset=${resetTime}`);
    if (res.status === 403 || res.status === 429) {
      throw new Error(`Rate limit exceeded — resets at ${resetTime}. Wait and try again.`);
    }
    if (res.status >= 400) {
      const msg = res.json?.message ?? res.status;
      throw new Error(`${res.status}: ${msg}`);
    }
    // Gitea search returns { data: [...] }; GitHub returns array directly
    const repos = Array.isArray(res.json) ? res.json : (res.json?.data ?? []);
    return repos;
  }

  static async createRepo(
    token: string,
    name: string,
    isPrivate: boolean,
    apiBase = "https://api.github.com",
  ): Promise<{ full_name: string; private: boolean }> {
    const res = await requestUrl({
      url: `${apiBase}/user/repos`,
      method: "POST",
      headers: apiHeaders(token, apiBase, { "Content-Type": "application/json" }),
      body: JSON.stringify({ name, private: isPrivate, auto_init: true }),
      throw: false,
    });
    if (res.status !== 201) throw new Error(res.json?.message || "Failed to create repo");
    return res.json;
  }

  static async fetchBranches(token: string, owner: string, repo: string, apiBase = "https://api.github.com"): Promise<string[]> {
    const res = await requestUrl({
      url: `${apiBase}/repos/${owner}/${repo}/branches?per_page=100`,
      method: "GET",
      headers: apiHeaders(token, apiBase),
      throw: false,
    });
    if (res.status >= 400) throw new Error(`${res.status}: ${res.json?.message ?? "failed"}`);
    return (res.json as Array<{ name: string }>).map((b) => b.name);
  }

  async getTree(): Promise<{ blobs: Array<{ path: string; sha: string; type: string }>; truncated: boolean }> {
    let data: any;
    try {
      data = await this.request(
        "GET",
        `/repos/${this.owner}/${this.repo}/git/trees/${encodeURIComponent(this.branch)}?recursive=true`
      );
    } catch (e: any) {
      // Empty repo — branch doesn't exist yet (GitHub/Gitea returns 404 or 400 with "sha not found")
      if (e?.message?.includes("404") || e?.message?.includes("400") || e?.message?.includes("sha not found") || e?.message?.includes("not found")) {
        console.log("[LM] getTree: empty repo detected, treating as no remote files");
        return { blobs: [], truncated: false };
      }
      throw e;
    }
    return {
      blobs: (data.tree || []).filter((item: any) => item.type === "blob"),
      truncated: !!data.truncated,
    };
  }

  async getFileContent(path: string): Promise<{ content: string; sha: string }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(this.branch)}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { content: new TextDecoder().decode(bytes), sha: data.sha };
  }

  async getBinaryContent(path: string): Promise<{ buffer: ArrayBuffer; sha: string }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(this.branch)}`
    );
    const b64 = data.content.replace(/\n/g, "");
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { buffer: bytes.buffer, sha: data.sha };
  }

  /** Returns only the blob SHA for a single file, or null if it doesn't exist on the remote. */
  async getFileSha(path: string): Promise<string | null> {
    try {
      const data = await this.request(
        "GET",
        `/repos/${this.owner}/${this.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(this.branch)}`
      );
      return data.sha ?? null;
    } catch (e: any) {
      if (e?.status === 404) return null;
      throw e;
    }
  }

  async getRef(): Promise<string> {
    // Use the branches API — more reliable than /git/refs/heads/ across providers.
    // GitHub returns { commit: { sha } }, Gitea returns { commit: { id } }.
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/branches/${encodeURIComponent(this.branch)}`
    );
    const sha = data?.commit?.sha ?? data?.commit?.id;
    if (!sha) throw new Error(`Ref not found for branch ${this.branch}`);
    return sha;
  }

  async getCommit(sha: string): Promise<{ treeSha: string }> {
    const data = await this.request("GET", `/repos/${this.owner}/${this.repo}/git/commits/${sha}`);
    return { treeSha: data.tree.sha };
  }

  async createBlob(content: string, encoding: "utf-8" | "base64" = "utf-8"): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/blobs`, { content, encoding });
    return data.sha;
  }

  async createTree(baseTreeSha: string, items: Array<{ path: string; sha: string | null; mode: string }>): Promise<string> {
    const body: Record<string, unknown> = {
      tree: items.map((i) => ({ path: i.path, mode: i.mode, type: "blob", sha: i.sha })),
    };
    if (baseTreeSha) body.base_tree = baseTreeSha; // omit for initial commit (empty repo)
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/trees`, body);
    return data.sha;
  }

  async createCommit(message: string, treeSha: string, parentSha: string): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/commits`, {
      message,
      tree: treeSha,
      parents: [parentSha],
    });
    return data.sha;
  }

  /** Create a root commit (no parents) for an empty repo. */
  async createInitialCommit(message: string, treeSha: string): Promise<string> {
    const data = await this.request("POST", `/repos/${this.owner}/${this.repo}/git/commits`, {
      message,
      tree: treeSha,
      parents: [],
    });
    return data.sha;
  }

  async updateRef(sha: string): Promise<void> {
    await this.request("PATCH", `/repos/${this.owner}/${this.repo}/git/refs/heads/${encodeURIComponent(this.branch)}`, {
      sha,
      force: true,
    });
  }

  /** Create a new branch ref (used when the repo has no commits yet). */
  async createRef(sha: string): Promise<void> {
    await this.request("POST", `/repos/${this.owner}/${this.repo}/git/refs`, {
      ref: `refs/heads/${this.branch}`,
      sha,
    });
  }

  /** True if the branch doesn't exist yet (empty repo or new branch). */
  async isBranchEmpty(): Promise<boolean> {
    try {
      await this.getRef();
      return false;
    } catch {
      return true;
    }
  }

  /**
   * Initialize an empty repo via the Contents API (works before the Git Data API is available).
   * Creates a placeholder commit so subsequent Git Data API calls succeed.
   * Idempotent: if the placeholder already exists (previous failed sync), fetches its SHA and updates it.
   */
  async initializeRepo(): Promise<void> {
    try {
      // Commit .gitkeep directly to the target branch.
      await this.request("PUT", `/repos/${this.owner}/${this.repo}/contents/.gitkeep`, {
        message: "Initialize repository",
        content: btoa(""),
        branch: this.branch,
      });
      return; // success
    } catch (e: any) {
      const msg = e?.message ?? "";
      // 422 [SHA]: Required → file already exists on some branch (Gitea falls back to
      // default branch when the specified branch doesn't exist).
      if (msg.includes("422") || msg.includes("SHA") || msg.includes("sha")) {
        // Check if our target branch now exists (happy path)
        try { await this.getRef(); console.log("[LM] initializeRepo: branch already initialized"); return; } catch {}
        // Branch still doesn't exist — .gitkeep lives on a different branch (e.g. master).
        // Create our branch from whatever branch already has a commit.
        console.log("[LM] initializeRepo: .gitkeep on different branch — creating target branch");
        await this.createBranchFromExisting();
        return;
      }
      throw e;
    }
  }

  /** Creates `this.branch` ensuring the repo has at least one commit first. */
  private async createBranchFromExisting(): Promise<void> {
    // Use repo info to understand actual state — more reliable than GET /branches
    const repoInfo = await this.request("GET", `/repos/${this.owner}/${this.repo}`);
    const defaultBranch: string = repoInfo?.default_branch ?? "master";
    const repoEmpty: boolean = repoInfo?.empty === true;
    console.log(`[LM] createBranchFromExisting: default_branch=${defaultBranch}, empty=${repoEmpty}, target=${this.branch}`);

    if (!repoEmpty) {
      // Repo has commits. Get SHA from the default branch and create our target from it.
      try {
        const defData = await this.request("GET", `/repos/${this.owner}/${this.repo}/branches/${defaultBranch}`);
        const sha = defData?.commit?.sha ?? defData?.commit?.id;
        if (!sha) throw new Error("no SHA in branch data");
        console.log(`[LM] createBranchFromExisting: creating ${this.branch} from ${defaultBranch} @ ${sha.slice(0, 7)}`);
        await this.request("POST", `/repos/${this.owner}/${this.repo}/git/refs`, {
          ref: `refs/heads/${this.branch}`,
          sha,
        });
        return;
      } catch (e: any) {
        console.warn(`[LM] createBranchFromExisting: failed to branch from ${defaultBranch}: ${e?.message}`);
      }

      // Fallback: list all git refs and use the first commit SHA we find
      try {
        const refs = await this.request("GET", `/repos/${this.owner}/${this.repo}/git/refs`);
        console.log(`[LM] createBranchFromExisting: git/refs = ${JSON.stringify(refs)?.slice(0, 300)}`);
        const firstRef = Array.isArray(refs) ? refs[0] : null;
        const sha = firstRef?.object?.sha;
        if (sha) {
          await this.request("POST", `/repos/${this.owner}/${this.repo}/git/refs`, {
            ref: `refs/heads/${this.branch}`,
            sha,
          });
          return;
        }
      } catch (e: any) {
        console.warn(`[LM] createBranchFromExisting: git/refs fallback failed: ${e?.message}`);
      }
    }

    // Truly empty repo (or couldn't get SHA from existing branches).
    // Create the very first commit without specifying a branch — Gitea uses default_branch.
    console.log("[LM] createBranchFromExisting: creating initial commit on default branch");
    await this.request("PUT", `/repos/${this.owner}/${this.repo}/contents/.gitkeep`, {
      message: "Initialize repository",
      content: btoa("\n"),
    });

    // If the newly created branch ≠ our target, create a ref from it.
    if (defaultBranch !== this.branch) {
      const defData = await this.request("GET", `/repos/${this.owner}/${this.repo}/branches/${defaultBranch}`);
      const sha = defData?.commit?.sha ?? defData?.commit?.id;
      if (!sha) throw new Error(`Cannot get SHA after initial commit on ${defaultBranch}`);
      await this.request("POST", `/repos/${this.owner}/${this.repo}/git/refs`, {
        ref: `refs/heads/${this.branch}`,
        sha,
      });
    }
  }

  async getFileCommits(path: string): Promise<Array<{ sha: string; parentSha: string | null; message: string; author: string; date: string }>> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/commits?path=${encoded}&sha=${encodeURIComponent(this.branch)}&per_page=30`
    );
    return (data as any[]).map((c: any) => ({
      sha: c.sha,
      parentSha: (c.parents as any[])?.[0]?.sha ?? null,
      message: (c.commit.message as string).split("\n")[0].slice(0, 80),
      author: c.commit.author?.name ?? c.commit.committer?.name ?? "Unknown",
      date: c.commit.author?.date ? new Date(c.commit.author.date).toLocaleString() : "",
    }));
  }

  async getFileAtCommit(path: string, commitSha: string): Promise<{ content: string }> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${commitSha}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { content: new TextDecoder().decode(bytes) };
  }

  async getBinaryContentAtCommit(path: string, commitSha: string): Promise<{ buffer: ArrayBuffer }> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${commitSha}`
    );
    const raw = atob(data.content.replace(/\n/g, ""));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return { buffer: bytes.buffer };
  }

  async getBranchCommits(page = 1, perPage = 100): Promise<{
    commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }>;
    hasMore: boolean;
  }> {
    const data = await this.request(
      "GET",
      `/repos/${this.owner}/${this.repo}/commits?sha=${encodeURIComponent(this.branch)}&per_page=${perPage}&page=${page}`
    );
    const commits = (data as any[]).map((c: any) => ({
      sha: c.sha,
      message: (c.commit.message as string).split("\n")[0].slice(0, 80),
      author: c.commit.author?.name ?? c.commit.committer?.name ?? "Unknown",
      date: c.commit.author?.date ?? c.commit.committer?.date ?? "",
      treeSha: c.commit.tree?.sha ?? "",
    }));
    return { commits, hasMore: commits.length === perPage };
  }

  getCommitUrl(sha: string): string {
    return `${this.webBase}/${this.owner}/${this.repo}/commit/${sha}`;
  }

  async restoreToCommit(targetSha: string, message: string): Promise<string> {
    // Get the tree SHA of the target commit
    const targetCommit = await this.request("GET", `/repos/${this.owner}/${this.repo}/git/commits/${targetSha}`);
    const treeSha = targetCommit.tree.sha;

    // Get current HEAD to use as parent
    const currentHeadSha = await this.getRef();

    // Create a new commit with the old tree on top of current HEAD
    const newCommitSha = await this.createCommit(message, treeSha, currentHeadSha);

    // Point the branch ref to the new commit
    await this.updateRef(newCommitSha);

    return newCommitSha;
  }

  // Create or update a single file via the Contents API (one-shot, no tree/commit dance).
  async putFile(path: string, textContent: string, message: string): Promise<void> {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    // Need existing SHA when updating, so the API knows it's an update not a collision.
    let existingSha: string | undefined;
    try {
      const existing = await this.request(
        "GET",
        `/repos/${this.owner}/${this.repo}/contents/${encoded}?ref=${encodeURIComponent(this.branch)}`
      );
      existingSha = existing.sha;
    } catch { /* file doesn't exist yet — that's fine */ }

    // GitHub Contents API expects base64-encoded file content.
    const b64 = btoa(unescape(encodeURIComponent(textContent)));
    await this.request("PUT", `/repos/${this.owner}/${this.repo}/contents/${encoded}`, {
      message,
      content: b64,
      branch: this.branch,
      ...(existingSha ? { sha: existingSha } : {}),
    });
  }
}


// ── File History Modal ─────────────────────────────────────────────────────────

class FileHistoryModal extends Modal {
  private file: TFile;
  private api: GitHubAPI;
  private encryptionEnabled: boolean;
  private commits: Array<{ sha: string; parentSha: string | null; message: string; author: string; date: string }> = [];
  private selectedIdx = -1;
  private selectedContent: string | null = null; // null = not loaded, "__binary__" = binary
  private diffEl!: HTMLElement;
  private restoreBtn!: HTMLButtonElement;
  private leftEl?: HTMLElement;
  private mobileSelect?: HTMLSelectElement;
  private isMobileLayout = false;
  private previewBlobUrl: string | null = null;

  constructor(app: App, file: TFile, api: GitHubAPI, encryptionEnabled: boolean) {
    super(app);
    this.file = file;
    this.api = api;
    this.encryptionEnabled = encryptionEnabled;
  }

  async onOpen() {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    contentEl.addClass("lm-history-modal");

    // Bigger modal
    modalEl.style.width = "min(90vw, 1000px)";
    modalEl.style.height = "85vh";
    modalEl.style.maxHeight = "85vh";

    this.isMobileLayout = Platform.isMobile || modalEl.offsetWidth < 550;

    contentEl.createEl("h3", { text: `History: ${this.file.name}`, cls: "lm-history-title" });

    if (this.isMobileLayout) {
      this.buildMobileLayout(contentEl);
    } else {
      this.buildDesktopLayout(contentEl);
    }

    await this.loadCommits();
  }

  private buildDesktopLayout(contentEl: HTMLElement) {
    const body = contentEl.createDiv({ cls: "lm-history-body" });

    this.leftEl = body.createDiv({ cls: "lm-history-left" });
    this.leftEl.createEl("p", { text: "Loading…", cls: "lm-history-status" });

    const rightEl = body.createDiv({ cls: "lm-history-right" });
    this.diffEl = rightEl.createDiv({ cls: "lm-history-diff" });
    this.diffEl.createEl("p", { text: "Select a version to view diff.", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-history-footer" });
    this.restoreBtn = footer.createEl("button", { text: "Restore this version", cls: "lm-restore-btn mod-cta" });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.restore());
  }

  private buildMobileLayout(contentEl: HTMLElement) {
    const selectWrap = contentEl.createDiv({ cls: "lm-history-mobile-select-wrap" });
    this.mobileSelect = selectWrap.createEl("select", { cls: "lm-history-mobile-select" });
    const placeholder = this.mobileSelect.createEl("option");
    placeholder.value = "";
    placeholder.textContent = "Loading…";
    placeholder.disabled = true;
    placeholder.selected = true;

    this.diffEl = contentEl.createDiv({ cls: "lm-history-diff lm-history-diff-mobile" });
    this.diffEl.createEl("p", { text: "Select a version to view diff.", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-history-footer" });
    this.restoreBtn = footer.createEl("button", { text: "Restore this version", cls: "lm-restore-btn mod-cta" });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.restore());

    this.mobileSelect.addEventListener("change", () => {
      const idx = parseInt(this.mobileSelect!.value);
      if (!isNaN(idx)) this.selectCommit(idx);
    });
  }

  private async loadCommits() {
    try {
      this.commits = await this.api.getFileCommits(this.file.path);

      if (this.isMobileLayout && this.mobileSelect) {
        this.mobileSelect.innerHTML = "";
        if (this.commits.length === 0) {
          const opt = this.mobileSelect.createEl("option");
          opt.textContent = "No history found";
          opt.disabled = true;
          opt.selected = true;
        } else {
          const ph = this.mobileSelect.createEl("option");
          ph.value = "";
          ph.textContent = "Select a version…";
          ph.disabled = true;
          ph.selected = true;
          this.commits.forEach((c, idx) => {
            const opt = this.mobileSelect!.createEl("option");
            opt.value = String(idx);
            opt.textContent = `${c.message} — ${c.date}`;
          });
        }
      } else if (this.leftEl) {
        this.leftEl.empty();
        if (this.commits.length === 0) {
          this.leftEl.createEl("p", { text: "No history found for this file.", cls: "lm-history-status" });
          return;
        }
        this.commits.forEach((c, idx) => {
          const item = this.leftEl!.createDiv({ cls: "lm-commit-item" });
          item.createEl("div", { text: c.message, cls: "lm-commit-msg" });
          item.createEl("div", { text: `${c.author} · ${c.date}`, cls: "lm-commit-meta" });
          item.addEventListener("click", () => {
            this.leftEl!.querySelectorAll<HTMLElement>(".lm-commit-item").forEach(el =>
              el.classList.remove("lm-commit-selected")
            );
            item.classList.add("lm-commit-selected");
            this.selectCommit(idx);
          });
        });
      }
    } catch (e: any) {
      const msg = e.message?.includes("401")
        ? "Authentication failed — token may be expired. Reconnect in settings."
        : `Error: ${e.message}`;
      if (this.isMobileLayout && this.mobileSelect) {
        this.mobileSelect.innerHTML = "";
        const opt = this.mobileSelect.createEl("option");
        opt.textContent = msg;
        opt.disabled = true;
        opt.selected = true;
      } else if (this.leftEl) {
        this.leftEl.empty();
        this.leftEl.createEl("p", { text: msg, cls: "lm-history-error" });
      }
    }
  }

  private async selectCommit(idx: number) {
    this.selectedIdx = idx;
    this.selectedContent = null;
    this.restoreBtn.disabled = true;
    this.diffEl.empty();
    this.diffEl.createEl("p", { text: "Loading diff…", cls: "lm-history-status" });

    const commit = this.commits[idx];
    if (!commit) return;

    try {
      if (isBinaryPath(this.file.path)) {
        this.diffEl.empty();
        // Revoke previous blob URL to avoid memory leaks
        if (this.previewBlobUrl) { URL.revokeObjectURL(this.previewBlobUrl); this.previewBlobUrl = null; }

        const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "svg"]);
        const ext = this.file.extension.toLowerCase();

        if (IMAGE_EXTS.has(ext)) {
          this.diffEl.createEl("p", { text: "Loading preview…", cls: "lm-history-status" });
          try {
            const { buffer } = await this.api.getBinaryContentAtCommit(this.file.path, commit.sha);
            this.diffEl.empty();

            const header = this.diffEl.createDiv({ cls: "lm-diff-header" });
            header.createEl("span", { text: commit.message, cls: "lm-diff-commit-msg" });
            header.createEl("span", { text: ` · ${commit.author}, ${commit.date}`, cls: "lm-diff-commit-meta" });

            const MIME: Record<string, string> = {
              jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
              gif: "image/gif", webp: "image/webp", bmp: "image/bmp",
              tiff: "image/tiff", tif: "image/tiff", svg: "image/svg+xml",
            };
            const blob = new Blob([buffer], { type: MIME[ext] ?? "application/octet-stream" });
            this.previewBlobUrl = URL.createObjectURL(blob);

            const wrap = this.diffEl.createDiv({ cls: "lm-history-img-wrap" });
            const img = wrap.createEl("img", { cls: "lm-history-img" });
            img.src = this.previewBlobUrl;
            wrap.createEl("p", {
              text: `${this.file.name} · ${(buffer.byteLength / 1024).toFixed(1)} KB`,
              cls: "lm-history-img-meta",
            });
          } catch (e: any) {
            this.diffEl.empty();
            this.diffEl.createEl("p", { text: `Preview error: ${e.message}`, cls: "lm-history-error" });
          }
        } else {
          this.diffEl.createEl("p", { text: "Binary file — preview not available.", cls: "lm-history-status" });
        }

        this.selectedContent = "__binary__";
        this.restoreBtn.disabled = false;
        return;
      }

      // Fetch this version
      const { content: currentRaw } = await this.api.getFileAtCommit(this.file.path, commit.sha);
      let current = currentRaw;
      if (this.encryptionEnabled && isEncryptedContent(currentRaw)) {
        current = (await decryptContent(currentRaw)) ?? currentRaw;
      }
      this.selectedContent = currentRaw;

      // Fetch parent version for diff
      let parent = "";
      if (commit.parentSha) {
        try {
          const { content: parentRaw } = await this.api.getFileAtCommit(this.file.path, commit.parentSha);
          parent = parentRaw;
          if (this.encryptionEnabled && isEncryptedContent(parentRaw)) {
            parent = (await decryptContent(parentRaw)) ?? parentRaw;
          }
        } catch {
          parent = ""; // File didn't exist in parent commit
        }
      }

      const diff = computeLineDiff(parent, current);
      this.diffEl.empty();
      this.renderDiff(this.diffEl, diff, commit);
      this.restoreBtn.disabled = false;
    } catch (e: any) {
      this.diffEl.empty();
      this.diffEl.createEl("p", { text: `Error: ${e.message}`, cls: "lm-history-error" });
    }
  }

  private renderDiff(
    container: HTMLElement,
    diff: DiffLine[],
    commit: { message: string; author: string; date: string }
  ) {
    const header = container.createDiv({ cls: "lm-diff-header" });
    header.createEl("span", { text: commit.message, cls: "lm-diff-commit-msg" });
    header.createEl("span", { text: ` · ${commit.author}, ${commit.date}`, cls: "lm-diff-commit-meta" });

    if (diff.length === 0) {
      container.createEl("p", { text: "No changes to this file in this commit.", cls: "lm-history-status" });
      return;
    }

    const table = container.createEl("table", { cls: "lm-diff-table" });
    const tbody = table.createEl("tbody");

    for (const line of diff) {
      if (line.type === "collapse") {
        const tr = tbody.createEl("tr", { cls: "lm-diff-collapse" });
        tr.createEl("td", { cls: "lm-diff-ln" });
        tr.createEl("td", { cls: "lm-diff-ln" });
        tr.createEl("td", { cls: "lm-diff-sign" });
        tr.createEl("td", {
          text: `… ${line.collapseCount} unchanged line${line.collapseCount !== 1 ? "s" : ""}`,
          cls: "lm-diff-code",
        });
        continue;
      }

      const tr = tbody.createEl("tr", { cls: `lm-diff-${line.type}` });
      tr.createEl("td", { text: line.oldLine !== null ? String(line.oldLine) : "", cls: "lm-diff-ln lm-diff-ln-old" });
      tr.createEl("td", { text: line.newLine !== null ? String(line.newLine) : "", cls: "lm-diff-ln lm-diff-ln-new" });
      tr.createEl("td", {
        text: line.type === "add" ? "+" : line.type === "remove" ? "−" : " ",
        cls: "lm-diff-sign",
      });
      tr.createEl("td", { text: line.content, cls: "lm-diff-code" });
    }
  }

  private async restore() {
    if (this.selectedIdx < 0 || this.selectedContent === null) return;
    this.restoreBtn.disabled = true;
    this.restoreBtn.textContent = "Restoring…";

    const commit = this.commits[this.selectedIdx];
    try {
      if (this.selectedContent === "__binary__") {
        const { buffer } = await this.api.getBinaryContentAtCommit(this.file.path, commit.sha);
        await this.app.vault.modifyBinary(this.file, buffer);
      } else {
        let final = this.selectedContent;
        if (this.encryptionEnabled && isEncryptedContent(this.selectedContent)) {
          final = (await decryptContent(this.selectedContent)) ?? this.selectedContent;
        }
        await this.app.vault.modify(this.file, final);
      }
      new Notice(`Restored: ${this.file.name}`);
      this.close();
    } catch (e: any) {
      new Notice(`Restore failed: ${e.message}`);
      this.restoreBtn.disabled = false;
      this.restoreBtn.textContent = "Restore this version";
    }
  }

  onClose() {
    if (this.previewBlobUrl) { URL.revokeObjectURL(this.previewBlobUrl); this.previewBlobUrl = null; }
    this.contentEl.empty();
  }
}


// ── Branch Timeline Modal ──────────────────────────────────────────────────────

class BranchTimelineModal extends Modal {
  private api: GitHubAPI;
  private plugin: QuildenSyncPlugin;
  private commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }> = [];
  private selectedSha: string | null = null;
  private restoreBtn!: HTMLButtonElement;
  private itemEls: HTMLElement[] = [];
  private listEl!: HTMLElement;
  private loadMoreBtn!: HTMLButtonElement;
  private currentPage = 1;
  private hasMore = false;
  private loadingMore = false;

  constructor(app: App, api: GitHubAPI, plugin: QuildenSyncPlugin) {
    super(app);
    this.api = api;
    this.plugin = plugin;
  }

  async onOpen() {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    contentEl.addClass("lm-timeline-modal");

    modalEl.style.width = "min(90vw, 700px)";
    modalEl.style.height = "85vh";
    modalEl.style.maxHeight = "85vh";

    contentEl.createEl("h3", { text: "Branch Timeline", cls: "lm-timeline-title" });
    contentEl.createEl("p", {
      text: "Select a past commit to restore the entire repo to that state. A new commit is created on the branch — no history is lost.",
      cls: "lm-timeline-subtitle",
    });

    const scrollEl = contentEl.createDiv({ cls: "lm-timeline-scroll" });
    scrollEl.createEl("p", { text: "Loading timeline…", cls: "lm-history-status" });

    const footer = contentEl.createDiv({ cls: "lm-timeline-footer" });
    this.restoreBtn = footer.createEl("button", {
      text: "Restore to selected point",
      cls: "lm-restore-btn mod-cta",
    });
    this.restoreBtn.disabled = true;
    this.restoreBtn.addEventListener("click", () => this.confirmAndRestore());

    await this.loadPage(scrollEl, true);
  }

  private async loadPage(scrollEl: HTMLElement, isFirst: boolean) {
    try {
      const { commits, hasMore } = await this.api.getBranchCommits(this.currentPage);
      this.hasMore = hasMore;

      if (isFirst) {
        scrollEl.empty();
        if (commits.length === 0) {
          scrollEl.createEl("p", { text: "No commits found on this branch.", cls: "lm-history-status" });
          return;
        }
        this.listEl = scrollEl.createDiv({ cls: "lm-timeline-list" });
        this.loadMoreBtn = scrollEl.createEl("button", { cls: "lm-timeline-load-more" });
        this.loadMoreBtn.addEventListener("click", async () => {
          if (this.loadingMore) return;
          this.loadingMore = true;
          this.loadMoreBtn.textContent = "Loading…";
          this.loadMoreBtn.disabled = true;
          this.currentPage++;
          await this.loadPage(scrollEl, false);
          this.loadingMore = false;
        });
      }

      const globalOffset = this.commits.length;
      this.commits.push(...commits);
      this.appendCommitItems(commits, globalOffset);

      // Update "Load more" button visibility
      if (hasMore) {
        this.loadMoreBtn.textContent = "Load more commits";
        this.loadMoreBtn.disabled = false;
        this.loadMoreBtn.style.display = "";
      } else {
        this.loadMoreBtn.style.display = "none";
      }
    } catch (e: any) {
      if (isFirst) {
        scrollEl.empty();
        scrollEl.createEl("p", { text: `Failed to load timeline: ${e.message}`, cls: "lm-history-error" });
      } else {
        new Notice(`Failed to load more commits: ${e.message}`, 5000);
        this.loadMoreBtn.textContent = "Load more commits";
        this.loadMoreBtn.disabled = false;
      }
    }
  }

  private appendCommitItems(
    commits: Array<{ sha: string; message: string; author: string; date: string; treeSha: string }>,
    startIdx: number
  ) {
    commits.forEach((commit, localIdx) => {
      const globalIdx = startIdx + localIdx;
      const isHead = globalIdx === 0;

      // Remove connector from previous last item before adding new ones
      if (localIdx === 0 && globalIdx > 0 && this.itemEls.length > 0) {
        const prevLast = this.itemEls[this.itemEls.length - 1];
        const prevNodeCol = prevLast.querySelector<HTMLElement>(".lm-timeline-node-col");
        if (prevNodeCol && !prevNodeCol.querySelector(".lm-timeline-connector")) {
          prevNodeCol.createDiv({ cls: "lm-timeline-connector" });
        }
      }

      const item = this.listEl.createDiv({
        cls: "lm-timeline-item" + (isHead ? " lm-timeline-item-head" : ""),
      });
      this.itemEls.push(item);

      // Left column: node dot + connector line
      const nodeCol = item.createDiv({ cls: "lm-timeline-node-col" });
      nodeCol.createDiv({ cls: "lm-timeline-node" + (isHead ? " lm-timeline-node-head" : "") });
      // Connector is added for all except the last item; we add it when more items load
      if (localIdx < commits.length - 1 || this.hasMore) {
        nodeCol.createDiv({ cls: "lm-timeline-connector" });
      }

      // Right column: commit details
      const content = item.createDiv({ cls: "lm-timeline-content" });

      const topRow = content.createDiv({ cls: "lm-timeline-top-row" });
      if (isHead) {
        topRow.createEl("span", { text: "LATEST", cls: "lm-timeline-badge" });
      }

      // GitHub link button — opens the commit page on GitHub
      const ghLink = topRow.createEl("a", { cls: "lm-timeline-gh-link", text: "View on GitHub ↗" });
      ghLink.href = this.api.getCommitUrl(commit.sha);
      ghLink.target = "_blank";
      ghLink.rel = "noopener";
      ghLink.title = `Open commit ${commit.sha.slice(0, 7)} on GitHub`;
      ghLink.addEventListener("click", (e) => e.stopPropagation());

      content.createEl("div", { text: commit.message, cls: "lm-timeline-msg" });

      const meta = content.createDiv({ cls: "lm-timeline-meta-row" });
      meta.createEl("span", { text: commit.author, cls: "lm-timeline-author" });
      meta.createEl("span", { text: " · ", cls: "lm-timeline-sep" });
      meta.createEl("span", { text: this.relativeTime(commit.date), cls: "lm-timeline-date" });
      meta.createEl("code", { text: commit.sha.slice(0, 7), cls: "lm-timeline-sha" });

      if (!isHead) {
        item.style.cursor = "pointer";
        item.addEventListener("click", () => this.selectCommit(globalIdx, item));
      } else {
        item.title = "Current HEAD — nothing to restore to";
      }
    });
  }

  private selectCommit(idx: number, itemEl: HTMLElement) {
    this.itemEls.forEach(el => el.classList.remove("lm-timeline-item-selected"));
    itemEl.classList.add("lm-timeline-item-selected");
    this.selectedSha = this.commits[idx].sha;
    this.restoreBtn.disabled = false;
    const msg = this.commits[idx].message;
    const label = msg.length > 42 ? msg.slice(0, 42) + "…" : msg;
    this.restoreBtn.textContent = `Restore to "${label}"`;
  }

  private relativeTime(isoDate: string): string {
    if (!isoDate) return "";
    const diffMs = Date.now() - new Date(isoDate).getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    if (days < 30) return `${days}d ago`;
    return new Date(isoDate).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
  }

  private async confirmAndRestore() {
    if (!this.selectedSha) return;
    const commit = this.commits.find(c => c.sha === this.selectedSha);
    if (!commit) return;

    const confirmed = confirm(
      `Restore entire repo to commit:\n"${commit.message.slice(0, 72)}"\n\n` +
      `SHA: ${commit.sha.slice(0, 7)}  ·  ${commit.author}  ·  ${this.relativeTime(commit.date)}\n\n` +
      "A new commit will be created on the branch with all files reverted to this state.\n" +
      "Your current state will remain accessible in the git history."
    );
    if (!confirmed) return;

    this.restoreBtn.disabled = true;
    this.restoreBtn.textContent = "Restoring…";

    try {
      await this.api.restoreToCommit(
        commit.sha,
        `Quilden: Restore to ${commit.sha.slice(0, 7)} — ${commit.message.slice(0, 60)}`
      );
      new Notice(`Restored to "${commit.message.slice(0, 40)}" ✓ — pulling restored state…`, 6000);
      this.close();
      await this.plugin.runSync("pull");
    } catch (e: any) {
      new Notice(`Restore failed: ${e.message}`, 8000);
      this.restoreBtn.disabled = false;
      this.restoreBtn.textContent = "Restore to selected point";
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}


export default class QuildenSyncPlugin extends Plugin {
  settings: QuildenSyncSettings = DEFAULT_SETTINGS;
  private syncInterval: number | null = null;
  private saveDebounce: number | null = null;
  private networkRetryTimer: number | null = null;
  private syncing = false;
  private statusBarEl: HTMLElement | null = null;
  private statusIconEl: HTMLElement | null = null;
  private statusMsgEl: HTMLElement | null = null;
  private ribbonEl: HTMLElement | null = null;
  private syncHistory: SyncHistoryEntry[] = [];
  private lastSyncTime: Date | null = null;
  // Accumulates paths during a sync run, reset at start of runSync
  private _syncPushedPaths: string[] = [];
  private _syncPulledPaths: string[] = [];
  private encryptionVerifyToken: string | null = null;
  private encryptionKeyBytes: string | null = null; // exported AES key bytes, persisted in data.json

  get hasExistingEncryption(): boolean {
    return !!this.encryptionVerifyToken;
  }

  // ── Encryption key localStorage helpers ──────────────────────────────────
  // We store the DERIVED KEY BYTES (not the password) so the plaintext password
  // is never persisted anywhere. Key bytes are device-local and scoped to one
  // repo — unlike a password they cannot be reused on other services.
  get hasSavedKey(): boolean {
    return !!this.encryptionKeyBytes;
  }

  /** Export current derivedKey bytes and persist to data.json. Never stores the password. */
  async saveEncKey(): Promise<void> {
    const exported = await exportDerivedKey();
    if (!exported) {
      console.warn("[LM] saveEncKey: exportDerivedKey returned null — derivedKey may not be set");
      return;
    }
    this.encryptionKeyBytes = exported;
    await this.savePluginData();
    console.log("[LM] saveEncKey: key bytes saved to data.json");
  }

  /** Import persisted key bytes and apply as active derivedKey. Returns true on success. */
  async loadAndApplyEncKey(): Promise<boolean> {
    if (!this.encryptionKeyBytes) {
      console.log("[LM] loadAndApplyEncKey: no key bytes in data.json");
      return false;
    }
    const ok = await importDerivedKey(this.encryptionKeyBytes);
    console.log(`[LM] loadAndApplyEncKey: ${ok ? "success" : "failed — key bytes may be corrupt"}`);
    return ok;
  }

  clearEncKey(): void {
    this.encryptionKeyBytes = null;
    this.savePluginData().catch(() => {});
  }

  // ── SyncState localStorage helpers ───────────────────────────────────────
  // Stored device-locally so iCloud (or any other vault sync) can't overwrite
  // sync progress saved on this device.
  private syncStateStorageKey(): string {
    return `quilden:syncstate:${this.settings.repoOwner}/${this.settings.repoName}/${this.settings.branch}`;
  }

  private saveSyncStateToLocalStorage(): void {
    try {
      const key = this.syncStateStorageKey();
      window.localStorage.setItem(key, JSON.stringify(this.syncState));
    } catch { /* localStorage unavailable */ }
  }

  private loadSyncStateFromLocalStorage(): { repoKey: string; files: Record<string, SyncedFileState> } | null {
    try {
      const key = this.syncStateStorageKey();
      const raw = window.localStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.repoKey === "string" && typeof parsed.files === "object") {
        return parsed as { repoKey: string; files: Record<string, SyncedFileState> };
      }
      return null;
    } catch { return null; }
  }

  private syncState: { repoKey: string; files: Record<string, SyncedFileState> } = {
    repoKey: "",
    files: {},
  };

  async onload() {
    await this.loadSettings();

    // Auto-unlock encryption using saved key bytes (never the password).
    // Awaited so derivedKey is set before any UI or sync runs.
    if (this.settings.encryptionEnabled && this.isConfigured()) {
      await this.loadAndApplyEncKey().catch(() => {});
    }

    this.statusBarEl = this.addStatusBarItem();
    this.statusBarEl.addClass("quilden-sync-status");
    this.statusBarEl.title = "Quilden Sync — click for history";
    this.statusBarEl.addEventListener("click", () => this.showSyncHistoryPopup());
    this.statusIconEl = this.statusBarEl.createSpan({ cls: "lm-status-icon", text: "⇅" });
    this.statusMsgEl = this.statusBarEl.createSpan({ cls: "lm-status-msg" });
    this.updateStatusBar("idle");

    this.ribbonEl = this.addRibbonIcon("refresh-cw", "Quilden Sync", async () => {
      await this.runSync();
    });

    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.runSync() });
    this.addCommand({ id: "sync-pull", name: "Pull from GitHub", callback: () => this.runSync("pull") });
    this.addCommand({ id: "sync-push", name: "Push to GitHub", callback: () => this.runSync("push") });
    this.addCommand({
      id: "copy-token-for-quilden",
      name: "Copy GitHub token for Quilden sign-in",
      callback: () => this.copyTokenForQuilden(),
    });
    this.addCommand({
      id: "branch-timeline",
      name: "Restore from branch timeline",
      callback: () => {
        if (!this.isConfigured()) {
          new Notice("Quilden Sync: Configure your repo first.");
          return;
        }
        const api = this.buildGitAPI();
        new BranchTimelineModal(this.app, api, this).open();
      },
    });

    this.addCommand({
      id: "file-history",
      name: "Browse file history",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || !this.isConfigured()) return false;
        if (!checking) this.openFileHistory(file);
        return true;
      },
    });

    // Right-click → file menu
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => {
        if (!(file instanceof TFile) || !this.isConfigured()) return;
        menu.addItem((item) => {
          item
            .setTitle("Browse file history")
            .setIcon("history")
            .onClick(() => this.openFileHistory(file));
        });
      })
    );

    this.addSettingTab(new QuildenSyncSettingTab(this.app, this));

    // Handle OAuth deep link from browser: obsidian://quilden-auth?token=...&login=...
    this.registerObsidianProtocolHandler("quilden-auth", async (params) => {
      const token = typeof params.token === "string" ? params.token : "";
      const login = typeof params.login === "string" ? params.login : "";
      const refreshToken = typeof params.refreshToken === "string" ? params.refreshToken : "";
      if (!token || !login) return;
      this.settings.githubToken = token;
      this.settings.githubRefreshToken = refreshToken;
      this.settings.githubUsername = login;
      await this.saveSettings();
      new Notice(`Quilden Sync: Connected as @${login} ✓`);
      // Refresh open settings tab if visible
      (this.app as any).setting?.activeTab?.display?.();
    });

    // Encrypted-file guard — intercept opening any file with QENC content
    this.registerEvent(
      this.app.workspace.on("file-open", async (file) => {
        if (!file || isBinaryPath(file.path)) return;
        if (this._pendingDecrypt.has(file.path)) return;
        try {
          const content = await this.app.vault.read(file);
          if (!isEncryptedContent(content)) return;

          if (derivedKey) {
            // Key already loaded — silently decrypt in place
            const dec = await decryptContent(content);
            if (dec !== null) {
              this.pulling = true;
              try {
                await this.app.vault.modify(file, dec);
                if (this.syncState?.files) delete this.syncState.files[file.path];
                await this.savePluginData();
              } finally {
                this.pulling = false;
              }
            }
          } else {
            // No key — prompt the user
            this._pendingDecrypt.add(file.path);
            new EncryptedFileModal(this.app, file, this, () => {
              this._pendingDecrypt.delete(file.path);
            }).open();
            // Also register close cleanup in case user cancels
            const cleanup = () => this._pendingDecrypt.delete(file.path);
            setTimeout(cleanup, 60_000); // fallback: clear after 60s
          }
        } catch { /* ignore read errors */ }
      })
    );

    // Sync on save — debounced 5 s after last edit
    this.registerEvent(
      this.app.vault.on("modify", (file) => {
        if (this.pulling) return; // ignore writes caused by our own pull
        if (file instanceof TFile) {
          this.dirtyPaths.add(file.path);
          console.log(`[LM] modify event: ${file.path} (dirtyPaths size: ${this.dirtyPaths.size})`);
        }
        if (!this.settings.syncOnSave || !this.isConfigured()) return;
        if (this.saveDebounce !== null) window.clearTimeout(this.saveDebounce);
        this.saveDebounce = window.setTimeout(() => {
          this.saveDebounce = null;
          console.log(`[LM] save debounce fired — dirty: ${[...this.dirtyPaths].join(", ")}`);
          this.runSync("push");
        }, 5000);
      })
    );

    this.setupAutoSync();

    if (this.settings.syncOnStartup && this.isConfigured()) {
      setTimeout(() => this.runSync(), 3000);
    }

    // Startup scan — find any QENC files in the vault before Obsidian indexes them.
    // Runs after layout is ready so the vault file list is fully populated.
    this.app.workspace.onLayoutReady(() => this.scanAndFixLocalQENC());
  }

  onunload() {
    if (this.syncInterval !== null) window.clearInterval(this.syncInterval);
    if (this.saveDebounce !== null) window.clearTimeout(this.saveDebounce);
    if (this.networkRetryTimer !== null) window.clearTimeout(this.networkRetryTimer);
    clearEncryptionKey();
  }

  private getRepoSyncKey(): string {
    return [
      this.settings.githubUsername || "unknown",
      this.settings.repoOwner,
      this.settings.repoName,
      this.settings.branch,
      // Note: encryption state intentionally excluded — toggling encryption
      // must NOT clear syncState or every file appears as a new candidate.
    ].join(":");
  }

  private ensureSyncStateRepoKey(): void {
    const repoKey = this.getRepoSyncKey();
    if (this.syncState.repoKey !== repoKey) {
      this.syncState = { repoKey, files: {} };
    }
  }

  private getFileSyncState(file: TFile): SyncedFileState {
    return {
      mtime: file.stat.mtime,
      size: file.stat.size,
    };
  }

  private isFileUnchangedSinceLastSync(file: TFile): boolean {
    const previous = this.syncState.files[file.path];
    if (!previous) return false;

    return previous.mtime === file.stat.mtime && previous.size === file.stat.size;
  }

  private getIncrementalCandidateDiagnostic(
    file: TFile,
    dirtyPaths: ReadonlySet<string>
  ): IncrementalCandidateDiagnostic | null {
    if (dirtyPaths.has(file.path)) {
      return {
        path: file.path,
        reason: "dirty-path",
        previous: this.syncState.files[file.path],
        current: this.getFileSyncState(file),
      };
    }

    const previous = this.syncState.files[file.path];
    if (!previous) {
      return {
        path: file.path,
        reason: "missing-sync-state",
        current: this.getFileSyncState(file),
      };
    }

    if (previous.mtime !== file.stat.mtime || previous.size !== file.stat.size) {
      return {
        path: file.path,
        reason: "metadata-changed",
        previous,
        current: this.getFileSyncState(file),
      };
    }

    return null;
  }

  private logIncrementalCandidateDiagnostics(diagnostics: IncrementalCandidateDiagnostic[]): void {
    if (diagnostics.length === 0) return;

    const counts = diagnostics.reduce<Record<IncrementalCandidateReason, number>>(
      (accumulator, diagnostic) => {
        accumulator[diagnostic.reason] += 1;
        return accumulator;
      },
      { "dirty-path": 0, "missing-sync-state": 0, "metadata-changed": 0 }
    );

    console.log(
      `[LM] incremental candidate reasons: dirty-path=${counts["dirty-path"]}, missing-sync-state=${counts["missing-sync-state"]}, metadata-changed=${counts["metadata-changed"]}`
    );

    diagnostics.slice(0, MAX_SYNC_DIAGNOSTIC_SAMPLE).forEach((diagnostic) => {
      if (diagnostic.reason === "metadata-changed" && diagnostic.previous) {
        console.log(
          `[LM] candidate [metadata-changed] ${diagnostic.path} | prev(mtime=${diagnostic.previous.mtime}, size=${diagnostic.previous.size}) -> current(mtime=${diagnostic.current.mtime}, size=${diagnostic.current.size})`
        );
        return;
      }

      if (diagnostic.reason === "dirty-path") {
        console.log(`[LM] candidate [dirty-path] ${diagnostic.path}`);
        return;
      }

      console.log(`[LM] candidate [missing-sync-state] ${diagnostic.path}`);
    });

    if (diagnostics.length > MAX_SYNC_DIAGNOSTIC_SAMPLE) {
      console.log(
        `[LM] incremental candidate diagnostics truncated: showing ${MAX_SYNC_DIAGNOSTIC_SAMPLE}/${diagnostics.length}`
      );
    }
  }

  private logRemoteComparisonDiagnostics(
    diagnostics: Array<{ path: string; localReason: IncrementalCandidateReason; changed: boolean }>
  ): void {
    if (diagnostics.length === 0) return;

    const summary = diagnostics.reduce<
      Record<IncrementalCandidateReason, { changed: number; unchanged: number }>
    >(
      (accumulator, diagnostic) => {
        accumulator[diagnostic.localReason][diagnostic.changed ? "changed" : "unchanged"] += 1;
        return accumulator;
      },
      {
        "dirty-path": { changed: 0, unchanged: 0 },
        "missing-sync-state": { changed: 0, unchanged: 0 },
        "metadata-changed": { changed: 0, unchanged: 0 },
      }
    );

    console.log(
      `[LM] remote comparison summary: dirty-path changed=${summary["dirty-path"].changed} unchanged=${summary["dirty-path"].unchanged}; missing-sync-state changed=${summary["missing-sync-state"].changed} unchanged=${summary["missing-sync-state"].unchanged}; metadata-changed changed=${summary["metadata-changed"].changed} unchanged=${summary["metadata-changed"].unchanged}`
    );

    const changedDiagnostics = diagnostics.filter((diagnostic) => diagnostic.changed);
    const changedSamples = changedDiagnostics.slice(0, MAX_SYNC_DIAGNOSTIC_SAMPLE);
    changedSamples.forEach((diagnostic) => {
      console.log(`[LM] remote mismatch [${diagnostic.localReason}] ${diagnostic.path}`);
    });

    if (changedDiagnostics.length > MAX_SYNC_DIAGNOSTIC_SAMPLE) {
      console.log(
        `[LM] remote mismatch diagnostics truncated: showing ${MAX_SYNC_DIAGNOSTIC_SAMPLE}/${changedDiagnostics.length}`
      );
    }
  }

  private markFilesSynced(files: TFile[], remoteShas?: Map<string, string>): void {
    const nextFiles = { ...this.syncState.files };
    for (const file of files) {
      const state = this.getFileSyncState(file);
      const sha = remoteShas?.get(file.path);
      nextFiles[file.path] = sha ? { ...state, remoteSha: sha } : state;
    }
    this.syncState = {
      ...this.syncState,
      files: nextFiles,
    };
  }

  /** Prune syncState to only active vault files. Returns paths that were removed (locally deleted). */
  private pruneSyncState(activeFiles: TFile[]): string[] {
    const activePaths = new Set(activeFiles.map((file) => file.path));
    const deleted: string[] = [];
    const nextFiles: typeof this.syncState.files = {};
    for (const [path, state] of Object.entries(this.syncState.files)) {
      if (activePaths.has(path)) {
        nextFiles[path] = state;
      } else {
        deleted.push(path);
      }
    }
    this.syncState = { ...this.syncState, files: nextFiles };
    return deleted;
  }

  private normalizeExcludePatterns(patterns: unknown): string[] {
    if (!Array.isArray(patterns)) {
      console.warn("[LM] excludePatterns is not an array; resetting to an empty user-defined list");
      return [];
    }

    return Array.from(new Set(patterns.map((pattern) => String(pattern).trim()).filter(Boolean)));
  }

  private getEffectiveExcludePatterns(): string[] {
    return Array.from(new Set([...this.settings.excludePatterns, ...REQUIRED_EXCLUDE_PATTERNS]));
  }

  async loadSettings() {
    const stored = (await this.loadData()) as PersistedPluginData | Partial<QuildenSyncSettings> | null;

    if (stored && "settings" in stored) {
      this.settings = Object.assign({}, DEFAULT_SETTINGS, stored.settings ?? {});
      // Migration: data.json syncState (may be stale if iCloud overwrote it).
      // Will be superseded by localStorage state after settings are applied.
      const rawSyncState = stored.syncState ?? { repoKey: "", files: {} };
      this.syncState = {
        repoKey: rawSyncState.repoKey.replace(/:(enc|plain)$/, ""),
        files: rawSyncState.files,
      };
      this.encryptionVerifyToken = stored.encryptionVerifyToken ?? null;
      this.encryptionKeyBytes = stored.encryptionKeyBytes ?? null;
      this.syncHistory = stored.syncHistory ?? [];
      console.log(`[LM] loadSettings: encryptionKeyBytes=${this.encryptionKeyBytes ? "present" : "absent"}, verifyToken=${this.encryptionVerifyToken ? "present" : "absent"}`);
    } else {
      this.settings = Object.assign({}, DEFAULT_SETTINGS, stored ?? {});
      this.syncState = { repoKey: "", files: {} };
      this.encryptionVerifyToken = null;
      this.encryptionKeyBytes = null;
      console.log(`[LM] loadSettings: legacy data format — encryptionKeyBytes not present`);
    }

    this.settings = {
      ...this.settings,
      excludePatterns: this.normalizeExcludePatterns(this.settings.excludePatterns),
    };

    // Prefer localStorage syncState (device-local, immune to iCloud overwrite).
    // localStorage key uses the repo coordinates from settings, which are now set.
    const lsSyncState = this.loadSyncStateFromLocalStorage();
    if (lsSyncState && Object.keys(lsSyncState.files).length >= Object.keys(this.syncState.files).length) {
      this.syncState = {
        repoKey: lsSyncState.repoKey.replace(/:(enc|plain)$/, ""),
        files: lsSyncState.files,
      };
      console.log(`[LM] loadSettings: using localStorage syncState (${Object.keys(lsSyncState.files).length} files)`);
    } else {
      console.log(`[LM] loadSettings: using data.json syncState (${Object.keys(this.syncState.files).length} files); localStorage had ${lsSyncState ? Object.keys(lsSyncState.files).length : 0}`);
    }

    this.ensureSyncStateRepoKey();
    console.log(`[LM] loadSettings: final syncState key="${this.syncState.repoKey}" files=${Object.keys(this.syncState.files).length}`);
  }

  async savePluginData() {
    // Persist syncState to device-local localStorage first (primary store).
    // This prevents iCloud (or any other vault-sync) from overwriting sync
    // progress saved on this device when it pushes an older data.json.
    this.saveSyncStateToLocalStorage();

    const data: PersistedPluginData = {
      settings: this.settings,
      syncState: this.syncState, // keep in data.json for migration / other devices
    };
    if (this.encryptionVerifyToken) data.encryptionVerifyToken = this.encryptionVerifyToken;
    if (this.encryptionKeyBytes) data.encryptionKeyBytes = this.encryptionKeyBytes;
    if (this.syncHistory.length > 0) data.syncHistory = this.syncHistory;
    await this.saveData(data);
  }

  async saveSettings() {
    this.ensureSyncStateRepoKey();
    await this.savePluginData();
    this.setupAutoSync();
  }

  isConfigured(): boolean {
    if (!this.settings.githubToken || !this.settings.repoOwner || !this.settings.repoName) return false;
    if (this.settings.provider === "gitea" && !this.settings.giteaBaseUrl) return false;
    return true;
  }

  resolveApiBase(): string {
    if (this.settings.provider === "gitea" && this.settings.giteaBaseUrl) {
      return `${this.settings.giteaBaseUrl.replace(/\/$/, "")}/api/v1`;
    }
    return "https://api.github.com";
  }

  resolveWebBase(): string {
    if (this.settings.provider === "gitea" && this.settings.giteaBaseUrl) {
      return this.settings.giteaBaseUrl.replace(/\/$/, "");
    }
    return "https://github.com";
  }

  buildGitAPI(): GitHubAPI {
    return new GitHubAPI(
      this.settings.githubToken,
      this.settings.repoOwner,
      this.settings.repoName,
      this.settings.branch || "main",
      this.resolveApiBase(),
      this.resolveWebBase(),
    );
  }

  private setupAutoSync() {
    if (this.syncInterval !== null) {
      window.clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    if (this.settings.autoSyncInterval > 0 && this.isConfigured()) {
      this.syncInterval = window.setInterval(() => this.runSync(), this.settings.autoSyncInterval * 60 * 1000);
    }
  }

  updateStatusBar(status: "idle" | "syncing" | "done" | "error") {
    // Ribbon icon: spin while syncing, regardless of notification mode
    if (this.ribbonEl) {
      const svgEl = this.ribbonEl.querySelector("svg");
      if (svgEl) {
        if (status === "syncing") {
          svgEl.addClass("lm-ribbon-spinning");
        } else {
          svgEl.removeClass("lm-ribbon-spinning");
        }
      }
    }

    if (!this.statusIconEl) return;
    const loc = this.settings.notificationLocation ?? "notice";

    if (loc !== "statusbar") {
      // For notice/none modes: keep icon static, never animate
      this.statusIconEl.textContent = "⇅";
      this.statusIconEl.removeClass("lm-spinning");
      if (this.statusMsgEl) this.statusMsgEl.textContent = "";
      return;
    }

    // Statusbar mode: update icon and animate during sync
    const icons: Record<string, string> = { idle: "⇅", syncing: "↻", done: "✓", error: "✗" };
    this.statusIconEl.textContent = icons[status];

    if (status === "syncing") {
      this.statusIconEl.addClass("lm-spinning");
    } else {
      this.statusIconEl.removeClass("lm-spinning");
    }

    if (status === "idle" && this.statusMsgEl) {
      this.statusMsgEl.textContent = "";
    }
  }

  notify(message: string, duration?: number): void {
    const loc = this.settings.notificationLocation ?? "notice";
    if (loc === "none") return;
    // Status bar is not visible on mobile — fall back to Notice
    if (loc === "statusbar" && !Platform.isMobile && this.statusMsgEl) {
      this.statusMsgEl.textContent = " " + message.slice(0, 60);
      window.setTimeout(() => {
        if (this.statusMsgEl) this.statusMsgEl.textContent = "";
      }, duration ?? 4000);
    } else {
      new Notice(message, duration);
    }
  }

  private showSyncHistoryPopup() {
    // Remove any existing popup first
    document.querySelector(".lm-sync-popup-backdrop")?.remove();

    const rect = this.statusBarEl!.getBoundingClientRect();
    const backdrop = document.body.createDiv({ cls: "lm-sync-popup-backdrop" });
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.remove();
    });

    const popup = backdrop.createDiv({ cls: "lm-sync-popup" });
    popup.style.bottom = `${window.innerHeight - rect.top + 8}px`;
    popup.style.right = `${window.innerWidth - rect.right}px`;

    const header = popup.createDiv({ cls: "lm-sync-popup-header" });
    header.createSpan({ text: "Sync History" });
    const closeBtn = header.createEl("button", { cls: "lm-sync-popup-close", text: "✕" });
    closeBtn.addEventListener("click", () => backdrop.remove());

    if (this.syncHistory.length === 0) {
      popup.createDiv({ cls: "lm-sync-empty", text: "No syncs yet this session." });
    } else {
      for (const entry of this.syncHistory) {
        const row = popup.createDiv({ cls: "lm-sync-entry" });

        const t = new Date(entry.time);
        const diffMs = Date.now() - t.getTime();
        const diffMin = Math.round(diffMs / 60000);
        let timeLabel: string;
        if (diffMin < 1) timeLabel = "Just now";
        else if (diffMin === 1) timeLabel = "1 min ago";
        else if (diffMin < 60) timeLabel = `${diffMin} min ago`;
        else timeLabel = t.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

        row.createEl("div", { cls: "lm-sync-entry-time", text: timeLabel });

        const parts: string[] = [];
        if (entry.pushed > 0) parts.push(`↑ ${entry.pushed} pushed`);
        if (entry.pulled > 0) parts.push(`↓ ${entry.pulled} pulled`);
        if (parts.length === 0) parts.push("No changes");
        row.createEl("div", { cls: "lm-sync-entry-stats", text: parts.join("   ") });

        if (entry.files.length > 0) {
          const filesEl = row.createEl("div", { cls: "lm-sync-entry-files" });
          const shown = entry.files.slice(0, 5);
          filesEl.textContent = shown.map(f => "· " + f.split("/").pop()).join("\n");
          if (entry.files.length > 5) {
            filesEl.textContent += `\n· +${entry.files.length - 5} more`;
          }
        }
      }
    }
  }

  private shouldExclude(path: string): boolean {
    return this.getEffectiveExcludePatterns().some((pattern) => path.startsWith(pattern) || path.includes("/" + pattern));
  }

  async encryptExistingContent(): Promise<void> {
    if (!this.isConfigured()) {
      new Notice("Configure GitHub connection first.");
      return;
    }
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }

    const api = this.buildGitAPI();

    new Notice("Scanning repo for unencrypted files…");
    const { blobs: tree } = await api.getTree();
    const filesToCheck = tree.filter((f) => shouldEncryptPath(f.path, this.settings.encryptionScope));

    const toEncrypt: Array<{ path: string; content: string }> = [];
    for (const file of filesToCheck) {
      const { content } = await api.getFileContent(file.path);
      if (isEncryptedContent(content)) continue; // already encrypted (any key) — skip to avoid double-encryption
      if (isBinaryPath(file.path)) {
        // Unencrypted binary: read raw bytes, encode as base64 for encryption
        const { buffer } = await api.getBinaryContent(file.path);
        const bytes = new Uint8Array(buffer);
        let binary = "";
        bytes.forEach((b) => (binary += String.fromCharCode(b)));
        toEncrypt.push({ path: file.path, content: btoa(binary) });
      } else {
        toEncrypt.push({ path: file.path, content });
      }
    }

    if (toEncrypt.length === 0) {
      new Notice("All markdown files are already encrypted.");
      return;
    }

    new Notice(`Encrypting ${toEncrypt.length} file(s)…`);

    const BATCH_SIZE = 50;
    for (let i = 0; i < toEncrypt.length; i += BATCH_SIZE) {
      const batch = toEncrypt.slice(i, i + BATCH_SIZE);
      const latestSha = await api.getRef();
      const { treeSha } = await api.getCommit(latestSha);
      const treeItems = await Promise.all(
        batch.map(async (f) => ({
          path: f.path,
          sha: await api.createBlob(await encryptContent(f.content)),
          mode: "100644",
        }))
      );
      const newTreeSha = await api.createTree(treeSha, treeItems);
      const commitSha = await api.createCommit(
        "Quilden: Encrypt existing content",
        newTreeSha,
        latestSha
      );
      await api.updateRef(commitSha);
    }

    new Notice(`✓ Encrypted ${toEncrypt.length} file(s) successfully.`);
  }

  async decryptExistingContent(): Promise<void> {
    if (!this.isConfigured()) {
      new Notice("Configure GitHub connection first.");
      return;
    }
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }

    const api = this.buildGitAPI();

    new Notice("Scanning repo for encrypted files…");
    const { blobs: tree } = await api.getTree();
    const filesToCheck = tree.filter((f) => shouldEncryptPath(f.path, this.settings.encryptionScope));

    const toDecrypt: Array<{ path: string; content: string; binary: boolean }> = [];
    for (const file of filesToCheck) {
      const { content } = await api.getFileContent(file.path);
      if (!isEncryptedContent(content)) continue;
      const dec = await decryptContent(content);
      if (dec === null) continue; // encrypted with a different key — skip
      toDecrypt.push({ path: file.path, content: dec, binary: isBinaryPath(file.path) });
    }

    if (toDecrypt.length === 0) {
      new Notice("No encrypted files found that can be decrypted with the current password.");
      return;
    }

    new Notice(`Decrypting ${toDecrypt.length} file(s)…`);

    const BATCH_SIZE = 50;
    for (let i = 0; i < toDecrypt.length; i += BATCH_SIZE) {
      const batch = toDecrypt.slice(i, i + BATCH_SIZE);
      const latestSha = await api.getRef();
      const { treeSha } = await api.getCommit(latestSha);
      const treeItems = await Promise.all(
        batch.map(async (f) => ({
          path: f.path,
          // Binary files: decrypted content is the original base64, push back as binary.
          // Text files: push as plain UTF-8.
          sha: await api.createBlob(f.content, f.binary ? "base64" : "utf-8"),
          mode: "100644",
        }))
      );
      const newTreeSha = await api.createTree(treeSha, treeItems);
      const commitSha = await api.createCommit(
        "Quilden: Decrypt existing content",
        newTreeSha,
        latestSha
      );
      await api.updateRef(commitSha);
    }

    new Notice(`✓ Decrypted ${toDecrypt.length} file(s) on GitHub. Updating local vault…`);

    // Write decrypted content directly to local vault files
    const vault = this.app.vault;
    let localFixed = 0;
    for (const f of toDecrypt) {
      try {
        const normalized = normalizePath(f.path);
        const vaultFile = vault.getAbstractFileByPath(normalized);
        if (!(vaultFile instanceof TFile)) continue;
        if (f.binary) {
          const binaryStr = atob(f.content);
          const bytes = new Uint8Array(binaryStr.length);
          for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
          await vault.modifyBinary(vaultFile, bytes.buffer);
        } else {
          await vault.modify(vaultFile, f.content);
        }
        // Update syncState so next push doesn't re-encrypt
        if (this.syncState?.files) delete this.syncState.files[f.path];
        localFixed++;
      } catch (e) {
        console.warn(`[LM] decrypt local failed for ${f.path}:`, e);
      }
    }
    if (this.syncState?.files && localFixed > 0) await this.savePluginData();
    new Notice(`✓ Local vault updated: ${localFixed} file(s) decrypted.`);
  }

  /**
   * Scan ALL local vault files and decrypt any that contain QENC-encrypted content.
   * This is a purely local operation — no GitHub API calls.
   */
  /**
   * Called once on startup (after layout ready). Scans all text files for QENC
   * content so nothing encrypted sits in the vault where Obsidian would index it.
   *
   * - If the key is available: silently decrypt everything found.
   * - If no key: show a persistent notice so the user knows to unlock.
   */
  private async scanAndFixLocalQENC(): Promise<void> {
    const vault = this.app.vault;
    const textFiles = vault.getFiles().filter(f => !isBinaryPath(f.path));
    const encrypted: TFile[] = [];

    for (const file of textFiles) {
      try {
        const content = await vault.read(file);
        if (isEncryptedContent(content)) encrypted.push(file);
      } catch { /* skip unreadable files */ }
    }

    if (encrypted.length === 0) return;

    if (derivedKey) {
      // Key available — silently fix them all
      this.pulling = true;
      try {
        let fixed = 0;
        for (const file of encrypted) {
          try {
            const content = await vault.read(file);
            const dec = await decryptContent(content);
            if (dec !== null) {
              await vault.modify(file, dec);
              if (this.syncState?.files) delete this.syncState.files[file.path];
              fixed++;
            }
          } catch { /* skip */ }
        }
        if (fixed > 0) await this.savePluginData();
      } finally {
        this.pulling = false;
      }
    } else {
      // No key — warn the user so they know search/links are broken until decrypted
      const n = encrypted.length;
      new Notice(
        `Quilden Sync: ${n} encrypted file${n > 1 ? "s" : ""} found in vault — open Settings → Quilden Sync and enter your encryption password to restore them.`,
        0 // persist until dismissed
      );
    }
  }

  async decryptLocalVaultFiles(): Promise<void> {
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }
    const vault = this.app.vault;

    // Pre-filter: only files known to syncState (synced through Quilden) and not binary-clean.
    // QENC content is always UTF-8 text, so only text files need checking.
    // This skips the vast majority of vault files that were never synced or are plain.
    const syncedPaths = new Set(Object.keys(this.syncState.files));
    const candidates = vault.getFiles().filter(f => syncedPaths.has(f.path) && !isBinaryPath(f.path));

    if (candidates.length === 0) {
      new Notice("No synced text files to scan.");
      return;
    }

    let fixed = 0, failed = 0, nextIdx = 0;
    const CONCURRENCY = 32;

    const worker = async () => {
      while (nextIdx < candidates.length) {
        const file = candidates[nextIdx++];
        try {
          const content = await vault.read(file);
          if (!isEncryptedContent(content)) continue;
          const dec = await decryptContent(content);
          if (dec === null) continue;
          await vault.modify(file, dec);
          if (this.syncState?.files) delete this.syncState.files[file.path];
          fixed++;
        } catch (e) {
          console.warn(`[LM] local decrypt failed for ${file.path}:`, e);
          failed++;
        }
      }
    };

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, candidates.length) }, worker));
    if (fixed > 0) await this.savePluginData();
    new Notice(`✓ Local vault: decrypted ${fixed} file(s)${failed > 0 ? `, ${failed} skipped` : ""}.`);
  }

  /**
   * Scan ALL media/image files and restore any that were accidentally stored as
   * QENC-encrypted blobs (regardless of the current encryption scope setting).
   * This is a targeted repair — it only touches files that actually have QENC content.
   */
  async repairEncryptedMediaFiles(): Promise<void> {
    if (!this.isConfigured()) {
      new Notice("Configure GitHub connection first.");
      return;
    }
    if (!derivedKey) {
      new Notice("Unlock encryption first by entering your password.");
      return;
    }

    const api = this.buildGitAPI();

    // Fast path: use syncState as candidate list instead of fetching the full remote tree.
    // Only media files already tracked in syncState could have been stored as QENC blobs.
    const MEDIA_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "svg", "pdf"]);
    const candidates = Object.keys(this.syncState.files).filter(path => {
      const ext = path.split(".").pop()?.toLowerCase() ?? "";
      return MEDIA_EXTS.has(ext);
    });

    if (candidates.length === 0) {
      new Notice("No synced media files found to check.");
      return;
    }

    new Notice(`Checking ${candidates.length} media file(s)…`);

    const CONCURRENCY = 32;
    const toRepair: Array<{ path: string; content: string }> = [];
    let nextIdx = 0;

    const checkWorker = async () => {
      while (nextIdx < candidates.length) {
        const path = candidates[nextIdx++];
        try {
          const { content } = await api.getFileContent(path);
          if (!isEncryptedContent(content)) continue;
          const dec = await decryptContent(content);
          if (dec !== null) toRepair.push({ path, content: dec });
        } catch { /* not accessible or already fixed — skip */ }
      }
    };

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, candidates.length) }, checkWorker));

    if (toRepair.length === 0) {
      new Notice("No encrypted image files found — nothing to repair.");
      return;
    }

    new Notice(`Repairing ${toRepair.length} encrypted image file(s)…`);

    const BATCH_SIZE = 50;
    let fixed = 0;
    for (let i = 0; i < toRepair.length; i += BATCH_SIZE) {
      const batch = toRepair.slice(i, i + BATCH_SIZE);
      const latestSha = await api.getRef();
      const { treeSha } = await api.getCommit(latestSha);
      const treeItems = await Promise.all(
        batch.map(async (f) => {
          // Determine if decrypted content is valid base64 (plugin-encrypted binary)
          // or a raw string (web app-encrypted binary via TextDecoder).
          let encoding: "base64" | "utf-8" = "utf-8";
          try {
            atob(f.content);
            encoding = "base64";
          } catch {
            // Not valid base64 — upload as UTF-8 best-effort
          }
          return {
            path: f.path,
            sha: await api.createBlob(f.content, encoding),
            mode: "100644",
          };
        })
      );
      const newTreeSha = await api.createTree(treeSha, treeItems);
      const commitSha = await api.createCommit(
        "Quilden: Fix encrypted image files",
        newTreeSha,
        latestSha,
      );
      await api.updateRef(commitSha);
      fixed += batch.length;
    }

    new Notice(`✓ Repaired ${fixed} encrypted image file(s) on GitHub. Updating local vault…`);

    // Write decrypted content directly to local vault files (faster than a full pull)
    const vault = this.app.vault;
    let localFixed = 0;
    for (const f of toRepair) {
      try {
        const normalized = normalizePath(f.path);
        const vaultFile = vault.getAbstractFileByPath(normalized);
        if (!(vaultFile instanceof TFile)) continue;
        // Determine encoding: valid base64 → binary file; otherwise → text
        try {
          const binaryStr = atob(f.content);
          const bytes = new Uint8Array(binaryStr.length);
          for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
          await vault.modifyBinary(vaultFile, bytes.buffer);
        } catch {
          // Not valid base64 (web-app encrypted path) — write as text best-effort
          await vault.modify(vaultFile, f.content);
        }
        if (this.syncState?.files) delete this.syncState.files[f.path];
        localFixed++;
      } catch (e) {
        console.warn(`[LM] repair local failed for ${f.path}:`, e);
      }
    }
    if (this.syncState?.files && localFixed > 0) await this.savePluginData();
    new Notice(`✓ Local vault updated: ${localFixed} image(s) restored.`);
  }

  /** Delete syncState entries for encrypted-scope files so Phase 1 is forced to re-pull and decrypt them after key unlock. */
  private clearEncryptedSyncState(): void {
    const nextFiles: typeof this.syncState.files = {};
    let changed = false;
    for (const [path, state] of Object.entries(this.syncState.files)) {
      if (this.settings.encryptionEnabled && shouldEncryptPath(path, this.settings.encryptionScope)) {
        // Drop the entry entirely — Phase 1 will see !cached → re-evaluate on next pull
        changed = true;
      } else {
        nextFiles[path] = state;
      }
    }
    if (changed) this.syncState = { ...this.syncState, files: nextFiles };
    this._encryptedNoKeyNoticeShown = false;
  }

  async tryUnlockEncryption(password: string): Promise<void> {
    if (!password) return;
    const { githubUsername, repoOwner, repoName, branch, githubToken } = this.settings;
    if (!githubUsername || !repoOwner || !repoName) {
      new Notice("Connect GitHub and select a repo first.");
      return;
    }

    // ── Fast path: local verification token already stored ──────────────────
    if (this.encryptionVerifyToken) {
      const result = await verifyOrInitEncryption(
        password, githubUsername, repoOwner, repoName,
        this.encryptionVerifyToken
      );
      if (!result.ok) {
        new Notice("Wrong password — this vault uses a different encryption password.", 6000);
        return;
      }
      new Notice("Quilden Sync: Password verified ✓");
      return;
    }

    // ── New device: no local token — verify via repo ─────────────────────────
    const VERIFY_PATH = ".quilden/encryption-verify";
    const api = this.buildGitAPI();
    const salt = await contextSalt(githubUsername, repoOwner, repoName);
    const candidateKey = await buildKey(password, salt);

    // Helper: swap in candidate key, attempt decrypt, restore previous key.
    const tryDecrypt = async (ciphertext: string): Promise<string | null> => {
      const prev = derivedKey;
      derivedKey = candidateKey;
      const result = await decryptContent(ciphertext);
      derivedKey = prev;
      return result;
    };

    // Step 1 — dedicated verify file (primary)
    try {
      const { content } = await api.getFileContent(VERIFY_PATH);
      const repoToken = content.trim();
      const check = await tryDecrypt(repoToken);
      if (check !== ENCRYPTION_VERIFY_PLAINTEXT) {
        new Notice("Wrong password — could not verify against repo encryption file.", 6000);
        return;
      }
      // Password correct via verify file.
      derivedKey = candidateKey;
      this.encryptionVerifyToken = repoToken;
      await this.savePluginData();
      new Notice("Quilden Sync: Password verified ✓");
      this.clearEncryptedSyncState();
      this.scanAndFixLocalQENC();
      this.runSync("pull").catch(e => console.warn("[LM] post-unlock pull failed:", e));
      return;
    } catch { /* verify file missing — fall through to md sampling */ }

    // Step 2 — fallback: sample encrypted .md files from the remote tree
    let foundEncrypted = false;
    let passwordCorrect = false;
    try {
      const { blobs: tree } = await api.getTree();
      const mdCandidates = tree
        .filter(f => f.path.endsWith(".md") && !f.path.startsWith("."))
        .slice(0, 8);

      for (const entry of mdCandidates) {
        try {
          const { content } = await api.getFileContent(entry.path);
          if (!isEncryptedContent(content)) continue; // plaintext file — skip

          foundEncrypted = true;
          const dec = await tryDecrypt(content);
          if (dec !== null) {
            passwordCorrect = true;
          } else {
            new Notice("Wrong password — could not decrypt existing encrypted files.", 6000);
            return;
          }
          break; // one encrypted file is enough to decide
        } catch { continue; }
      }
    } catch (e: any) {
      // 404 means the repo is empty or the branch doesn't exist yet — treat as
      // first-time setup (no encrypted files to verify against).
      const is404 = e.message?.includes("404") || e.message?.includes("Not Found");
      if (!is404) {
        new Notice(`Could not reach repo for verification: ${e.message}`, 5000);
        return;
      }
      // Fall through: empty repo → accept password as new setup
    }

    if (foundEncrypted && !passwordCorrect) return; // already notified above

    // Password accepted — either verified via md file, or no encrypted files yet (first setup).
    derivedKey = candidateKey;
    const token = await encryptContent(ENCRYPTION_VERIFY_PLAINTEXT);
    this.encryptionVerifyToken = token;
    await this.savePluginData();

    // Upload verify file so future new-device logins skip the md sampling.
    try {
      await api.putFile(VERIFY_PATH, token, "chore: add Quilden encryption verification token");
    } catch { /* non-critical — md sampling is the fallback */ }

    if (foundEncrypted) {
      new Notice("Quilden Sync: Password verified ✓");
    } else {
      new Notice(
        "Quilden Sync: Encryption set up ✓\n\n" +
        "⚠️ Keep your password safe — it cannot be changed later. " +
        "Losing it means your encrypted files cannot be recovered.",
        12000
      );
    }
    this.clearEncryptedSyncState();
    this.scanAndFixLocalQENC();
    this.runSync("pull").catch(e => console.warn("[LM] post-unlock pull failed:", e));
  }

  private openFileHistory(file: TFile) {
    const { githubToken, repoOwner, repoName, branch, encryptionEnabled } = this.settings;
    if (!githubToken || !repoOwner || !repoName) {
      new Notice("Quilden Sync: Configure your repo first.");
      return;
    }
    console.log(`[LM] openFileHistory: repo=${repoOwner}/${repoName}@${branch}`);
    const api = this.buildGitAPI();
    new FileHistoryModal(this.app, file, api, encryptionEnabled).open();
  }

  private async copyTokenForQuilden() {
    if (!this.settings.githubToken) {
      new Notice("Quilden Sync: No GitHub token configured.");
      return;
    }
    try {
      await navigator.clipboard.writeText(this.settings.githubToken);
      new Notice("Token copied! Paste it into Quilden's sign-in form.");
    } catch {
      new Notice("Clipboard unavailable. Copy the token manually from settings.", 5000);
    }
  }

  async openQuildenWebsite(statusEl?: HTMLElement): Promise<void> {
    if (!this.settings.githubToken) {
      new Notice("Quilden Sync: No GitHub token configured.");
      return;
    }
    if (statusEl) { statusEl.setText("Connecting…"); statusEl.style.color = "var(--text-muted)"; }

    try {
      const res = await requestUrl({
        url: `${QUILDEN_BASE}/api/auth/from-pat`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: this.settings.githubToken,
          ...(this.settings.provider === "gitea" ? { provider: "gitea", baseUrl: this.settings.giteaBaseUrl } : {}),
        }),
        throw: false,
      });

      if (res.status === 401) {
        if (statusEl) statusEl.setText("Token rejected by server.");
        new Notice("Quilden: Token is invalid or expired. Reconnect with a fresh token.", 6000);
        return;
      }
      if (res.status >= 400) {
        const msg = res.json?.error ?? `Server error ${res.status}`;
        if (statusEl) statusEl.setText("Failed.");
        new Notice(`Quilden: ${msg}`, 5000);
        return;
      }

      const { url } = res.json as { url: string; login: string };
      if (statusEl) { statusEl.setText("Opening browser…"); }
      window.open(url, "_blank");
      if (statusEl) setTimeout(() => statusEl.setText(""), 3000);
    } catch (e: any) {
      if (statusEl) statusEl.setText("Network error.");
      new Notice(`Quilden: Could not reach server — ${e.message}`, 5000);
    }
  }

  /** Try to silently refresh the token via the server. Returns true if successful. */
  private async tryRefreshToken(): Promise<boolean> {
    if (!this.settings.githubRefreshToken) return false;
    try {
      const res = await requestUrl({
        url: `${QUILDEN_BASE}/api/auth/plugin-refresh`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: this.settings.githubRefreshToken }),
        throw: false,
      });
      if (res.status === 200 && res.json?.token) {
        this.settings.githubToken = res.json.token;
        if (res.json.refreshToken) this.settings.githubRefreshToken = res.json.refreshToken;
        await this.saveSettings();
        console.log("[LM] token refreshed silently");
        return true;
      }
    } catch { /* network error — fall through */ }
    return false;
  }

  private async verifySyncAccess(): Promise<void> {
    const apiBase = this.resolveApiBase();
    const providerName = this.settings.provider === "gitea" ? "Gitea" : "GitHub";
    const tokenCheck = await requestUrl({
      url: `${apiBase}/user`,
      method: "GET",
      headers: apiHeaders(this.settings.githubToken, apiBase),
      throw: false,
    });

    if (tokenCheck.status === 401) {
      // Attempt silent refresh before giving up (GitHub OAuth tokens only)
      const refreshed = await this.tryRefreshToken();
      if (!refreshed) {
        throw new Error(`${providerName} token is invalid or expired. Disconnect and reconnect.`);
      }
      // Token just came from our auth server — trust it without re-verifying immediately.
      return;
    }

    if (tokenCheck.status >= 400) {
      const message = tokenCheck.json?.message ?? tokenCheck.status;
      throw new Error(`Unable to verify ${providerName} token (${tokenCheck.status}: ${message})`);
    }

    const scopes = tokenCheck.headers?.["x-oauth-scopes"] ?? "";
    console.log(`[LM] token scopes: "${scopes}"`);

    const repoUrl = `${apiBase}/repos/${this.settings.repoOwner}/${this.settings.repoName}`;
    const repoCheck = await requestUrl({
      url: repoUrl,
      method: "GET",
      headers: apiHeaders(this.settings.githubToken, apiBase),
      throw: false,
    });

    if (repoCheck.status === 404) {
      throw new Error(
        `${providerName} token cannot access ${this.settings.repoOwner}/${this.settings.repoName}. ` +
        "Reconnect and grant that repository, or choose a different repo."
      );
    }

    if (repoCheck.status === 403) {
      const resetEpoch = repoCheck.headers?.["x-ratelimit-reset"];
      const resetTime = resetEpoch ? new Date(Number(resetEpoch) * 1000).toLocaleTimeString() : "unknown";
      const message = repoCheck.json?.message ?? repoCheck.status;
      if (repoCheck.headers?.["x-ratelimit-remaining"] === "0") {
        throw new Error(`${providerName} rate limit exceeded — resets at ${resetTime}. Wait and try again.`);
      }
      throw new Error(`${providerName} denied access to ${this.settings.repoOwner}/${this.settings.repoName} (${message}).`);
    }

    if (repoCheck.status >= 400) {
      const message = repoCheck.json?.message ?? repoCheck.status;
      throw new Error(`Unable to verify repo access (${repoCheck.status}: ${message})`);
    }

    const permissions = repoCheck.json?.permissions as RepoPermissionSummary | undefined;
    if (permissions && !permissions.admin && !permissions.maintain && !permissions.push) {
      throw new Error(
        `${providerName} token can read ${this.settings.repoOwner}/${this.settings.repoName} but cannot push to it. ` +
        "Reconnect and grant write access."
      );
    }

    if (!scopes) {
      console.log("[LM] token uses permission-based access; repo capability check passed");
    }
  }

  async runSync(mode: "full" | "push" | "pull" = "full") {
    if (this.syncing) {
      console.log(`[LM] runSync(${mode}) skipped — already syncing`);
      return;
    }
    if (!this.isConfigured()) {
      const provider = this.settings.provider === "gitea" ? "Gitea" : "GitHub";
      if (!this.settings.githubToken) {
        new Notice(`Quilden Sync: Please connect ${provider} first.`);
      } else {
        new Notice("Quilden Sync: Please select a repository in settings first.");
      }
      return;
    }

    // Cancel any pending network-error retry — this sync supersedes it
    if (this.networkRetryTimer !== null) {
      window.clearTimeout(this.networkRetryTimer);
      this.networkRetryTimer = null;
    }

    console.log(`[LM] runSync(${mode}) started`);
  // Obsidian plugin callbacks run on the single JS event loop, so setting this
  // immediately after the guard is sufficient to serialize sync execution.
    this.syncing = true;
    this._syncPushedPaths = [];
    this._syncPulledPaths = [];
    this.updateStatusBar("syncing");

    try {
      await this.verifySyncAccess();

      const api = this.buildGitAPI();

      let justDeleted: ReadonlySet<string> = new Set();
      if (mode === "push" || mode === "full") justDeleted = await this.pushChanges(api, "incremental");
      if (mode === "pull" || mode === "full") await this.pullChanges(api, justDeleted);

      // Record sync history entry
      this.lastSyncTime = new Date();
      const allFiles = [...new Set([...this._syncPushedPaths, ...this._syncPulledPaths])];
      const entry: SyncHistoryEntry = {
        time: this.lastSyncTime.toISOString(),
        pushed: this._syncPushedPaths.length,
        pulled: this._syncPulledPaths.length,
        files: allFiles,
      };
      this.syncHistory = [entry, ...this.syncHistory].slice(0, 25);
      if (this.statusBarEl) {
        this.statusBarEl.title = `Last sync: ${this.lastSyncTime.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
      }
      await this.savePluginData();

      this.updateStatusBar("done");
      this.notify("Quilden Sync: Complete");
      setTimeout(() => this.updateStatusBar("idle"), 3000);
    } catch (e) {
      console.error("[LM] Sync error:", e);
      this.updateStatusBar("error");
      const msg = e instanceof Error ? e.message : "Unknown error";
      const isAuthError = msg.includes("401") || msg.includes("token is invalid") || msg.includes("Bad credentials") || msg.includes("Unauthorized");
      const isNetworkError = !isAuthError && (msg.includes("ERR_NETWORK") || msg.includes("ERR_INTERNET") || msg.includes("net::") || msg.includes("fetch"));
      if (isAuthError) {
        // Cancel any pending retry — retrying won't help with an expired token
        if (this.networkRetryTimer !== null) { window.clearTimeout(this.networkRetryTimer); this.networkRetryTimer = null; }
        this.notify(`Quilden Sync: Token expired — disconnect and reconnect in settings`, 10000);
      } else if (isNetworkError) {
        const RETRY_DELAY_S = 30;
        this.notify(`Quilden Sync: Network lost — retrying in ${RETRY_DELAY_S}s`, 8000);
        if (this.networkRetryTimer !== null) window.clearTimeout(this.networkRetryTimer);
        this.networkRetryTimer = window.setTimeout(() => {
          this.networkRetryTimer = null;
          console.log("[LM] retrying sync after network error");
          this.runSync(mode);
        }, RETRY_DELAY_S * 1000);
      } else {
        this.notify(`Quilden Sync: Failed — ${msg}`, 8000);
      }
      setTimeout(() => this.updateStatusBar("idle"), 5000);
    } finally {
      this.syncing = false;
      console.log(`[LM] runSync(${mode}) finished`);
    }
  }

  // Tracks files modified locally since last push (for incremental syncs)
  private dirtyPaths = new Set<string>();
  // Paths currently showing the EncryptedFileModal — prevents duplicate modals
  private _pendingDecrypt = new Set<string>();
  private _encryptedNoKeyNoticeShown = false;

  private async pushChanges(api: GitHubAPI, scope: "full" | "incremental" = "full"): Promise<Set<string>> {
    const allVaultFiles = this.app.vault.getFiles();
    const preEnsureCount = Object.keys(this.syncState.files).length;
    const preEnsureKey = this.syncState.repoKey;
    this.ensureSyncStateRepoKey();
    const postEnsureCount = Object.keys(this.syncState.files).length;
    console.log(`[LM] pushChanges: syncState before ensureKey: key="${preEnsureKey}" files=${preEnsureCount}; after: key="${this.syncState.repoKey}" files=${postEnsureCount}; computed="${this.getRepoSyncKey()}"`);
    if (postEnsureCount === 0 && preEnsureCount > 0) {
      console.warn(`[LM] BUG: pushChanges ensureSyncStateRepoKey() wiped ${preEnsureCount} entries!`);
    }
    const prePruneCount = Object.keys(this.syncState.files).length;
    const deletedPaths = this.pruneSyncState(allVaultFiles);
    const postPruneCount = Object.keys(this.syncState.files).length;
    console.log(`[LM] pushChanges: after pruneSyncState: ${postPruneCount} entries (pruned ${prePruneCount - postPruneCount} stale paths from ${allVaultFiles.length} vault files)`);

    // Decide which files to push
    let candidateFiles = allVaultFiles.filter((f) => !this.shouldExclude(f.path));
    const candidateDiagnostics = new Map<string, IncrementalCandidateDiagnostic>();

    if (scope === "incremental") {
      const dirtyPaths = new Set(this.dirtyPaths);
      candidateFiles = candidateFiles.filter((file) => {
        const diagnostic = this.getIncrementalCandidateDiagnostic(file, dirtyPaths);
        if (!diagnostic) return false;
        candidateDiagnostics.set(file.path, diagnostic);
        return true;
      });
      console.log(`[LM] incremental push: ${candidateFiles.length} candidate file(s) after local change scan`);
      this.logIncrementalCandidateDiagnostics(Array.from(candidateDiagnostics.values()));
    } else {
      console.log(`[LM] full sync scan: ${candidateFiles.length} local file(s)`);
    }

    // Even if no files changed, we may still need to commit deletions
    if (candidateFiles.length === 0 && deletedPaths.length === 0) {
      console.log("[LM] pushChanges: nothing to push");
      return new Set<string>();
    }

    const filesToPush: Array<{ file: TFile; path: string; content: string; encoding: "utf-8" | "base64" }> = [];

    for (const file of candidateFiles) {
      if (isBinaryPath(file.path)) {
        const buffer = await this.app.vault.readBinary(file);
        if (buffer.byteLength === 0 && file.stat.size > 0) {
          // readBinary returned empty but the file has content — iCloud eviction or similar.
          // Uploading an empty blob would corrupt the remote; skip silently.
          console.log(`[LM] skip push ${file.path}: not locally available (size=${file.stat.size})`);
          continue;
        }
        const bytes = new Uint8Array(buffer);
        let binary = "";
        bytes.forEach((b) => (binary += String.fromCharCode(b)));
        const b64 = btoa(binary);
        const willEncrypt = this.settings.encryptionEnabled && !!derivedKey
          && shouldEncryptPath(file.path, this.settings.encryptionScope);
        // If encrypting, tag as utf-8 so the QENC ciphertext is pushed as text; otherwise base64 binary.
        filesToPush.push({ file, path: file.path, content: b64, encoding: willEncrypt ? "utf-8" : "base64" });
      } else {
        const content = await this.app.vault.read(file);
        // Store plaintext — encryption happens later only for files that actually changed.
        filesToPush.push({ file, path: file.path, content, encoding: "utf-8" });
      }
    }

    console.log(`[LM] pushChanges: prepared ${filesToPush.length} local file(s) for comparison`);

    // Optimisation: for small incremental pushes with no deletions, fetch only
    // the SHAs of the specific files instead of the full tree.
    // Fall back to getTree() when there are many candidates (e.g. first sync).
    const PER_FILE_LOOKUP_THRESHOLD = 10;
    const usePerFileLookup = scope === "incremental"
      && deletedPaths.length === 0
      && filesToPush.length <= PER_FILE_LOOKUP_THRESHOLD;
    let remoteShaByPath: Map<string, string>;
    let remoteTreeTruncated = false;

    if (usePerFileLookup) {
      // Fetch SHAs for non-encrypted candidates in parallel (encrypted files use mtime comparison).
      const needsSha = filesToPush.filter(f =>
        !(this.settings.encryptionEnabled && !!derivedKey && shouldEncryptPath(f.path, this.settings.encryptionScope))
      );
      const shaEntries = await Promise.all(
        needsSha.map(async f => {
          const sha = await api.getFileSha(f.path);
          return [f.path, sha] as [string, string | null];
        })
      );
      remoteShaByPath = new Map(
        shaEntries.filter((e): e is [string, string] => e[1] !== null)
      );
      console.log(`[LM] remote SHAs fetched for ${shaEntries.length} file(s) (per-file lookup)`);
    } else {
      const { blobs: remoteTree, truncated } = await api.getTree();
      remoteTreeTruncated = truncated;
      if (remoteTreeTruncated) {
        console.warn(`[LM] remote tree is truncated (repo too large for single tree fetch). Missing-sync-state files absent from the partial tree will be skipped to avoid re-uploading unchanged content.`);
      }
      console.log(`[LM] remote tree: ${remoteTree.length} entries${remoteTreeTruncated ? " (TRUNCATED)" : ""}`);
      remoteShaByPath = new Map(remoteTree.map((entry) => [entry.path, entry.sha]));
    }
    const changedFilesToPush: Array<{ file: TFile; path: string; content: string; encoding: "utf-8" | "base64" }> = [];
    const unchangedFiles: TFile[] = [];
    const remoteComparisonDiagnostics: Array<{
      path: string;
      localReason: IncrementalCandidateReason;
      changed: boolean;
    }> = [];

    for (const file of filesToPush) {
      // Guard: never re-encrypt content that's already encrypted (e.g. pulled with a mismatched key).
      const shouldEnc = this.settings.encryptionEnabled && !!derivedKey
        && shouldEncryptPath(file.path, this.settings.encryptionScope)
        && !isEncryptedContent(file.content);

      let changed: boolean;
      if (shouldEnc) {
        // AES-GCM uses a random IV so each encryption of the same plaintext
        // produces a different SHA. SHA comparison is useless here.
        // Use mtime+size to decide whether the local file has actually changed.
        const prev = this.syncState.files[file.path];
        changed = !prev
          || prev.mtime !== file.file.stat.mtime
          || prev.size !== file.file.stat.size;
      } else {
        const localSha = await computeGitBlobSha(file.content, file.encoding);
        const remoteSha = remoteShaByPath.get(file.path);
        // When the remote tree is truncated, a missing entry may just mean
        // the file is beyond the truncation cutoff — not that it's absent.
        // Treat missing-sync-state files absent from a truncated tree as
        // unchanged (they'll still be compared properly once in syncState).
        const localDiag = candidateDiagnostics.get(file.path);
        if (remoteSha === undefined && remoteTreeTruncated && localDiag?.reason === "missing-sync-state") {
          changed = false; // can't verify — assume unchanged to avoid spurious upload
        } else {
          changed = localSha !== remoteSha;
        }
      }

      const localDiagnostic = candidateDiagnostics.get(file.path);
      if (localDiagnostic) {
        remoteComparisonDiagnostics.push({ path: file.path, localReason: localDiagnostic.reason, changed });
      }

      if (changed) {
        let uploadContent = file.content;
        let uploadEncoding = file.encoding;
        if (shouldEnc) {
          uploadContent = await encryptContent(file.content);
          uploadEncoding = "utf-8"; // encrypted output is always UTF-8 text
        }
        changedFilesToPush.push({ ...file, content: uploadContent, encoding: uploadEncoding });
      } else {
        // BUG GUARD: if encryption is enabled but the key isn't unlocked yet,
        // don't record encryptable files as synced. They remain without sync-state so the
        // next sync (after the user unlocks) will see them as candidates and
        // encrypt+upload them properly.
        const encPending = this.settings.encryptionEnabled && !derivedKey
          && shouldEncryptPath(file.path, this.settings.encryptionScope);
        if (!encPending) {
          this.dirtyPaths.delete(file.path);
          unchangedFiles.push(file.file);
        }
      }
    }

    if (unchangedFiles.length > 0) {
      this.markFilesSynced(unchangedFiles);
      await this.savePluginData();
    }

    this.logRemoteComparisonDiagnostics(remoteComparisonDiagnostics);

    // Filter deletions to only paths that actually exist on the remote
    // (no point deleting something GitHub doesn't have)
    const remoteDeletions = deletedPaths.filter(p => remoteShaByPath.has(p));
    if (remoteDeletions.length > 0) {
      console.log(`[LM] pushChanges: ${remoteDeletions.length} file(s) to delete on remote: ${remoteDeletions.join(", ")}`);
    }

    console.log(`[LM] pushChanges: ${changedFilesToPush.length}/${filesToPush.length} file(s) changed vs remote`);

    if (changedFilesToPush.length === 0 && remoteDeletions.length === 0) {
      console.log("[LM] pushChanges: nothing changed vs remote");
      return new Set<string>();
    }

    // Upload all blobs concurrently (8 workers), then create a single tree,
    // commit, and ref update — exactly like a standard `git commit`.
    let isEmpty = await api.isBranchEmpty();

    // Gitea's Git Data API (/git/blobs, /git/trees, etc.) requires at least one
    // commit to exist before it accepts requests. Initialize via the Contents API.
    if (isEmpty) {
      console.log("[LM] empty repo detected — initializing via Contents API");
      await api.initializeRepo();
      isEmpty = false;
    }

    const currentSha = await api.getRef();
    const baseTreeSha = (await api.getCommit(currentSha)).treeSha;
    console.log(`[LM] base tree SHA: ${baseTreeSha}`);

    const deletionItems: Array<{ path: string; sha: null; mode: string }> =
      remoteDeletions.map(p => ({ path: p, sha: null, mode: "100644" }));

    // Also remove the placeholder file created during initialization
    const placeholderItem: { path: string; sha: null; mode: string } = { path: ".gitkeep", sha: null, mode: "100644" };

    console.log(`[LM] uploading ${changedFilesToPush.length} blob(s)`);
    const uploadedItems = changedFilesToPush.length > 0
      ? await uploadBatchBlobs(api, changedFilesToPush, 1)
      : [];
    const treeItems = [...uploadedItems, ...deletionItems, placeholderItem];

    const newTreeSha = await api.createTree(baseTreeSha, treeItems);
    console.log(`[LM] new tree SHA: ${newTreeSha}`);

    if (newTreeSha === baseTreeSha) {
      console.log("[LM] push done — tree unchanged, no commit needed");
      changedFilesToPush.forEach((f) => this.dirtyPaths.delete(f.path));
      this.markFilesSynced(changedFilesToPush.map((f) => f.file));
    } else {
      const timestamp = new Date().toISOString().slice(0, 19).replace("T", " ");
      const commitSha = await api.createCommit(`${this.settings.commitMessage} - ${timestamp}`, newTreeSha, currentSha);
      await api.updateRef(commitSha);
      changedFilesToPush.forEach((f) => {
        this.dirtyPaths.delete(f.path);
        this._syncPushedPaths.push(f.path);
      });
      this.markFilesSynced(changedFilesToPush.map((f) => f.file));
      if (remoteDeletions.length > 0) remoteDeletions.forEach(p => this._syncPushedPaths.push(p));
      console.log(`[LM] push done — 1 commit ${commitSha} (${changedFilesToPush.length} file(s) updated, ${remoteDeletions.length} deleted)`);
      return new Set(remoteDeletions);
    }
    await this.savePluginData();
    return new Set<string>();
  }

  private pulling = false;

  private async pullChanges(api: GitHubAPI, skipPaths: ReadonlySet<string> = new Set()) {
    const vault = this.app.vault;

    // One API call to get all remote SHAs — no content fetched yet
    const { blobs: remoteTree } = await api.getTree();
    console.log(`[LM] pull: ${remoteTree.length} remote entries`);

    let created = 0, updated = 0, unchanged = 0;
    const syncedFiles: TFile[] = [];

    // ── Phase 1: determine which files need downloading (no network I/O) ──────
    type PullTask = {
      remote: { path: string; sha: string };
      normalized: string;
      action: "update" | "create";
      existingFile?: TFile;
    };
    const tasks: PullTask[] = [];

    for (const remote of remoteTree) {
      if (skipPaths.has(remote.path)) continue; // just deleted in this sync — don't re-create
      if (this.shouldExclude(remote.path)) continue;
      if (/^\.\.\/|\/\.\.\//g.test(remote.path) || remote.path.startsWith("/")) continue;
      const firstSegment = remote.path.split("/")[0];
      if (firstSegment.startsWith(".") && firstSegment !== ".obsidian") continue;

      const normalized = normalizePath(remote.path);
      const existing = vault.getAbstractFileByPath(normalized);

      if (existing instanceof TFile) {
        const cached = this.syncState.files[remote.path];
        let needsUpdate: boolean;
        // Fast path: if the remote SHA hasn't changed since last sync, nothing to do —
        // regardless of encryption state. This also prevents re-downloading encrypted
        // files when there's no key (they're recorded with remoteSha after first encounter).
        if (cached?.remoteSha === remote.sha) {
          needsUpdate = false;
        } else if (this.settings.encryptionEnabled && shouldEncryptPath(remote.path, this.settings.encryptionScope)) {
          needsUpdate = !cached || cached.mtime !== existing.stat.mtime;
        } else {
          const localBytes = isBinaryPath(remote.path)
            ? new Uint8Array(await vault.readBinary(existing))
            : new TextEncoder().encode(await vault.read(existing));
          const localSha = await gitBlobSha(localBytes);
          needsUpdate = localSha !== remote.sha;
        }
        if (!needsUpdate) {
          unchanged++;
          syncedFiles.push(existing);
          continue;
        }
        tasks.push({ remote, normalized, action: "update", existingFile: existing });
      } else {
        // File doesn't exist locally. Check if we've seen this remote SHA before and
        // couldn't process it (e.g. encrypted with no key) — don't re-attempt unless remote changed.
        const cached = this.syncState.files[remote.path];
        if (cached?.remoteSha === remote.sha) {
          unchanged++;
          continue;
        }
        tasks.push({ remote, normalized, action: "create" });
      }
    }

    // ── Phase 2: download and apply in parallel ────────────────────────────────
    const PULL_CONCURRENCY = 8;
    // Tracks path → remote SHA for every processed task so syncState.remoteSha stays current.
    const remoteShaForPath = new Map<string, string>();
    let encryptedNoKeyCount = 0;
    this.pulling = true;
    try {
      let nextIdx = 0;
      const worker = async () => {
        while (nextIdx < tasks.length) {
          const task = tasks[nextIdx++];
          try {
            const { remote, normalized, action, existingFile } = task;
            const isEncBinary = isBinaryPath(remote.path)
              && this.settings.encryptionEnabled
              && shouldEncryptPath(remote.path, this.settings.encryptionScope);

            if (action === "update" && existingFile) {
              if (isBinaryPath(remote.path) && !isEncBinary) {
                // Plain binary (not encrypted) — fast path via raw download
                const { buffer } = await api.getBinaryContent(remote.path);
                if (buffer.byteLength === 0 && existingFile.stat.size > 0) {
                  console.log(`[LM] pull skip ${remote.path}: remote empty, local has content`);
                  unchanged++;
                  syncedFiles.push(existingFile);
                  continue;
                }
                await vault.modifyBinary(existingFile, buffer);
              } else {
                const { content } = await api.getFileContent(remote.path);
                let final: string | null = content;
                // Decrypt QENC if key is available; otherwise write QENC as-is so user can access it.
                if (isEncryptedContent(content)) {
                  if (!derivedKey) {
                    // No key — write QENC content as-is so user can open and decrypt it locally.
                    // EncryptedFileModal handles per-file decryption on open.
                    encryptedNoKeyCount++;
                    // final stays as content (QENC), falls through to vault.modify below
                  } else {
                    final = await decryptContent(content);
                  }
                }
                if (final === null) {
                  // Decryption failed — leave local untouched
                } else if (isBinaryPath(remote.path)) {
                  // Binary file: decrypted content is base64-encoded bytes
                  try {
                    const binaryStr = atob(final);
                    const bytes = new Uint8Array(binaryStr.length);
                    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
                    await vault.modifyBinary(existingFile, bytes.buffer);
                  } catch {
                    await vault.modify(existingFile, final);
                  }
                } else {
                  await vault.modify(existingFile, final);
                }
              }
              remoteShaForPath.set(remote.path, remote.sha);
              syncedFiles.push(existingFile);
              console.log(`[LM] pull update: ${remote.path}`);
              this._syncPulledPaths.push(remote.path);
              updated++;

            } else {
              // create — ensure parent dir first
              const dir = remote.path.includes("/") ? remote.path.slice(0, remote.path.lastIndexOf("/")) : null;
              if (dir) {
                const dirPath = normalizePath(dir);
                if (!vault.getAbstractFileByPath(dirPath)) {
                  try { await vault.createFolder(dirPath); } catch { /* already exists */ }
                }
              }

              if (isBinaryPath(remote.path) && !isEncBinary) {
                // Plain binary — fast path
                const { buffer } = await api.getBinaryContent(remote.path);
                await vault.createBinary(normalized, buffer);
              } else {
                const { content } = await api.getFileContent(remote.path);
                let final: string | null = content;
                if (isEncryptedContent(content)) {
                  if (!derivedKey) {
                    // No key — create file with QENC content so user can decrypt it locally.
                    encryptedNoKeyCount++;
                    // final stays as content (QENC), falls through to vault.create below
                  } else {
                    final = await decryptContent(content);
                  }
                }
                if (final !== null) {
                  if (isBinaryPath(remote.path)) {
                    try {
                      const binaryStr = atob(final);
                      const bytes = new Uint8Array(binaryStr.length);
                      for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
                      await vault.createBinary(normalized, bytes.buffer);
                    } catch {
                      await vault.create(normalized, final);
                    }
                  } else {
                    await vault.create(normalized, final);
                  }
                }
              }
              remoteShaForPath.set(remote.path, remote.sha);
              const newFile = vault.getAbstractFileByPath(normalized);
              if (newFile instanceof TFile) syncedFiles.push(newFile);
              console.log(`[LM] pull create: ${remote.path}`);
              this._syncPulledPaths.push(remote.path);
              created++;
            }
          } catch (e) {
            console.warn(`[LM] pull error ${task.remote.path}:`, e);
          }
        }
      };

      await Promise.all(Array.from({ length: Math.min(PULL_CONCURRENCY, tasks.length || 1) }, () => worker()));
    } finally {
      this.pulling = false;
    }

    // Show one-time notice directing user to set up encryption
    if (encryptedNoKeyCount > 0 && !this._encryptedNoKeyNoticeShown) {
      this._encryptedNoKeyNoticeShown = true;
      new EncryptedPullNoticeModal(this.app, encryptedNoKeyCount, () => {
        (this.app as any).setting?.open?.();
        (this.app as any).setting?.openTabById?.("quilden-sync");
      }).open();
    }

    this.ensureSyncStateRepoKey();
    // Persist remoteSha for all processed files (updates, creates, and encrypted-no-key skips).
    const needsSave = syncedFiles.length > 0 || remoteShaForPath.size > 0;
    if (syncedFiles.length > 0) this.markFilesSynced(syncedFiles, remoteShaForPath);
    if (needsSave) await this.savePluginData();

    console.log(`[LM] pullChanges done: created=${created} updated=${updated} unchanged=${unchanged}`);
    const pulled = created + updated;
    if (pulled > 0) this.notify(`Quilden Sync: Pulled ${pulled} file(s)`);
  }
}


function confirmDialog(app: App, title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const modal = new Modal(app);
    modal.titleEl.setText(title);
    modal.contentEl.createEl("p", { text: message });
    const btnRow = modal.contentEl.createDiv({ cls: "modal-button-container" });
    btnRow.createEl("button", { text: "Cancel" }).addEventListener("click", () => {
      modal.close();
      resolve(false);
    });
    const confirmBtn = btnRow.createEl("button", { text: "Continue", cls: "mod-cta" });
    confirmBtn.addEventListener("click", () => {
      modal.close();
      resolve(true);
    });
    modal.open();
  });
}

// ── Encrypted-file unlock modal ───────────────────────────────────────────────
// Shown when a local file contains QENC-encrypted content but no key is loaded.
// The user enters their password; on success the file is decrypted in place.
class EncryptedPullNoticeModal extends Modal {
  constructor(
    app: App,
    private count: number,
    private openSettings: () => void,
  ) {
    super(app);
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.createEl("h2", { text: "Encrypted files found" });
    contentEl.createEl("p", {
      text: `${this.count} file(s) synced from GitHub are encrypted and cannot be read without your encryption password.`,
    });
    contentEl.createEl("p", {
      text: "Open plugin settings to set up encryption. You can either enter your password to automatically decrypt files as they sync, or decrypt all existing files at once.",
    });
    const btns = contentEl.createDiv({ cls: "modal-button-container" });
    const primary = btns.createEl("button", { text: "Open Encryption Settings", cls: "mod-cta" });
    primary.onclick = () => { this.close(); this.openSettings(); };
    const dismiss = btns.createEl("button", { text: "Dismiss" });
    dismiss.onclick = () => this.close();
  }

  onClose() {
    this.contentEl.empty();
  }
}

class EncryptedFileModal extends Modal {
  private file: TFile;
  private plugin: QuildenSyncPlugin;
  private onDecrypted: () => void;

  constructor(app: App, file: TFile, plugin: QuildenSyncPlugin, onDecrypted: () => void) {
    super(app);
    this.file = file;
    this.plugin = plugin;
    this.onDecrypted = onDecrypted;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("lm-enc-modal");

    contentEl.createEl("h3", { text: "🔒 Encrypted file" });
    contentEl.createEl("p", {
      text: `"${this.file.name}" is encrypted. Enter your encryption password to decrypt and open it.`,
      cls: "lm-enc-desc",
    });

    const pwInput = contentEl.createEl("input", { type: "password", placeholder: "Encryption password", cls: "lm-enc-input" });
    const errorEl = contentEl.createEl("p", { cls: "lm-enc-error" });
    const btnRow = contentEl.createDiv({ cls: "lm-enc-btns" });
    const decryptBtn = btnRow.createEl("button", { text: "Decrypt & open", cls: "mod-cta lm-enc-btn" });
    btnRow.createEl("button", { text: "Cancel" }).addEventListener("click", () => this.close());

    const attempt = async () => {
      const password = pwInput.value.trim();
      if (!password) { errorEl.setText("Enter a password."); return; }

      decryptBtn.disabled = true;
      decryptBtn.textContent = "Decrypting…";
      errorEl.setText("");

      try {
        const { githubUsername: login, repoOwner: owner, repoName: repo } = this.plugin.settings;
        const salt = await contextSalt(login, owner, repo);
        const candidateKey = await buildKey(password, salt);

        // Temporarily use this key to try decrypting
        const prevKey = derivedKey;
        derivedKey = candidateKey;
        const content = await this.app.vault.read(this.file);
        const dec = await decryptContent(content);
        derivedKey = prevKey; // restore

        if (dec === null) {
          errorEl.setText("Wrong password — could not decrypt.");
          decryptBtn.disabled = false;
          decryptBtn.textContent = "Decrypt & open";
          return;
        }

        // Write decrypted content — suppress sync push
        this.plugin.pulling = true;
        try {
          await this.app.vault.modify(this.file, dec);
          if (this.plugin.syncState?.files) delete this.plugin.syncState.files[this.file.path];
          await this.plugin.savePluginData();
        } finally {
          this.plugin.pulling = false;
        }

        this.close();
        this.onDecrypted();
      } catch (e: any) {
        errorEl.setText(`Error: ${e.message}`);
        decryptBtn.disabled = false;
        decryptBtn.textContent = "Decrypt & open";
      }
    };

    decryptBtn.addEventListener("click", attempt);
    pwInput.addEventListener("keydown", (e) => { if (e.key === "Enter") attempt(); });

    // Focus password input after modal animates in
    setTimeout(() => pwInput.focus(), 50);
  }

  onClose() { this.contentEl.empty(); }
}

class QuildenSyncSettingTab extends PluginSettingTab {
  plugin: QuildenSyncPlugin;
  private showAdvanced = false;
  private showEncryption = false;
  private allRepos: Array<{ full_name: string; private: boolean }> = [];
  private renderGeneration = 0;
  private activePollingTimer: number | null = null;
  private unlockFeedback: { ok: boolean; msg: string } | null = null;
  private encToggleMsg: "on" | "off" | null = null;
  private changingPassword = false;

  constructor(app: App, plugin: QuildenSyncPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  hide(): void {
    this.stopActivePolling();
  }

  private stopActivePolling(): void {
    if (this.activePollingTimer !== null) {
      window.clearInterval(this.activePollingTimer);
      this.activePollingTimer = null;
    }
  }

  display(): void {
    this.stopActivePolling();
    const { containerEl } = this;
    const generation = ++this.renderGeneration;
    containerEl.empty();
    containerEl.addClass("quilden-sync-settings");

    const titleRow = containerEl.createDiv({ cls: "lm-settings-title-row" });
    const titleEl = titleRow.createDiv({ cls: "lm-settings-title-heading" });
    titleEl.createEl("h2", { text: "Quilden Sync" });
    titleEl.createEl("span", { text: `v${this.plugin.manifest.version}`, cls: "lm-settings-version-badge" });
    const websiteLink = titleRow.createEl("a", {
      text: "Open Quilden Website",
      href: QUILDEN_BASE,
      cls: "lm-settings-title-link",
    });
    websiteLink.setAttr("target", "_blank");
    websiteLink.setAttr("rel", "noopener noreferrer");

    const connectionSection = containerEl.createDiv({ cls: "lm-settings-section" });
    this.renderConnectionWizard(connectionSection, generation);

    if (!this.plugin.isConfigured()) {
      containerEl.createDiv({
        cls: "quilden-not-connected-hint",
        text: "Connect a GitHub repository above to access sync settings.",
      });
      return;
    }

    // ── Sync now ──
    new Setting(containerEl).setName("Sync now").addButton((btn) =>
      btn.setButtonText("Sync").setCta().onClick(() => this.plugin.runSync())
    );

    // ── Encryption ──
    const encHeader = containerEl.createEl("h3", {
      cls: "setting-item-heading quilden-collapsible-heading",
    });
    encHeader.style.cursor = "pointer";

    const encHeaderText = encHeader.createSpan({ text: this.showEncryption ? "▼ Encryption" : "▶ Encryption" });

    // Status tag — visible even when collapsed
    const encTag = encHeader.createSpan({ cls: "quilden-enc-tag" });
    if (this.plugin.settings.encryptionEnabled && derivedKey) {
      encTag.addClass("quilden-enc-tag--active");
      setIcon(encTag, "lock");
      encTag.createSpan({ text: "active" });
    } else if (this.plugin.settings.encryptionEnabled) {
      encTag.addClass("quilden-enc-tag--locked");
      setIcon(encTag, "lock");
      encTag.createSpan({ text: "locked" });
    } else {
      encTag.addClass("quilden-enc-tag--off");
      setIcon(encTag, "lock-open");
      encTag.createSpan({ text: "off" });
    }

    encHeader.addEventListener("click", () => {
      this.showEncryption = !this.showEncryption;
      this.display();
    });

    if (this.showEncryption) {
      // ── Group 1: Status & enable toggle ──
      const encGroup1 = containerEl.createDiv("setting-group").createDiv("setting-items");

      const encStatus = encGroup1.createDiv("encryption-status");
      if (this.plugin.settings.encryptionEnabled && derivedKey) {
        encStatus.addClass("active");
        const scopeLabel = this.plugin.settings.encryptionScope === "all"
        ? "all files"
        : this.plugin.settings.encryptionScope === "media"
          ? "notes, images & PDFs"
          : "markdown notes";
      encStatus.setText(`🔒 Encryption active — ${scopeLabel} are encrypted before upload`);
      } else if (this.plugin.settings.encryptionEnabled) {
        encStatus.addClass("inactive");
        encStatus.setText("🔒 Encryption enabled — enter your password below to activate");
      } else {
        encStatus.addClass("inactive");
        encStatus.setText("🔓 Encryption disabled — files are stored as plain text in GitHub");
      }

      new Setting(encGroup1)
        .setName("Enable encryption")
        .setDesc("Encrypts files before pushing to GitHub.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.encryptionEnabled).onChange(async (v) => {
            this.unlockFeedback = null;
            this.encToggleMsg = v ? "on" : "off";
            this.plugin.settings.encryptionEnabled = v;
            if (!v) clearEncryptionKey();
            await this.plugin.saveSettings();
            this.display();
          })
        );

      if (this.encToggleMsg === "on") {
        encGroup1.createDiv({ cls: "enc-toggle-change-msg enc-toggle-change-msg--on",
          text: "Encryption enabled. New syncs will encrypt matching files. Files already in GitHub are not affected — use 'Encrypt existing repo content' below to encrypt them.",
        });
      } else if (this.encToggleMsg === "off") {
        encGroup1.createDiv({ cls: "enc-toggle-change-msg enc-toggle-change-msg--off",
          text: "Encryption disabled. New syncs will push files as plain text. Files already encrypted in GitHub remain encrypted — use 'Decrypt existing repo content' below to restore them as plain text.",
        });
      }

      if (this.plugin.settings.encryptionEnabled) {
        const encNote = encGroup1.createDiv("enc-toggle-note");
        if (this.plugin.hasExistingEncryption) {
          encNote.setText("This vault already has an encryption password set. Enter it below to unlock.");
        } else {
          encNote.setText("⚠️ Your encryption password cannot be changed later. If you forget it, your encrypted files cannot be recovered. Choose carefully.");
        }

        new Setting(encGroup1)
          .setName("Encrypt")
          .setDesc("Which file types to encrypt before pushing.")
          .addDropdown((dd) =>
            dd
              .addOption("markdown", "Markdown notes only")
              .addOption("media", "Notes, images & PDFs")
              .addOption("all", "Everything")
              .setValue(this.plugin.settings.encryptionScope ?? "markdown")
              .onChange(async (v) => {
                this.plugin.settings.encryptionScope = v as "markdown" | "media" | "all";
                await this.plugin.saveSettings();
                this.display();
              })
          );

        // ── Group 2: Password ──
        const pwGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

        const hasSaved = this.plugin.hasSavedKey;
        const showSavedState = !derivedKey && hasSaved && !this.changingPassword;
        const showInputState = (!derivedKey && (!hasSaved || this.changingPassword)) || (!!derivedKey && this.changingPassword);

        const pwSetting = new Setting(pwGroup)
          .setName("Vault password")
          .setDesc(
            derivedKey && !this.changingPassword
              ? "Encryption is active — files are encrypted on each sync."
              : showSavedState
                ? "Password saved on this device — auto-applied on startup."
                : "Enter your password to activate encryption."
          );

        if (derivedKey && !this.changingPassword) {
          pwSetting.addButton((btn) =>
            btn.setButtonText("Change password").onClick(() => {
              this.changingPassword = true;
              this.unlockFeedback = null;
              this.display();
            })
          );
        }

        if (showSavedState) {
          // Show filled-bullet placeholder + action buttons
          const savedInput = pwSetting.controlEl.createEl("input", {
            type: "password",
            cls: "enc-saved-pw-display",
          });
          savedInput.value = "••••••••";
          savedInput.readOnly = true;

          pwSetting
            .addButton((btn) =>
              btn.setButtonText("Unlock").setCta().onClick(async () => {
                this.unlockFeedback = null;
                const ok = await this.plugin.loadAndApplyEncKey();
                this.unlockFeedback = ok
                  ? { ok: true, msg: "✓ Encryption unlocked." }
                  : { ok: false, msg: "✗ Saved key is invalid. Try re-entering your password." };
                this.display();
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Change").onClick(() => {
                this.changingPassword = true;
                this.unlockFeedback = null;
                this.display();
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Forget").onClick(() => {
                this.plugin.clearEncKey();
                this.changingPassword = false;
                this.unlockFeedback = null;
                this.display();
              })
            );
        }

        if (showInputState) {
          const doUnlock = async (password: string) => {
            // If changing password while already unlocked, clear first so tryUnlockEncryption re-derives
            if (derivedKey) clearEncryptionKey();
            this.unlockFeedback = null;
            await this.plugin.tryUnlockEncryption(password);
            if (derivedKey) {
              await this.plugin.saveEncKey();
              this.changingPassword = false;
              this.unlockFeedback = { ok: true, msg: "✓ Password verified — key saved on this device." };
            } else {
              this.unlockFeedback = { ok: false, msg: "✗ Wrong password. Please try again." };
            }
            this.display();
          };

          pwSetting.addText((text) => {
            text.setPlaceholder("Password");
            text.inputEl.type = "password";
            text.inputEl.addEventListener("keydown", async (e) => {
              if (e.key !== "Enter") return;
              await doUnlock(text.getValue().trim());
            });
          });

          if (this.changingPassword) {
            pwSetting
              .addButton((btn) =>
                btn.setButtonText("Save new password").setCta().onClick(async () => {
                  const input = pwSetting.controlEl.querySelector("input") as HTMLInputElement | null;
                  await doUnlock(input?.value.trim() ?? "");
                })
              )
              .addButton((btn) =>
                btn.setButtonText("Cancel").onClick(() => {
                  this.changingPassword = false;
                  this.unlockFeedback = null;
                  this.display();
                })
              );
          } else {
            pwSetting.addButton((btn) =>
              btn.setButtonText("Unlock").onClick(async () => {
                const input = pwSetting.controlEl.querySelector("input") as HTMLInputElement | null;
                await doUnlock(input?.value.trim() ?? "");
              })
            );
          }
        }

        if (this.unlockFeedback) {
          pwGroup.createDiv({
            cls: this.unlockFeedback.ok ? "enc-feedback-ok" : "enc-feedback-err",
            text: this.unlockFeedback.msg,
          });
        }

        const repoContentSetting = new Setting(pwGroup)
          .setName("GitHub repo content")
          .setDesc(
            derivedKey
              ? "Encrypt or decrypt files already stored in your GitHub repo. This re-uploads all matching files."
              : "Unlock encryption above first."
          );

        if (derivedKey) {
          repoContentSetting
            .addButton((btn) =>
              btn.setButtonText("Encrypt all").onClick(async () => {
                const confirmed = await confirmDialog(
                  this.app,
                  "Encrypt existing repo content",
                  "This will re-upload all matching unencrypted files in your GitHub repo with encryption applied. Files already encrypted will be skipped. Continue?"
                );
                if (!confirmed) return;
                try {
                  await this.plugin.encryptExistingContent();
                } catch (e) {
                  new Notice(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
                }
              })
            )
            .addButton((btn) =>
              btn.setButtonText("Decrypt all").onClick(async () => {
                const confirmed = await confirmDialog(
                  this.app,
                  "Decrypt existing repo content",
                  "This will re-upload all encrypted files in your GitHub repo as plain text. This cannot be undone without re-encrypting. Continue?"
                );
                if (!confirmed) return;
                try {
                  await this.plugin.decryptExistingContent();
                } catch (e) {
                  new Notice(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
                }
              })
            );

          new Setting(pwGroup)
            .setName("Repair local vault")
            .setDesc(
              "Scan and decrypt any files in your local vault that still contain QENC-encrypted content. Also repairs images and PDFs accidentally stored as encrypted blobs. No GitHub calls — local only."
            )
            .addButton((btn) =>
              btn.setButtonText("Repair local files").onClick(async () => {
                const confirmed = await confirmDialog(
                  this.app,
                  "Repair local vault",
                  "This will scan your entire local vault, decrypt any QENC-encrypted text files, and restore any images or PDFs accidentally stored as encrypted blobs. Continue?"
                );
                if (!confirmed) return;
                try {
                  await this.plugin.decryptLocalVaultFiles();
                  await this.plugin.repairEncryptedMediaFiles();
                } catch (e) {
                  new Notice(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
                }
              })
            );
        } else {
          repoContentSetting.addButton((btn) =>
            btn.setButtonText("Locked").setDisabled(true)
          );
        }
      }
    }

    // ── Advanced ──
    const advHeader = containerEl.createEl("h3", {
      text: this.showAdvanced ? "▼ Advanced" : "▶ Advanced",
      cls: "setting-item-heading",
    });
    advHeader.style.cursor = "pointer";
    advHeader.addEventListener("click", () => {
      this.showAdvanced = !this.showAdvanced;
      this.display();
    });

    if (this.showAdvanced) {
      // ── Group 1: Sync behaviour ──
      const syncGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

      new Setting(syncGroup)
        .setName("Sync on save")
        .setDesc("Automatically push changes 5 seconds after you finish editing a note.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.syncOnSave).onChange(async (v) => {
            this.plugin.settings.syncOnSave = v;
            await this.plugin.saveSettings();
          })
        );

      new Setting(syncGroup)
        .setName("Sync on startup")
        .setDesc("Automatically sync when Obsidian opens.")
        .addToggle((t) =>
          t.setValue(this.plugin.settings.syncOnStartup).onChange(async (v) => {
            this.plugin.settings.syncOnStartup = v;
            await this.plugin.saveSettings();
          })
        );

      new Setting(syncGroup)
        .setName("Auto sync interval")
        .setDesc("Minutes between auto syncs. 0 to disable.")
        .addText((text) =>
          text
            .setPlaceholder("0")
            .setValue(String(this.plugin.settings.autoSyncInterval))
            .onChange(async (v) => {
              this.plugin.settings.autoSyncInterval = Math.max(0, parseInt(v) || 0);
              await this.plugin.saveSettings();
            })
        );

      new Setting(syncGroup)
        .setName("Notification location")
        .setDesc("Where sync status messages appear.")
        .addDropdown((d) =>
          d
            .addOption("notice", "Pop-up notification")
            .addOption("statusbar", "Status bar only")
            .addOption("none", "None (silent)")
            .setValue(this.plugin.settings.notificationLocation ?? "notice")
            .onChange(async (v) => {
              this.plugin.settings.notificationLocation = v as "notice" | "statusbar" | "none";
              await this.plugin.saveSettings();
            })
        );

      // ── Group 2: GitHub ──
      const ghGroup = containerEl.createDiv("setting-group").createDiv("setting-items");

      new Setting(ghGroup)
        .setName("Commit message")
        .setDesc("Custom commit message for pushes.")
        .addText((text) =>
          text
            .setPlaceholder("Quilden Sync: Update from Obsidian")
            .setValue(this.plugin.settings.commitMessage)
            .onChange(async (v) => {
              this.plugin.settings.commitMessage = v || DEFAULT_SETTINGS.commitMessage;
              await this.plugin.saveSettings();
            })
        );

      new Setting(ghGroup)
        .setName("Conflict strategy")
        .setDesc("How to resolve conflicts between local and remote.")
        .addDropdown((d) =>
          d
            .addOption("newer", "Keep newer")
            .addOption("local", "Keep local")
            .addOption("remote", "Keep remote")
            .setValue(this.plugin.settings.conflictStrategy)
            .onChange(async (v) => {
              this.plugin.settings.conflictStrategy = v as "local" | "remote" | "newer";
              await this.plugin.saveSettings();
            })
        );

      new Setting(ghGroup)
        .setName("Exclude patterns")
        .setDesc("Comma-separated path prefixes to exclude from sync.")
        .addTextArea((text) =>
          text
            .setPlaceholder("User patterns only; .obsidian/, .trash/, and .DS_Store are always excluded")
            .setValue(this.plugin.settings.excludePatterns.join(", "))
            .onChange(async (v) => {
              this.plugin.settings.excludePatterns = this.plugin.normalizeExcludePatterns(
                v.split(",").map((s) => s.trim()).filter(Boolean)
              );
              await this.plugin.saveSettings();
            })
        );

      if (this.plugin.isConfigured()) {
        new Setting(ghGroup)
          .setName("Restore from branch timeline")
          .setDesc("View all commits on this branch and restore the repo to any past state. A new commit is created — no history is lost.")
          .addButton((btn) =>
            btn.setButtonText("Open timeline").onClick(() => {
              const { githubToken, repoOwner, repoName, branch } = this.plugin.settings;
              const api = this.plugin.buildGitAPI();
              new BranchTimelineModal(this.plugin.app, api, this.plugin).open();
            })
          );
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Interactive GitHub connection wizard
  // ─────────────────────────────────────────────────────────────
  private renderConnectionWizard(containerEl: HTMLElement, generation: number) {
    containerEl.createEl("h3", { text: "Repository Connection", cls: "lm-settings-section-title" });
    const isConnected = !!(this.plugin.settings.githubToken && this.plugin.settings.githubUsername);
    if (isConnected) {
      this.renderConnectedState(containerEl, generation);
    } else {
      this.renderConnectSteps(containerEl, generation);
    }
  }

  // ── Connected state ──────────────────────────────────────────
  private renderConnectedState(containerEl: HTMLElement, generation: number) {
    const { settings } = this.plugin;
    const activeBranch = settings.branch || "main";
    const currentRepo = settings.repoOwner ? `${settings.repoOwner}/${settings.repoName}` : "";

    // ── Username + Disconnect ──
    const providerLabel = settings.provider === "gitea"
      ? `Gitea (${settings.giteaBaseUrl || "self-hosted"}) ✓`
      : "Connected to GitHub ✓";
    new Setting(containerEl)
      .setName(`@${settings.githubUsername}`)
      .setDesc(providerLabel)
      .addButton((btn) =>
        btn.setButtonText("Disconnect").onClick(async () => {
          this.plugin.settings.githubToken = "";
          this.plugin.settings.githubUsername = "";
          this.plugin.settings.repoOwner = "";
          this.plugin.settings.repoName = "";
          this.plugin.settings.branch = "main";
          this.plugin.settings.provider = "github";
          this.plugin.settings.giteaBaseUrl = "";
          this.allRepos = [];
          await this.plugin.saveSettings();
          this.display();
        })
      );

    // ── Quilden website access ──
    const quildenStatusEl = containerEl.createEl("div", { cls: "setting-item-description lm-quilden-status" });
    new Setting(containerEl)
      .setName("Use on Quilden website")
      .setDesc("Open your vault in the browser, or copy your token to sign in manually.")
      .addButton((btn) =>
        btn.setButtonText("Open in Quilden").setCta().onClick(() =>
          this.plugin.openQuildenWebsite(quildenStatusEl)
        )
      )
      .addButton((btn) =>
        btn.setButtonText("Copy token").onClick(async () => {
          if (!this.plugin.settings.githubToken) {
            new Notice("No token configured.");
            return;
          }
          try {
            await navigator.clipboard.writeText(this.plugin.settings.githubToken);
            btn.setButtonText("Copied!");
            new Notice(
              "⚠️ Keep this token secret! Anyone with it can access your connected GitHub repositories.",
              6000
            );
            setTimeout(() => btn.setButtonText("Copy token"), 2000);
          } catch {
            new Notice("Clipboard unavailable. Copy the token manually from settings.", 5000);
          }
        })
      );

    // ── Repository ──
    if (currentRepo) {
      const repoSetting = new Setting(containerEl)
        .setName("Repository")
        .setDesc(currentRepo)
        .addButton((btn) =>
          btn.setButtonText("Change").onClick(async () => {
            this.plugin.settings.repoOwner = "";
            this.plugin.settings.repoName = "";
            this.plugin.settings.branch = "main";
            await this.plugin.saveSettings();
            this.display();
          })
        );

      const branchMetaRow = repoSetting.descEl.createDiv({ cls: "lm-inline-branch-row" });
      branchMetaRow.createSpan({ text: `Branch: ${activeBranch}`, cls: "lm-inline-branch-label" });
      const changeBranchButton = branchMetaRow.createEl("button", {
        text: "Change branch",
        cls: "clickable-icon lm-inline-branch-button",
      });

      const branchControls = repoSetting.descEl.createDiv({ cls: "lm-inline-branch-controls is-hidden" });
      const branchStatus = branchControls.createDiv({ cls: "lm-inline-branch-status", text: "Loading branches…" });
      const branchDropdownHost = branchControls.createDiv({ cls: "lm-inline-branch-dropdown" });
      const branchDropdown = new DropdownComponent(branchDropdownHost);
      branchDropdown.addOption(activeBranch, activeBranch);
      branchDropdown.setValue(activeBranch);

      let branchesLoaded = false;
      let branchLoadInFlight = false;

      const loadBranches = async () => {
        if (branchesLoaded || branchLoadInFlight) return;
        branchLoadInFlight = true;
        branchStatus.setText("Loading branches…");
        changeBranchButton.disabled = true;

        try {
          const branches = await GitHubAPI.fetchBranches(settings.githubToken, settings.repoOwner, settings.repoName, this.plugin.resolveApiBase());
          if (this.renderGeneration !== generation || !branchDropdown.selectEl.isConnected) return;

          const nextValue = branches.includes(this.plugin.settings.branch || "main")
            ? (this.plugin.settings.branch || "main")
            : (branches[0] ?? "main");

          if (!branchDropdown.selectEl.isConnected) return;
          branchDropdown.selectEl.empty();
          branches.forEach((branch) => branchDropdown.addOption(branch, branch));
          branchDropdown.setValue(nextValue);
          branchStatus.setText("Select a branch if you want to sync something other than main.");
          branchesLoaded = true;
        } catch (error) {
          if (this.renderGeneration !== generation || !branchDropdown.selectEl.isConnected) return;
          const message = error instanceof Error ? error.message : "unknown error";
          branchStatus.setText(`Failed to load branches: ${message}`);
        } finally {
          branchLoadInFlight = false;
          if (this.renderGeneration === generation && changeBranchButton.isConnected) {
            changeBranchButton.disabled = false;
          }
        }
      };

      branchDropdown.onChange(async (value) => {
        this.plugin.settings.branch = value || "main";
        await this.plugin.saveSettings();
        this.display();
      });

      changeBranchButton.addEventListener("click", () => {
        const isHidden = branchControls.classList.contains("is-hidden");
        branchControls.classList.toggle("is-hidden", !isHidden);
        changeBranchButton.setText(isHidden ? "Hide branch" : "Change branch");
        if (isHidden) {
          void loadBranches();
        }
      });
    } else {
      let selectedRepo = "";
      let repoDropdown: DropdownComponent | null = null;
      let selectRepoButton: ButtonComponent | null = null;
      let loadingRepos = false;

      const repoPickerSetting = new Setting(containerEl)
        .setName("Repository")
        .setDesc("Loading repositories…")
        .addDropdown((dropdown) => {
          repoDropdown = dropdown;
          dropdown.addOption("", "Loading repositories…");
          dropdown.setValue("");
          dropdown.onChange((value) => {
            selectedRepo = value;
            selectRepoButton?.setDisabled(!selectedRepo);
          });
        })
        .addButton((btn) => {
          selectRepoButton = btn;
          btn.setButtonText("Use repo").setDisabled(true).onClick(async () => {
            if (!selectedRepo) return;
            const [owner, repo] = selectedRepo.split("/");
            this.plugin.settings.repoOwner = owner;
            this.plugin.settings.repoName = repo;
            this.plugin.settings.branch = "main";
            await this.plugin.saveSettings();
            this.display();
          });
        })
        .addButton((btn) => {
          if (settings.provider === "gitea") {
            btn.setButtonText("Open Gitea").onClick(() => {
              window.open(settings.giteaBaseUrl, "_blank");
            });
          } else {
            btn.setButtonText("Manage on GitHub").onClick(() => {
              window.open(`${QUILDEN_BASE}/api/auth/manage-repos`, "_blank");
            });
          }
        });

      const populateDropdown = () => {
        if (!repoDropdown) return;
        repoDropdown.selectEl.empty();
        if (this.allRepos.length === 0) {
          repoDropdown.addOption("", "No repositories found");
          repoDropdown.setValue("");
          selectedRepo = "";
          selectRepoButton?.setDisabled(true);
          repoPickerSetting.setDesc('No repositories found. Use "Manage on GitHub" to grant access.');
          return;
        }
        repoDropdown.addOption("", "Select a repository");
        this.allRepos.slice(0, 100).forEach((repo) => {
          repoDropdown?.addOption(repo.full_name, repo.full_name);
        });
        const extraCount = Math.max(this.allRepos.length - 100, 0);
        repoPickerSetting.setDesc(
          extraCount > 0
            ? `Showing 100 of ${this.allRepos.length} repositories.`
            : `${this.allRepos.length} repositor${this.allRepos.length === 1 ? "y" : "ies"} available.`
        );
        const preserved = this.allRepos.some((r) => r.full_name === selectedRepo) ? selectedRepo : "";
        selectedRepo = preserved;
        repoDropdown.setValue(preserved);
        selectRepoButton?.setDisabled(!preserved);
      };

      const loadRepos = async () => {
        if (loadingRepos) return;
        if (this.allRepos.length > 0) { populateDropdown(); return; }
        loadingRepos = true;
        try {
          this.allRepos = await GitHubAPI.fetchRepos(settings.githubToken, this.plugin.resolveApiBase());
          if (this.renderGeneration !== generation || !containerEl.isConnected) return;
          populateDropdown();
        } catch (error) {
          if (this.renderGeneration !== generation || !containerEl.isConnected) return;
          const message = error instanceof Error ? error.message : "unknown error";
          repoPickerSetting.setDesc(`Failed to load repositories: ${message}`);
          repoDropdown?.selectEl.empty();
          repoDropdown?.addOption("", "Failed to load");
          repoDropdown?.setValue("");
          selectedRepo = "";
          selectRepoButton?.setDisabled(true);
        } finally {
          loadingRepos = false;
        }
      };

      void loadRepos();
    }
  }

  private async loadBranchSection(
    sel: HTMLSelectElement,
    token: string,
    owner: string,
    repo: string,
    currentBranch: string
  ) {
    sel.empty();
    sel.createEl("option", { text: "Loading…" });

    try {
      const branches = await GitHubAPI.fetchBranches(token, owner, repo);
      sel.empty();
      branches.forEach((b) => {
        const opt = sel.createEl("option", { text: b });
        opt.value = b;
        if (b === currentBranch) opt.selected = true;
      });
    } catch {
      sel.empty();
      sel.createEl("option", { text: "Failed to load" });
    }

    sel.addEventListener("change", async () => {
      this.plugin.settings.branch = sel.value;
      await this.plugin.saveSettings();
    });
  }

  // ── Not connected: OAuth flow via Quilden ────────────────
  private renderConnectSteps(containerEl: HTMLElement, generation: number) {
    const statusEl = containerEl.createEl("div", { cls: "setting-item-description" });
    const errorEl = containerEl.createEl("div", { cls: "setting-item-description" });

    // ── Provider selector ──────────────────────────────────────────
    const { settings } = this.plugin;
    new Setting(containerEl)
      .setName("Git provider")
      .setDesc("Choose GitHub or a self-hosted Gitea instance.")
      .addDropdown((d) => {
        d.addOption("github", "GitHub");
        d.addOption("gitea", "Gitea (self-hosted)");
        d.setValue(settings.provider ?? "github");
        d.onChange(async (v) => {
          settings.provider = v as "github" | "gitea";
          await this.plugin.saveSettings();
          this.display();
        });
      });

    if (settings.provider === "gitea") {
      // ── Gitea URL + PAT connect ────────────────────────────────
      let giteaUrlInput = "";
      let giteaPatInput = "";
      const giteaStatusEl = containerEl.createEl("div", { cls: "setting-item-description" });

      new Setting(containerEl)
        .setName("Gitea URL")
        .setDesc("Base URL of your Gitea instance (e.g. https://git.example.com)")
        .addText((t) => {
          t.setPlaceholder("https://git.example.com");
          t.setValue(settings.giteaBaseUrl ?? "");
          t.onChange((v) => { giteaUrlInput = v.trim(); });
          t.inputEl.style.width = "260px";
        });

      new Setting(containerEl)
        .setName("Personal Access Token")
        .setDesc("Gitea → Settings → Applications. Required scopes: user (Read) + repository (Read and Write).")
        .addText((t) => {
          t.setPlaceholder("Gitea access token");
          t.inputEl.type = "password";
          t.onChange((v) => { giteaPatInput = v.trim(); });
          t.inputEl.style.width = "260px";
        })
        .addButton((btn) =>
          btn.setButtonText("Connect").setCta().onClick(async () => {
            const url = giteaUrlInput || settings.giteaBaseUrl;
            const pat = giteaPatInput;
            if (!url) { giteaStatusEl.setText("Enter Gitea URL first."); return; }
            if (!pat) { giteaStatusEl.setText("Enter a Personal Access Token."); return; }
            btn.setDisabled(true);
            btn.setButtonText("Verifying…");
            giteaStatusEl.setText("");
            try {
              let apiBase: string;
              try {
                apiBase = `${new URL(url).origin}/api/v1`;
              } catch {
                giteaStatusEl.setText("Invalid URL format.");
                return;
              }
              const requestUrl2 = `${apiBase}/user`;
              const headers = apiHeaders(pat, apiBase);
              console.log("[Quilden] Gitea connect attempt:", { url, apiBase, requestUrl: requestUrl2, headers: { ...headers, Authorization: headers.Authorization?.replace(/token .+/, "token [REDACTED]") } });
              const user = await GitHubAPI.verifyToken(pat, apiBase);
              console.log("[Quilden] Gitea connect success:", user);
              settings.githubToken = pat;
              settings.githubUsername = user.login;
              settings.giteaBaseUrl = new URL(url).origin;
              settings.provider = "gitea";
              await this.plugin.saveSettings();
              new Notice(`Quilden Sync: Connected to Gitea as @${user.login} ✓`);
              this.display();
            } catch (e: any) {
              console.error("[Quilden] Gitea connect error:", e);
              giteaStatusEl.setText(`Connection failed: ${e.message}`);
            } finally {
              btn.setDisabled(false);
              btn.setButtonText("Connect");
            }
          })
        );

      return; // Gitea PAT-only — no polling needed
    }

    // ── GitHub OAuth flow ──────────────────────────────────────────
    // Stateless deep-link flow: after OAuth, quilden.com redirects the
    // browser to obsidian://quilden-auth?token=...&login=... which fires
    // the registerObsidianProtocolHandler registered in onload().

    new Setting(containerEl)
      .setName("GitHub account")
      .setDesc("Sign in with GitHub through Quilden. You choose exactly which repositories to share.")
      .addButton((btn) =>
        btn.setButtonText("Connect with GitHub").setCta().onClick(async () => {
          errorEl.setText("");

          const state = Array.from(crypto.getRandomValues(new Uint8Array(18)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          let githubOAuthUrl = `${QUILDEN_BASE}/api/auth/plugin-login?state=${state}`;
          try {
            const initRes = await requestUrl({
              url: `${QUILDEN_BASE}/api/auth/plugin-login?state=${state}&json=1`,
              method: "GET",
              throw: false,
            });
            if (initRes.status === 200 && initRes.json?.url) {
              githubOAuthUrl = initRes.json.url;
            }
          } catch {
            // fall back to redirect flow
          }
          if (this.renderGeneration !== generation || !containerEl.isConnected || !btn.buttonEl.isConnected) return;

          const authWindow = window.open(githubOAuthUrl, "_blank");
          if (!authWindow) {
            errorEl.empty();
            errorEl.appendText("Popup blocked. ");
            const link = errorEl.createEl("a", {
              text: "Click here to sign in",
              href: githubOAuthUrl,
            });
            link.setAttr("target", "_blank");
            link.setAttr("rel", "noopener noreferrer");
          }

          btn.setDisabled(true);
          btn.setButtonText("Waiting…");
          statusEl.setText("Complete sign-in in the browser — Obsidian will update automatically.");
          // Re-enable button after 5 minutes in case something went wrong
          window.setTimeout(() => {
            if (btn.buttonEl.isConnected) {
              btn.setDisabled(false);
              btn.setButtonText("Connect with GitHub");
              statusEl.setText("");
            }
          }, 5 * 60 * 1000);
        })
      );

  }
}
