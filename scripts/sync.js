const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const { URL } = require('url');

// === 配置区域 ===
const CF_API_URL = 'https://api.cloudflare.com/client/v4';
const DOMAIN_ROOT = 'is-a.page';

// 保留域名
const RESERVED_DOMAINS = new Set([
  'www', 'api', 'blog', 'mail', 'smtp', 'pop', 'imap', 
  'support', 'admin', 'root', 'status', 'billing', 'cdn', 'test',
  'dev', 'staging', 'prod', 'official', 'security', 'ns1', 'ns2', 'root', 'email'
]);

// 敏感词黑名单 (从环境变量读取 Secrets)
const blocklistEnv = process.env.KEYWORD_BLOCKLIST || '';
const KEYWORD_BLOCKLIST = blocklistEnv.split(',').map(s => s.trim()).filter(Boolean);

console.log(`🛡️ Loaded ${KEYWORD_BLOCKLIST.length} keywords into security blocklist.`);

const CF_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const ZONE_ID = process.env.CLOUDFLARE_ZONE_ID;
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const LIST_ID = process.env.CLOUDFLARE_LIST_ID;

if (!CF_TOKEN || !ZONE_ID || !ACCOUNT_ID || !LIST_ID) {
  console.error("❌ Error: Missing Cloudflare environment variables.");
  process.exit(1);
}

const api = axios.create({
  baseURL: CF_API_URL,
  headers: {
    'Authorization': 'Bearer ' + CF_TOKEN,
    'Content-Type': 'application/json',
  },
});

/**
 * 安全的 JSON 注释剥离器
 */
function parseJSONWithComments(jsonString) {
  const cleaned = jsonString.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
  return JSON.parse(cleaned);
}

/**
 * 核心验证与容错提取函数
 */
function validateAndExtract(subdomain, data) {
  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!labelRegex.test(subdomain)) return { error: 'Invalid subdomain format.' };
  if (RESERVED_DOMAINS.has(subdomain)) return { error: 'Subdomain is reserved.' };
  if (KEYWORD_BLOCKLIST.some(kw => subdomain.includes(kw))) return { error: 'Subdomain contains forbidden keywords.' };
  if (!data.type) return { error: 'Missing "type" field.' };

  const type = data.type.toUpperCase();
  const allowedTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'REDIRECT'];
  if (!allowedTypes.includes(type)) {
    return { error: `Invalid type '${type}'. Allowed: A, AAAA, CNAME, TXT, MX, REDIRECT` };
  }

  let target = data.content || data.value || data.target || data.url || data.cname || data.ip || data.ipv6 || data.txt || data.mx;
  if (!target && type !== 'REDIRECT') return { error: `Missing routing target for type ${type}.` };

  let proxied = data.proxied !== undefined ? data.proxied : true;
  if (['TXT', 'MX'].includes(type)) {
    proxied = false; 
  }

  // 这里的 Managed 前缀是后续用于判断是否允许删除/覆盖的唯一凭证！
  const result = {
    type: type,
    proxied: proxied,
    comment: "Managed: " + (data.owner && data.owner.username ? data.owner.username : "unknown")
  };

  if (type === 'REDIRECT') {
    if (!target) return { error: 'Missing "url" field for redirect.' };
    try {
      const urlObj = new URL(target);
      if (!['http:', 'https:'].includes(urlObj.protocol)) return { error: 'Redirect URL must be http/https.' };
    } catch (e) { return { error: `Invalid URL: ${target}` }; }
    result.url = target;
    result.proxied = true;
  } 
  else if (type === 'A') {
    if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) return { error: `Invalid IPv4: ${target}` };
    result.content = target;
  }
  else if (type === 'AAAA') {
    if (!target.includes(':')) return { error: `Invalid IPv6: ${target}` };
    result.content = target;
  }
  else if (type === 'MX') {
    result.content = target;
    result.priority = data.priority || 10;
  }
  else {
    result.content = target;
  }

  return { data: result };
}

async function main() {
  console.log("🚀 Starting Sync (v3.1 - Auto GC & Conflict Prevention)...");

  const domainsDir = path.join(__dirname, '../domains');
  if (!fs.existsSync(domainsDir)) {
    console.error("❌ Error: domains directory not found.");
    process.exit(1);
  }

  const files = fs.readdirSync(domainsDir).filter(f => f.endsWith('.json'));
  console.log(`📂 Found ${files.length} local domain files.`);

  const dnsUpdates = []; 
  const redirectItems = []; 

  // 解析本地 JSON 期望状态
  for (const file of files) {
    const subdomain = file.replace('.json', '').toLowerCase();
    
    try {
      const filePath = path.join(domainsDir, file);
      const rawFileContent = fs.readFileSync(filePath, 'utf8');
      
      const data = parseJSONWithComments(rawFileContent);
      const { error, data: extracted } = validateAndExtract(subdomain, data);
      
      if (error) {
        console.warn(`⚠️ SKIPPING ${file}: ${error}`);
        continue;
      }

      if (extracted.type === 'REDIRECT') {
        redirectItems.push({
          redirect: {
            source_url: subdomain + "." + DOMAIN_ROOT,
            target_url: extracted.url,
            status_code: 302,
            include_subdomains: false,
            subpath_matching: true,
            preserve_query_string: true,
            preserve_path_suffix: false,
          },
        });
      } else {
        dnsUpdates.push({
          type: extracted.type,
          name: subdomain,
          content: String(extracted.content),
          proxied: extracted.proxied,
          priority: extracted.priority,
          comment: extracted.comment,
        });
      }
    } catch (err) {
      console.error(`❌ Error parsing ${file}:`, err.message);
    }
  }

  // 拉取云端存量 DNS 记录
  console.log("☁️ Fetching existing DNS records from Cloudflare...");
  let existingRecords = [];
  let page = 1;
  let totalPages = 1;

  try {
    do {
      const recordsRes = await api.get(`/zones/${ZONE_ID}/dns_records`, {
        params: { per_page: 500, page: page }
      });
      existingRecords = existingRecords.concat(recordsRes.data.result);
      totalPages = recordsRes.data.result_info.total_pages;
      page++;
    } while (page <= totalPages);
    
    console.log(`✅ Loaded ${existingRecords.length} existing DNS records.`);
  } catch (err) {
    console.error("❌ Failed to fetch existing DNS records:", err.response?.data || err.message);
    process.exit(1); 
  }

  // 定义集合，用于快速检查某个存量记录是否仍在本地 JSON 中
  // 键的格式: "域名|类型" (例如: test.is-a.page|CNAME)
  const desiredDnsSet = new Set(dnsUpdates.map(d => `${d.name}.${DOMAIN_ROOT}|${d.type}`));

  // === 阶段 1：删除操作 (Garbage Collection) ===
  console.log("🧹 Running Garbage Collection...");
  for (const record of existingRecords) {
    // 只有带有 "Managed:" 标签的记录才受系统管辖
    const isManaged = record.comment && record.comment.startsWith("Managed:");
    
    if (isManaged) {
      const recordKey = `${record.name}|${record.type}`;
      // 如果云端是托管记录，但本地已经找不到对应项，说明已被用户删除 PR，执行清理
      if (!desiredDnsSet.has(recordKey)) {
        console.log(`🗑️ Deleting orphan DNS record: [${record.type}] ${record.name}`);
        try {
          await api.delete(`/zones/${ZONE_ID}/dns_records/${record.id}`);
        } catch (err) {
          console.error(`❌ Failed to delete ${record.name}:`, err.response?.data?.errors || err.message);
        }
      }
    }
  }

  // === 阶段 2：创建与更新操作 ===
  if (dnsUpdates.length > 0) {
    console.log(`🔄 Syncing ${dnsUpdates.length} DNS records...`);
    for (const desired of dnsUpdates) {
      const fullDomain = `${desired.name}.${DOMAIN_ROOT}`;
      
      // 找出云端所有同名的记录
      const domainRecords = existingRecords.filter(r => r.name === fullDomain);
      
      // 防冲突机制：如果云端存在同名记录，且它没有 "Managed:" 标签，说明这是管理员手动配的
      const hasUnmanagedConflict = domainRecords.some(r => !(r.comment && r.comment.startsWith("Managed:")));
      if (hasUnmanagedConflict) {
        console.warn(`🛑 Conflict Prevented: '${fullDomain}' already exists manually in Cloudflare. Skipping GitOps update.`);
        continue;
      }

      // 在同名同类型的记录中寻找是否已存在
      const existing = domainRecords.find(r => r.type === desired.type);

      const payload = {
        type: desired.type,
        name: desired.name,
        content: desired.content,
        proxied: desired.proxied,
        ttl: 1,
        comment: desired.comment,
      };
      if (desired.priority !== undefined) payload.priority = desired.priority;

      try {
        if (!existing) {
          console.log(`➕ Creating DNS: [${desired.type}] ${fullDomain} -> ${desired.content} (Proxied: ${desired.proxied})`);
          await api.post(`/zones/${ZONE_ID}/dns_records`, payload);
        } else {
          // 对比内容，判断是否需要调用 PUT 更新
          const contentChanged = existing.content !== desired.content;
          const proxiedChanged = existing.proxied !== desired.proxied;
          const typeChanged = existing.type !== desired.type;
          const priorityChanged = desired.type === 'MX' && existing.priority !== desired.priority;
          const commentChanged = existing.comment !== desired.comment; // Owner 发生了变更

          if (contentChanged || proxiedChanged || typeChanged || priorityChanged || commentChanged) {
            console.log(`🔄 Updating DNS: [${desired.type}] ${fullDomain} -> ${desired.content}`);
            await api.put(`/zones/${ZONE_ID}/dns_records/${existing.id}`, payload);
          }
        }
      } catch (err) {
        console.error(`❌ Failed to sync DNS for ${fullDomain}:`, err.response?.data?.errors || err.message);
      }
    }
  } else {
    console.log("ℹ️ No standard DNS records to sync.");
  }

  // === 阶段 3：处理 Redirect (天然支持删除) ===
  // 注意：Cloudflare List Item API 的 PUT 操作是全量替换机制。
  // 本地删除了 redirect JSON，生成的新 redirectItems 里自然就没它了，
  // 传给 Cloudflare 就会直接从列表中抹除，因此 Redirect 不需要额外的 Delete 逻辑！
  if (redirectItems.length > 0) {
    console.log(`🔀 Syncing ${redirectItems.length} redirect rules...`);
    try {
      const url = `/accounts/${ACCOUNT_ID}/rules/lists/${LIST_ID}/items`;
      const res = await api.put(url, redirectItems);

      if (res.data.success) {
        console.log("✅ Redirects synced successfully!");
      } else {
        console.error("❌ Cloudflare API returned success: false", res.data.errors);
      }
    } catch (err) {
      console.error("❌ Redirect Sync Failed:", err.response?.data || err.message);
    }
  } else {
    console.log("ℹ️ No redirects to sync.");
    // 安全起见：如果本地的所有 Redirect 都被删除了，我们要清空云端列表
    try {
      console.log("🧹 Clearing all redirect rules (0 local files found)...");
      await api.put(`/accounts/${ACCOUNT_ID}/rules/lists/${LIST_ID}/items`, []);
    } catch (err) {
      console.error("❌ Failed to clear redirects:", err.response?.data || err.message);
    }
  }

  console.log("🎉 All sync operations completed successfully.");
}

main();
