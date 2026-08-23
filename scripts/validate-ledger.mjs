import { createHash } from "node:crypto";
import { readdir, readFile, realpath, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = resolve(import.meta.dirname, "..");
const format = process.argv.slice(2).includes("--format");
const forbiddenKeys = /^(?:accessToken|refreshToken|oauth|xUserId|xUsername|providerUserId|walletToX|privatePartnerTerms|email|privateKey|secretKey|keypair|mnemonic|seedPhrase)$/i;
const forbiddenNormalizedKeys = new Set([
  "accesstoken",
  "apitoken",
  "email",
  "keypair",
  "mnemonic",
  "oauth",
  "oauthtoken",
  "partnertermsprivate",
  "privatekey",
  "privatepartnerterms",
  "provideruserid",
  "refreshtoken",
  "secretkey",
  "seedphrase",
  "signingkey",
  "wallettox",
  "xuserid",
  "xusername",
]);
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const rewardsProgramId = "REWArDioXgQJ2fZKkfu9LCLjQfRwYWVVfsvcsR5hoXi";
const rewardsAuditedCommit = "aa1cfd9276375e44e57d1917d110ff095fb6d475";
const schemaByKind = new Map([
  ["allocation", "https://cheapcoin.fun/schemas/allocation-list-v1.schema.json"],
  ["campaign", "https://cheapcoin.fun/schemas/campaign-manifest-v1.schema.json"],
  ["deployment", "https://cheapcoin.fun/schemas/deployment-record-v1.schema.json"],
  ["reconciliation", "https://cheapcoin.fun/schemas/reconciliation-v1.schema.json"],
  ["transaction", "https://cheapcoin.fun/schemas/transaction-record-v1.schema.json"],
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function canonical(value) {
  const visit = (candidate) => {
    if (Array.isArray(candidate)) return candidate.map(visit);
    if (candidate && typeof candidate === "object") return Object.fromEntries(Object.entries(candidate).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, visit(child)]));
    assert(candidate === null || typeof candidate === "string" || typeof candidate === "boolean" || (typeof candidate === "number" && Number.isFinite(candidate)), "JSON contains a non-canonical value");
    return candidate;
  };
  return `${JSON.stringify(visit(value), null, 2)}\n`;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeBase58(value, file, field) {
  assert(typeof value === "string" && value.length > 0, `${file}: ${field} must be a non-empty base58 string`);
  let number = 0n;
  for (const character of value) {
    const digit = base58Alphabet.indexOf(character);
    assert(digit !== -1, `${file}: ${field} is not valid base58`);
    number = number * 58n + BigInt(digit);
  }
  const decoded = [];
  while (number > 0n) {
    decoded.push(Number(number & 255n));
    number >>= 8n;
  }
  decoded.reverse();
  const leadingZeroes = value.match(/^1*/u)?.[0].length ?? 0;
  return Uint8Array.from([...new Array(leadingZeroes).fill(0), ...decoded]);
}

function assertAddress(value, file, field) {
  assert(decodeBase58(value, file, field).length === 32, `${file}: ${field} must decode to exactly 32 bytes`);
}

function assertSignature(value, file, field) {
  const decoded = decodeBase58(value, file, field);
  assert(decoded.length === 64, `${file}: ${field} must decode to exactly 64 bytes`);
  assert(decoded.some((byte) => byte !== 0), `${file}: ${field} may not be the all-zero signature`);
}

function assertPublicUri(value, file, field) {
  assert(typeof value === "string", `${file}: ${field} must be a URI string`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${file}: ${field} is not a valid URI`);
  }
  assert(["https:", "ipfs:", "ar:"].includes(parsed.protocol), `${file}: ${field} must use https, ipfs, or ar`);
  assert(parsed.hostname.length > 0, `${file}: ${field} must include a host or content identifier`);
  assert(parsed.username === "" && parsed.password === "", `${file}: ${field} may not embed credentials`);
  assert(parsed.hash === "", `${file}: ${field} may not contain a fragment`);
}

function scanPrivateFields(value, file, path = "$") {
  if (Array.isArray(value)) return value.forEach((child, index) => scanPrivateFields(child, file, `${path}[${index}]`));
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.replaceAll(/[^a-z0-9]/gi, "").toLowerCase();
    assert(!forbiddenKeys.test(key) && !forbiddenNormalizedKeys.has(normalizedKey), `${file}: forbidden private/signing field ${path}.${key}`);
    if (normalizedKey === "uri" || normalizedKey.endsWith("uri")) assertPublicUri(child, file, `${path}.${key}`);
    scanPrivateFields(child, file, `${path}.${key}`);
  }
}

async function files(directory, extension) {
  const base = resolve(root, directory);
  const result = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = resolve(current, entry.name);
      const file = relative(root, path).replaceAll("\\", "/");
      assert(!entry.isSymbolicLink(), `${file}: symbolic links are forbidden`);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile() && entry.name.endsWith(extension)) result.push(path);
      else if (!(entry.isFile() && entry.name === "README.md")) throw new Error(`${file}: unexpected file`);
    }
  }
  await walk(base);
  return result.sort();
}

async function safeEvidencePath(fromFile, referencedPath, allowedRoots) {
  assert(typeof referencedPath === "string" && !referencedPath.includes("\\") && !referencedPath.split("/").includes(".."), `${fromFile}: unsafe evidence path`);
  assert(allowedRoots.some((allowed) => referencedPath.startsWith(`${allowed}/`)), `${fromFile}: path is outside its allowed evidence root`);
  const expected = resolve(root, referencedPath);
  const actual = await realpath(expected);
  assert(actual === expected && actual.startsWith(`${root}${sep}`), `${fromFile}: evidence path is not canonical`);
  return actual;
}

function assertFixtureBoundary(value, referencedPath, referencedValue, file, field) {
  const pathIsFixture = referencedPath.startsWith("fixtures/");
  assert(pathIsFixture === value.fixture, `${file}: ${field} crosses the fixture/publication boundary`);
  if (referencedValue) assert(referencedValue.fixture === value.fixture, `${file}: ${field} fixture flag mismatch`);
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const schemaFiles = await files("schemas", ".json");
for (const path of schemaFiles) {
  const source = await readFile(path, "utf8");
  const value = JSON.parse(source);
  assert(value.$schema === "https://json-schema.org/draft/2020-12/schema", `${relative(root, path)}: unsupported JSON Schema draft`);
  ajv.addSchema(value);
  if (format && source !== canonical(value)) await writeFile(path, canonical(value));
}

const records = new Map();
for (const [kind, schemaId] of schemaByKind) {
  const validator = ajv.getSchema(schemaId);
  assert(validator, `Missing schema ${schemaId}`);
  const directories = [`${kind}s`, `fixtures/${kind}s`];
  for (const directory of directories) {
    for (const path of await files(directory, ".json")) {
      const file = relative(root, path).replaceAll("\\", "/");
      const source = await readFile(path, "utf8");
      const value = JSON.parse(source);
      assert(validator(value), `${file}: ${ajv.errorsText(validator.errors, { separator: "; " })}`);
      assert(value.recordType === kind, `${file}: recordType does not match its directory`);
      assert(file.startsWith("fixtures/") === value.fixture, `${file}: fixture flag does not match its directory`);
      scanPrivateFields(value, file);
      const canonicalSource = canonical(value);
      if (format && source !== canonicalSource) await writeFile(path, canonicalSource);
      else assert(source === canonicalSource, `${file}: JSON is not canonical; run pnpm format:evidence`);
      const key = `${kind}:${value[kind === "campaign" ? "campaignId" : kind === "allocation" ? "campaignId" : kind === "deployment" ? "recordId" : kind === "transaction" ? "transactionId" : "reconciliationId"]}`;
      assert(!records.has(key), `${file}: duplicate record identity ${key}`);
      records.set(key, { file, path, value, sha256: digest(Buffer.from(canonicalSource)) });
    }
  }
}

for (const record of records.values()) {
  const { file, value } = record;
  if (value.recordType === "allocation") {
    if (value.asset.mint) assertAddress(value.asset.mint, file, "asset.mint");
    let total = 0n;
    let previous = "";
    const seen = new Set();
    for (const [index, recipient] of value.recipients.entries()) {
      assertAddress(recipient.address, file, `recipients[${index}].address`);
      assert(!seen.has(recipient.address), `${file}: duplicate recipient ${recipient.address}`);
      assert(previous.localeCompare(recipient.address) < 0, `${file}: recipients must be address-sorted at index ${index}`);
      seen.add(recipient.address);
      previous = recipient.address;
      total += BigInt(recipient.amount);
    }
    assert(total === BigInt(value.total), `${file}: allocation total does not reproduce`);
  }

  if (value.recordType === "campaign") {
    assertAddress(value.sourceTreasury, file, "sourceTreasury");
    if (value.asset.kind === "SPL_TOKEN") {
      assert(value.asset.mint && value.asset.tokenProgram, `${file}: SPL asset requires mint and token program`);
      assertAddress(value.asset.mint, file, "asset.mint");
      assertAddress(value.asset.tokenProgram, file, "asset.tokenProgram");
      assert(value.asset.tokenProgram === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", `${file}: Token-2022 campaigns require extension inspection and are disabled in V1`);
    }
    const allocationPath = await safeEvidencePath(file, value.allocation.path, ["allocations", "fixtures/allocations"]);
    const allocationBytes = await readFile(allocationPath);
    const allocation = JSON.parse(allocationBytes);
    assertFixtureBoundary(value, value.allocation.path, allocation, file, "allocation");
    assert(digest(allocationBytes) === value.allocation.sha256, `${file}: allocation SHA-256 mismatch`);
    assert(allocation.campaignId === value.campaignId, `${file}: allocation campaignId mismatch`);
    assert(allocation.cluster === value.cluster, `${file}: allocation cluster mismatch`);
    assert(allocation.snapshotSlot === value.snapshotSlot, `${file}: allocation snapshot slot mismatch`);
    assert(allocation.asset.kind === value.asset.kind && allocation.asset.decimals === value.asset.decimals && allocation.asset.mint === value.asset.mint, `${file}: allocation asset mismatch`);
    assert(allocation.total === value.budget, `${file}: allocation total differs from budget`);
    assert(allocation.recipients.length === value.allocation.recipientCount, `${file}: recipient count mismatch`);
    const rulesPath = await safeEvidencePath(file, value.rules.path, ["rules", "fixtures/rules"]);
    assertFixtureBoundary(value, value.rules.path, null, file, "rules");
    assert(digest(await readFile(rulesPath)) === value.rules.sha256, `${file}: rules SHA-256 mismatch`);
    if (value.delivery === "SQUADS_BATCH") assert(allocation.recipients.length <= 200, `${file}: direct batch exceeds 200 recipients`);
    if (value.delivery === "MERKLE_REWARDS") {
      assert(value.asset.kind === "SPL_TOKEN", `${file}: Merkle campaigns require an SPL asset; native SOL must be wrapped`);
      assert(value.rewardsDeployment, `${file}: Merkle delivery lacks a pinned deployment`);
      assert(value.rewardsDeployment.programId === rewardsProgramId, `${file}: Merkle rewards program ID is not the pinned audited baseline`);
      assert(value.rewardsDeployment.auditedCommit === rewardsAuditedCommit, `${file}: Merkle rewards commit is not the pinned audited baseline`);
      assertAddress(value.rewardsDeployment.programId, file, "rewardsDeployment.programId");
      const deploymentPath = await safeEvidencePath(file, value.rewardsDeployment.deploymentRecordPath, ["deployments", "fixtures/deployments"]);
      const deploymentBytes = await readFile(deploymentPath);
      const deployment = JSON.parse(deploymentBytes);
      assertFixtureBoundary(value, value.rewardsDeployment.deploymentRecordPath, deployment, file, "rewards deployment");
      assert(digest(deploymentBytes) === value.rewardsDeployment.manifestSha256, `${file}: rewards deployment SHA-256 mismatch`);
      assert(deployment.purpose === "MERKLE_REWARDS" && deployment.programId === value.rewardsDeployment.programId && deployment.cluster === value.cluster, `${file}: rewards deployment identity mismatch`);
      assert(deployment.audit?.auditedCommit === value.rewardsDeployment.auditedCommit, `${file}: rewards deployment audit commit mismatch`);
    }
  }

  if (value.recordType === "deployment") {
    assertAddress(value.programId, file, "programId");
    if (value.upgradeAuthority) assertAddress(value.upgradeAuthority, file, "upgradeAuthority");
    assertSignature(value.deploymentSignature, file, "deploymentSignature");
    assert(BigInt(value.verifiedSlot) >= BigInt(value.deployedSlot), `${file}: verifiedSlot precedes deployedSlot`);
    if (value.purpose === "MERKLE_REWARDS") {
      assert(value.programId === rewardsProgramId, `${file}: Merkle deployment does not use the pinned rewards program ID`);
      assert(value.sourceCommit === rewardsAuditedCommit, `${file}: Merkle deployment source is not the pinned audited commit`);
      assert(value.audit?.auditedCommit === rewardsAuditedCommit, `${file}: Merkle deployment lacks the pinned audit commitment`);
    }
  }

  if (value.recordType === "transaction") {
    const campaignPath = await safeEvidencePath(file, value.campaignManifestPath, ["campaigns", "fixtures/campaigns"]);
    const campaignBytes = await readFile(campaignPath);
    const campaign = JSON.parse(campaignBytes);
    assertFixtureBoundary(value, value.campaignManifestPath, campaign, file, "campaign manifest");
    assert(digest(campaignBytes) === value.campaignManifestSha256, `${file}: campaign manifest SHA-256 mismatch`);
    assert(campaign.campaignId === value.campaignId, `${file}: campaignId differs from the referenced manifest`);
    assert(campaign.cluster === value.cluster, `${file}: cluster differs from the referenced manifest`);
    const allowedKinds = campaign.delivery === "SQUADS_BATCH" ? ["SQUADS_BATCH"] : ["MERKLE_FUND", "MERKLE_CLAWBACK", "CLAIM", "UNWRAP"];
    assert(allowedKinds.includes(value.kind), `${file}: transaction kind is incompatible with campaign delivery`);
    assert((value.status === "EXECUTED") === Boolean(value.signature), `${file}: only executed transactions carry signatures`);
    assert((value.status === "EXECUTED") === Boolean(value.finalizedSlot), `${file}: executed transaction finality is incomplete`);
    if (value.signature) assertSignature(value.signature, file, "signature");
    if (["SIMULATED", "EXECUTED"].includes(value.status)) assert(value.simulation.successful && value.simulation.error === null, `${file}: successful status requires successful simulation`);
  }

  if (value.recordType === "reconciliation") {
    const campaignPath = await safeEvidencePath(file, value.campaignManifestPath, ["campaigns", "fixtures/campaigns"]);
    const allocationPath = await safeEvidencePath(file, value.allocationPath, ["allocations", "fixtures/allocations"]);
    const campaignBytes = await readFile(campaignPath);
    const allocationBytes = await readFile(allocationPath);
    const campaign = JSON.parse(campaignBytes);
    const allocation = JSON.parse(allocationBytes);
    assertFixtureBoundary(value, value.campaignManifestPath, campaign, file, "campaign manifest");
    assertFixtureBoundary(value, value.allocationPath, allocation, file, "allocation");
    assert(digest(campaignBytes) === value.campaignManifestSha256, `${file}: campaign manifest SHA-256 mismatch`);
    assert(digest(allocationBytes) === value.allocationSha256, `${file}: allocation SHA-256 mismatch`);
    assert(campaign.campaignId === value.campaignId && allocation.campaignId === value.campaignId, `${file}: referenced campaign identity mismatch`);
    assert(campaign.cluster === value.cluster && allocation.cluster === value.cluster, `${file}: referenced cluster mismatch`);
    assert(campaign.budget === value.budget && allocation.total === value.budget, `${file}: referenced budget mismatch`);
    assert(campaign.status === "RECONCILED", `${file}: reconciliation requires a RECONCILED campaign manifest`);
    const budget = BigInt(value.budget);
    const distributed = BigInt(value.distributed);
    const unclaimed = BigInt(value.unclaimed);
    assert(budget === distributed + unclaimed, `${file}: budget must equal distributed plus unclaimed`);
    if (value.status === "COMPLETE") assert(unclaimed === 0n, `${file}: COMPLETE reconciliation may not retain an unclaimed balance`);
    if (value.status === "EXPIRED_WITH_UNCLAIMED") assert(unclaimed > 0n, `${file}: expired reconciliation must retain an unclaimed balance`);
    assert(value.transactions.reduce((sum, transaction) => sum + BigInt(transaction.amount), 0n) === distributed, `${file}: transaction totals do not reproduce distributed amount`);
    assert(new Set(value.transactions.map(({ signature }) => signature)).size === value.transactions.length, `${file}: duplicate transaction signature`);
    value.transactions.forEach(({ signature }, index) => assertSignature(signature, file, `transactions[${index}].signature`));
    const publishedTransactions = new Map([...records.values()].filter((candidate) => candidate.value.recordType === "transaction" && candidate.value.campaignId === value.campaignId && candidate.value.status === "EXECUTED").map((candidate) => [candidate.value.signature, candidate.value]));
    value.transactions.forEach(({ finalizedSlot, signature }) => {
      const transaction = publishedTransactions.get(signature);
      assert(transaction, `${file}: reconciliation signature lacks an executed transaction record`);
      assert(transaction.finalizedSlot === finalizedSlot, `${file}: reconciliation finalized slot differs from its transaction record`);
    });
  }
}

const transactionSequences = new Set();
const executedSignatures = new Set();
for (const { file, value } of records.values()) {
  if (value.recordType === "transaction") {
    const sequenceKey = `${value.campaignId}:${value.sequence}`;
    assert(!transactionSequences.has(sequenceKey), `${file}: duplicate campaign transaction sequence ${sequenceKey}`);
    transactionSequences.add(sequenceKey);
    if (value.signature) {
      assert(!executedSignatures.has(value.signature), `${file}: duplicate executed transaction signature`);
      executedSignatures.add(value.signature);
    }
  }
  if (value.recordType === "campaign" && value.status === "RECONCILED") {
    assert([...records.values()].some((candidate) => candidate.value.recordType === "reconciliation" && candidate.value.campaignId === value.campaignId && candidate.value.cluster === value.cluster), `${file}: RECONCILED campaign lacks a reconciliation record`);
  }
}

if (!format) console.log(`Validated ${schemaFiles.length} schemas and ${records.size} canonical Solana evidence records with base58, allocation, hash, privacy, deployment, and reconciliation checks.`);
