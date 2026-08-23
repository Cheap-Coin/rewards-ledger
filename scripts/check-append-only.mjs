import { execFileSync } from "node:child_process";

const arguments_ = process.argv.slice(2);
if (arguments_[0] === "--") arguments_.shift();
const [base, ...unexpected] = arguments_;
if (!base || unexpected.length || !/^[0-9a-f]{40}$/i.test(base)) throw new Error("Pass one trusted 40-character base commit SHA");

const protectedRoots = ["allocations", "campaigns", "deployments", "notices", "reconciliations", "rules", "schemas", "transactions"];
const hadSolanaV1Baseline = (() => {
  try {
    execFileSync("git", ["cat-file", "-e", `${base}:schemas/common-v1.schema.json`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

// The first Solana V1 publication intentionally replaces the retired ledger.
// There was no Solana evidence contract to preserve before common-v1 existed.
// Once that schema is in the trusted base, the normal append-only rule below is
// permanent and this branch is no longer reachable.
if (!hadSolanaV1Baseline) {
  execFileSync("node", ["scripts/validate-ledger.mjs"], { stdio: "inherit" });
  console.log("Solana V1 baseline bootstrap passed; append-only enforcement begins after this baseline is merged.");
  process.exit(0);
}

const output = execFileSync("git", ["diff", "--name-status", "--find-renames", base, "HEAD", "--", ...protectedRoots], { encoding: "utf8" }).trim();
const violations = [];
for (const line of output ? output.split(/\r?\n/) : []) {
  const [status, ...paths] = line.split("\t");
  if (status === "A") continue;
  if (paths.every((path) => /(^|\/)README\.md$/.test(path))) continue;
  violations.push(line);
}

if (violations.length) {
  console.error("Published schemas, rules, and evidence are append-only; publish a superseding version:");
  violations.forEach((violation) => console.error(`  ${violation}`));
  process.exitCode = 1;
} else {
  console.log("Append-only evidence check passed.");
}
