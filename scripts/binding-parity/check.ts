#!/usr/bin/env -S npx tsx
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCheck } from "./check-core.js";

const here = dirname(fileURLToPath(import.meta.url));
process.exit(runCheck(join(here, "..", "..")));
