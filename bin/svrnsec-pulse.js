#!/usr/bin/env node
/**
 * svrnsec-pulse CLI
 * Usage: npx svrnsec-pulse <command> [options]
 */
import { run } from '../src/cli/runner.js';
run(process.argv.slice(2));
