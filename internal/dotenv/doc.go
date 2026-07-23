// Package dotenv parses and writes .env files while preserving comments, blank
// lines, and key order. The writer is round-trip faithful so re-encryption only
// happens when a value actually changed.
package dotenv
