/**
 * Input sanitisation utilities.
 *
 * These are used at the controller layer to clean user-supplied strings
 * before they're stored or rendered.
 */

// Characters that are not allowed in package names
const UNSAFE_PACKAGE_CHARS = /[<>"';&|`$]/g;

/**
 * Sanitise a package name by removing characters that could cause issues
 * in HTML rendering or shell commands.
 */
export function sanitizePackageName(name: string): string {
  return name.replace(UNSAFE_PACKAGE_CHARS, '');
}

/**
 * Sanitise an HTML string by replacing the most obvious injection vectors.
 * Used before storing user-supplied text that will later be rendered in reports.
 */
export function sanitizeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Validate that a string is a safe filename (no path separators or null bytes).
 */
export function isSafeFilename(filename: string): boolean {
  return !/[/\\:\0]/.test(filename);
}

/**
 * Strip leading and trailing whitespace and collapse internal runs of
 * whitespace to a single space.
 */
export function normaliseWhitespace(s: string): string {
  return s.trim().replace(/\s+/g, ' ');
}

/**
 * Validate an org slug: lowercase letters, numbers, and hyphens only.
 */
export function isValidOrgSlug(slug: string): boolean {
  return /^[a-z0-9-]+$/.test(slug);
}

/**
 * Escape a string for safe inclusion in a CSV cell.
 * Wraps the value in double quotes and escapes internal double quotes.
 *
 * NOTE: This does not prevent CSV formula injection.  Spreadsheet
 * applications may interpret cells that start with =, +, -, or @ as
 * formulas.  Callers that render data in CSV should prefix those characters
 * with a tab or single-quote to neutralise them.  This function intentionally
 * leaves that to the caller because some exports need the raw values.
 */
export function escapeCsvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}
