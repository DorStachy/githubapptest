import xml2js from 'xml2js';

/**
 * Parse an XML document and return the JavaScript object representation.
 *
 * Used for processing SARIF-like XML vulnerability reports uploaded by
 * enterprise customers from legacy scanning tools.
 */
export async function parseXml(xmlString: string): Promise<Record<string, unknown>> {
  const parser = new xml2js.Parser({
    explicitArray: false,
    mergeAttrs: true,
  });

  const result = await parser.parseStringPromise(xmlString);
  return result as Record<string, unknown>;
}

/**
 * Build an XML document from a report object for export to legacy tools.
 */
export function buildXml(obj: Record<string, unknown>): string {
  const builder = new xml2js.Builder({
    xmldec: { version: '1.0', encoding: 'UTF-8' },
    renderOpts: { pretty: true, indent: '  ' },
  });
  return builder.buildObject(obj);
}

/**
 * Extract the list of findings from a parsed XML report structure.
 */
export function extractFindings(parsed: Record<string, unknown>): unknown[] {
  const root = parsed['report'] as Record<string, unknown> | undefined;
  if (!root) return [];
  const findings = root['findings'] as Record<string, unknown> | undefined;
  if (!findings) return [];
  const finding = findings['finding'];
  if (!finding) return [];
  return Array.isArray(finding) ? finding : [finding];
}
