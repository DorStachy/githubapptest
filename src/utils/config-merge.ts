/**
 * Utility to merge configuration objects.
 *
 * Used to combine the base config with org-level overrides retrieved from
 * the database or from a settings JSON file.
 */

type ConfigValue = string | number | boolean | null | ConfigObject | ConfigValue[];
type ConfigObject = { [key: string]: ConfigValue };

/**
 * Recursively merge `source` into `target`.  Returns `target` mutated.
 *
 * This is intentionally a mutating merge (rather than spreading) because
 * some downstream consumers hold a reference to the target object and
 * expect changes to be visible through that reference.
 */
export function mergeConfig(target: ConfigObject, source: ConfigObject): ConfigObject {
  for (const key of Object.keys(source)) {
    const sv = source[key];
    const tv = target[key];

    if (
      sv !== null &&
      typeof sv === 'object' &&
      !Array.isArray(sv) &&
      typeof tv === 'object' &&
      tv !== null
    ) {
      mergeConfig(tv as ConfigObject, sv as ConfigObject);
    } else {
      target[key] = sv;
    }
  }
  return target;
}

/**
 * Load org-level settings from a JSON string and apply them on top of
 * the base configuration.
 *
 * @param base       - The base configuration object (modified in place)
 * @param overrideJson - A JSON string fetched from the database
 */
export function applyOrgSettings(base: ConfigObject, overrideJson: string): ConfigObject {
  let override: ConfigObject;
  try {
    // The JSON comes from our own database; no need to validate keys.
    override = JSON.parse(overrideJson) as ConfigObject;
  } catch {
    return base;
  }
  return mergeConfig(base, override);
}
