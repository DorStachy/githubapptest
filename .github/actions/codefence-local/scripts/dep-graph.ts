export interface DependencyGraph {
  roots: string[];
  childrenByNode: Map<string, string[]>;
}

function normalizeNodeName(name: string): string {
  return name.trim();
}

export function buildGraphFromPackageLock(lockfile: any): DependencyGraph {
  const childrenByNode = new Map<string, string[]>();
  const roots: string[] = [];

  if (lockfile?.dependencies && typeof lockfile.dependencies === 'object') {
    for (const [name, meta] of Object.entries(lockfile.dependencies as Record<string, any>)) {
      const root = normalizeNodeName(name);
      roots.push(root);
      hydrateNode(root, meta, childrenByNode);
    }
  }

  if (lockfile?.packages && typeof lockfile.packages === 'object') {
    for (const [pkgPath, meta] of Object.entries(lockfile.packages as Record<string, any>)) {
      if (!pkgPath || pkgPath === '') {
        continue;
      }
      const name = pkgPath.startsWith('node_modules/')
        ? pkgPath.slice('node_modules/'.length)
        : pkgPath;
      const deps = Object.keys((meta as any)?.dependencies || {});
      if (!childrenByNode.has(name)) {
        childrenByNode.set(name, deps);
      }
    }

    if (roots.length === 0) {
      for (const [pkgPath] of Object.entries(lockfile.packages as Record<string, any>)) {
        if (pkgPath.startsWith('node_modules/')) {
          roots.push(pkgPath.slice('node_modules/'.length));
        }
      }
    }
  }

  return {
    roots: Array.from(new Set(roots)),
    childrenByNode,
  };
}

function hydrateNode(
  node: string,
  meta: any,
  childrenByNode: Map<string, string[]>,
): void {
  const deps = Object.keys(meta?.dependencies || {});
  childrenByNode.set(node, deps);

  for (const [child, childMeta] of Object.entries(meta?.dependencies || {})) {
    if (!childrenByNode.has(child)) {
      hydrateNode(child, childMeta, childrenByNode);
    }
  }
}

export function introducedByChain(graph: DependencyGraph, target: string): string[] {
  const parents = new Map<string, string[]>();

  for (const [node, children] of graph.childrenByNode.entries()) {
    for (const child of children) {
      const key = normalizeNodeName(child);
      const bucket = parents.get(key) || [];
      bucket.push(node);
      parents.set(key, bucket);
    }
  }

  const queue: Array<{ node: string; chain: string[] }> = [{ node: target, chain: [target] }];
  const seen = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }

    if (graph.roots.includes(current.node)) {
      return current.chain.slice().reverse();
    }

    const currentParents = parents.get(current.node) || [];
    for (const parent of currentParents) {
      if (seen.has(parent)) {
        continue;
      }
      seen.add(parent);
      queue.push({ node: parent, chain: [...current.chain, parent] });
    }
  }

  return [target];
}

export function maxDepthFromRoots(graph: DependencyGraph, node: string): number {
  const queue: Array<{ name: string; depth: number }> = graph.roots.map((root) => ({
    name: root,
    depth: 1,
  }));
  const seen = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      continue;
    }

    if (current.name === node) {
      return current.depth;
    }

    if (seen.has(current.name)) {
      continue;
    }
    seen.add(current.name);

    const children = graph.childrenByNode.get(current.name) || [];
    for (const child of children) {
      queue.push({ name: child, depth: current.depth + 1 });
    }
  }

  return -1;
}
