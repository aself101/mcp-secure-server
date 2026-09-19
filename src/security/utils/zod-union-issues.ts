type Issue = Record<string, unknown>;

function isIssue(value: unknown): value is Issue {
  return typeof value === 'object' && value !== null &&
    typeof (value as Issue).code === 'string' &&
    Array.isArray((value as Issue).path) &&
    typeof (value as Issue).message === 'string';
}

/**
 * Expand the most specific union branch, matching the policy-config formatter.
 * Zod 3 branch paths are absolute; Zod 4 branch paths are relative to the union.
 * Equal-depth alternatives stay represented by the union message: guessing a
 * branch there would incorrectly prescribe one of several valid input shapes.
 */
export function expandUnionIssues(issues: Issue[], basePath: unknown[] = [], depth = 0): Issue[] {
  return issues.flatMap((issue) => {
    const path = [...basePath, ...(Array.isArray(issue.path) ? issue.path : [])];
    const parent = { ...issue, path };
    // Malformed/deep diagnostic payloads retain the original union diagnostic.
    if (issue.code !== 'invalid_union' || depth >= 20) return [parent];
    const zod4 = Array.isArray(issue.errors);
    const rawBranches = zod4 ? issue.errors : Array.isArray(issue.unionErrors)
      ? issue.unionErrors.map((branch: unknown) =>
        typeof branch === 'object' && branch !== null ? (branch as Issue).issues : undefined)
      : undefined;
    if (!Array.isArray(rawBranches) || rawBranches.length === 0 ||
      !rawBranches.every(branch => Array.isArray(branch) && branch.length > 0 && branch.every(isIssue))) {
      return [parent];
    }
    const branches = (rawBranches as Issue[][]).map(branch =>
      expandUnionIssues(branch, zod4 ? path : [], depth + 1));
    const depths = branches.map(branch => branch.reduce((max, child) =>
      Math.max(max, (child.path as unknown[]).length), 0));
    const deepest = Math.max(...depths);
    const best = branches.filter((_, index) => depths[index] === deepest);
    const selected = best[0];
    return best.length === 1 && selected && deepest > path.length ? selected : [parent];
  });
}
