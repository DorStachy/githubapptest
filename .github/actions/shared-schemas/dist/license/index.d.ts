export type LicenseCategory = 'permissive' | 'weak_copyleft' | 'strong_copyleft' | 'non_permissive' | 'unknown' | 'unlicensed';
export type LicenseConfidence = 'HIGH' | 'MEDIUM' | 'LOW';
export interface LicenseEvidence {
    filePath: string;
    matchedSpdx: string;
    matchScore: number;
    method: 'declared_metadata' | 'file_content_match' | 'classifier' | 'fallback';
}
export interface LicenseFact {
    declaredSpdx: string | null;
    detectedSpdx: string[];
    effectiveSpdx: string | null;
    confidence: LicenseConfidence;
    category: LicenseCategory;
    evidence: LicenseEvidence[];
}
export type LicenseIssueType = 'BANNED' | 'NO_LICENSE' | 'UNKNOWN' | 'STRONG_COPYLEFT' | 'AMBIGUOUS';
export type LicenseIssueRisk = 'critical' | 'high' | 'medium' | 'low';
export interface LicenseIssueRow {
    id: string;
    package: string;
    version: string;
    ecosystem: string;
    license: string | null;
    risk: LicenseIssueRisk;
    issueType: LicenseIssueType;
    reason: string;
    projectsCount: number;
    endpointsCount: number;
}
