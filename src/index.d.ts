export type Finding = {
  level: 'error' | 'warn'
  kind: 'value' | 'pieces' | 'shape' | 'name' | 'sourcemap' | 'history-value' | 'history-shape' | 'history-env'
  file: string
  line: number
  what: string
  sample?: string
  shapeId?: string
  /** History findings: the short commit and its date. */
  commit?: string
  date?: string
  /** Set by verifyFindings: did the provider accept the key? */
  verified?: 'live' | 'dead' | 'unknown'
}
export type Result = { findings: Finding[]; files: number; dirs?: string[]; secretsChecked?: number; commits?: number; verified?: boolean }
export type Secret = { name: string; value: string; source: string; line: number; ok: boolean }

export declare function scanProject(root: string, opts?: { dirs?: string[]; allow?: string[]; env?: Record<string, string | undefined>; envFiles?: string[]; deep?: boolean }): Result
export declare function scanUrl(url: string, secrets?: Secret[], opts?: { deep?: boolean }): Promise<Result>
export declare function scanHistory(root: string, secrets?: Secret[]): Promise<{ findings: Finding[]; commits: number } | null>
export declare function verifyKey(shapeId: string, key: string, fetch?: typeof globalThis.fetch): Promise<'live' | 'dead' | 'unknown'>
export declare function verifyFindings(findings: Finding[], fetch?: typeof globalThis.fetch): Promise<Finding[]>
export declare const VERIFIABLE: string[]
export declare function scanText(text: string, secrets: Secret[], opts?: { deep?: boolean }): Omit<Finding, 'file'>[]
export declare function findOutputDirs(root: string): string[]
export declare function loadSecrets(dir: string, opts?: { env?: Record<string, string | undefined>; files?: string[]; allow?: string[] }): { secrets: Secret[]; all: Secret[] }
export declare function report(result: Result): string
export declare function mask(value: string): string
export declare const PUBLIC_PREFIXES: string[]
