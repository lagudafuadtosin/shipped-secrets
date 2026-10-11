export type Finding = { level: 'error' | 'warn'; kind: 'value' | 'shape' | 'name' | 'sourcemap'; file: string; line: number; what: string; sample?: string }
export type Result = { findings: Finding[]; files: number; dirs?: string[]; secretsChecked?: number }
export type Secret = { name: string; value: string; source: string; line: number; ok: boolean }

export declare function scanProject(root: string, opts?: { dirs?: string[]; allow?: string[]; env?: Record<string, string | undefined>; envFiles?: string[] }): Result
export declare function scanUrl(url: string, secrets?: Secret[]): Promise<Result>
export declare function scanText(text: string, secrets: Secret[]): Omit<Finding, 'file'>[]
export declare function findOutputDirs(root: string): string[]
export declare function loadSecrets(dir: string, opts?: { env?: Record<string, string | undefined>; files?: string[]; allow?: string[] }): { secrets: Secret[]; all: Secret[] }
export declare function report(result: Result): string
export declare function mask(value: string): string
export declare const PUBLIC_PREFIXES: string[]
