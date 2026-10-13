import type { Report, PolicyOptions, Severity } from './core.js';
export * from './core.js';
export type IocType = 'url' | 'domain' | 'ipv4' | 'ipv6' | 'email' | 'md5' | 'sha1' | 'sha256' | 'sha512' | 'cve' | 'attack' | 'btc' | 'eth' | 'xmr' | 'registry' | 'filename';
export interface Ioc { type: IocType; value: string; line: number; defanged: boolean; context: string; file?: string; class?: string; host?: string; watchlist?: string; }
export interface ExtractOptions { types?: (IocType | 'hash' | 'ip' | 'wallet')[]; refang?: boolean; includePrivate?: boolean; benignDomains?: string[]; file?: string; fileNameDomains?: boolean; }
export interface WatchEntry { value: string; label?: string; }
export interface ScanOptions extends ExtractOptions, PolicyOptions { watchlist?: string | WatchEntry[]; binaryStrings?: boolean; }
export interface AggregatedIoc { type: IocType; value: string; defanged: string; count: number; sources: string[]; class?: string; watchlist?: string; }
export interface IocReport extends Report { iocs: AggregatedIoc[]; watchlistEntries: number; }
export declare const TYPES: IocType[];
export declare const VERSION: string;
export declare const DEFAULT_BENIGN: string[];
export declare const RULES: Record<string, { severity: Severity; title: string; group: string }>;
export declare function extract(text: string, opts?: ExtractOptions): Ioc[];
export declare function refang(text: string): string;
export declare function defang(value: string): string;
export declare function ipv4Class(ip: string): string;
export declare function ipv6Class(ip: string): string;
export declare function btcValid(address: string): boolean;
export declare function strings(buf: Uint8Array, min?: number): string;
export declare function parseWatchlist(text: string): WatchEntry[];
export declare function scan(inputs: (string | { name: string; text: string })[], opts?: ScanOptions): IocReport;
export declare function formatCsv(report: IocReport, opts?: { defanged?: boolean }): string;
export declare function formatList(report: IocReport, opts?: { defanged?: boolean }): string;
export declare function formatStix(report: IocReport, opts?: { name?: string; now?: string | Date }): string;
export declare function stixPattern(ioc: { type: IocType; value: string }): string | null;
