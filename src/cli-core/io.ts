/**
 * src/cli/io.ts
 *
 * Node.js filesystem helpers for the Majik Signature CLI.
 */

import {
  access,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";

import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

import { fileURLToPath } from "node:url";

import type { FolderFile } from "./types";

const MIME_TYPES: Record<string, string> = {
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".csv": "text/csv",
  ".json": "application/json",
  ".xml": "application/xml",
  ".html": "text/html",
  ".htm": "text/html",

  ".pdf": "application/pdf",

  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",

  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".flac": "audio/flac",

  ".mp4": "video/mp4",
  ".mkv": "video/x-matroska",

  ".docx":
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx":
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",

  ".zip": "application/zip",
  ".exe": "application/vnd.microsoft.portable-executable",
  ".msi": "application/x-msi",
  ".msix": "application/msix",
  ".deb": "application/vnd.debian.binary-package",

  ".mjksig": "application/vnd.majikah.mjksig",
  ".mjksmap": "application/vnd.majikah.mjksmap",
};

const MAJIK_ARTIFACT_EXTENSIONS = new Set([".mjksig", ".mjksmap"]);

function normalizeSlashes(value: string): string {
  return value.replaceAll("\\", "/");
}

/**
 * Convert a filesystem path into the normalized relative-path convention
 * used by MajikSignatureMap.
 */
export function relativePosix(root: string, target: string): string {
  return normalizeSlashes(relative(root, target)).replace(/^\/+/, "").trim();
}

export function mimeTypeForPath(path: string): string {
  return MIME_TYPES[extname(path).toLowerCase()] ?? "application/octet-stream";
}

export function isMajikArtifact(path: string): boolean {
  return MAJIK_ARTIFACT_EXTENSIONS.has(extname(path).toLowerCase());
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDirectory(path: string): Promise<void> {
  await mkdir(path, {
    recursive: true,
  });
}

export async function readBytes(path: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(path));
}

export async function readText(path: string): Promise<string> {
  return readFile(path, "utf8");
}

export async function readBlob(path: string): Promise<Blob> {
  const bytes = await readBytes(path);

  return new Blob([bytes as BlobPart], {
    type: mimeTypeForPath(path),
  });
}

export async function readJsonFile<T = unknown>(path: string): Promise<T> {
  const text = await readText(path);

  try {
    return JSON.parse(text) as T;
  } catch (error) {
    throw new Error(
      `Invalid JSON in "${path}": ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export async function writeBytes(
  path: string,
  bytes: Uint8Array,
  overwrite: boolean,
): Promise<void> {
  if (!overwrite && (await pathExists(path))) {
    throw new Error(
      `Output already exists: "${path}". Use --overwrite to replace it.`,
    );
  }

  await ensureDirectory(dirname(path));
  await writeFile(path, bytes);
}

export async function writeBlob(
  path: string,
  blob: Blob,
  overwrite: boolean,
): Promise<void> {
  const bytes = new Uint8Array(await blob.arrayBuffer());

  await writeBytes(path, bytes, overwrite);
}

export async function writeJsonFile(
  path: string,
  value: unknown,
  overwrite: boolean,
): Promise<void> {
  const json = JSON.stringify(value, null, 2) + "\n";

  await writeText(path, json, overwrite);
}

export async function writeText(
  path: string,
  value: string,
  overwrite: boolean,
): Promise<void> {
  if (!overwrite && (await pathExists(path))) {
    throw new Error(
      `Output already exists: "${path}". Use --overwrite to replace it.`,
    );
  }

  await ensureDirectory(dirname(path));
  await writeFile(path, value, "utf8");
}

async function walkDirectory(
  root: string,
  current: string,
  output: FolderFile[],
): Promise<void> {
  const entries = await readdir(current, {
    withFileTypes: true,
  });

  for (const entry of entries) {
    const absolutePath = join(current, entry.name);

    /**
     * Do not follow symlinks. This avoids directory cycles and prevents a
     * folder signing operation from unexpectedly escaping its input tree.
     */
    if (entry.isSymbolicLink()) {
      continue;
    }

    if (entry.isDirectory()) {
      await walkDirectory(root, absolutePath, output);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    /**
     * Existing Majik Signature sidecars/manifests are artifacts, not source
     * files for a subsequent folder operation.
     */
    if (isMajikArtifact(absolutePath)) {
      continue;
    }

    const fileStat = await stat(absolutePath);

    output.push({
      absolutePath,
      relativePath: relativePosix(root, absolutePath),
      blob: await readBlob(absolutePath),
      size: fileStat.size,
      mimeType: mimeTypeForPath(absolutePath),
    });
  }
}

/**
 * Read all regular files underneath a folder into memory.
 *
 * This is intentional for MJKSMAP operations because the CLI may need both
 * the file bytes and the generated manifest/bundle during a single operation.
 */
export async function readFolderFiles(rootPath: string): Promise<FolderFile[]> {
  const root = resolve(rootPath);

  const rootStat = await stat(root);

  if (!rootStat.isDirectory()) {
    throw new Error(`Expected a directory: "${root}"`);
  }

  const result: FolderFile[] = [];

  await walkDirectory(root, root, result);

  result.sort((a, b) =>
    a.relativePath.localeCompare(b.relativePath, undefined, {
      sensitivity: "base",
    }),
  );

  return result;
}

export async function getPathKind(
  inputPath: string,
): Promise<"file" | "directory"> {
  const target = resolve(inputPath);

  let fileStat;

  try {
    fileStat = await stat(target);
  } catch {
    throw new Error(`Path does not exist: "${target}"`);
  }

  if (fileStat.isDirectory()) {
    return "directory";
  }

  if (fileStat.isFile()) {
    return "file";
  }

  throw new Error(`Unsupported filesystem object: "${target}"`);
}

export function resolveCliPath(path: string): string {
  if (isAbsolute(path)) {
    return resolve(path);
  }

  return resolve(process.cwd(), path);
}

export function outputPathForDetachedFile(inputPath: string): string {
  return `${inputPath}.mjksig`;
}

export function outputPathForMap(inputDirectory: string): string {
  return join(inputDirectory, "signatures.mjksmap");
}

export function outputPathForMapBundle(
  inputDirectory: string,
  mapPath: string,
): string {
  const directoryName = basename(inputDirectory);
  const mapName = basename(mapPath, extname(mapPath));

  return join(dirname(mapPath), `${directoryName || mapName}.mjksbundle.zip`);
}

export async function getPackageVersion(): Promise<string> {
  const currentFile = fileURLToPath(import.meta.url);

  /**
   * dist/cli/io.js
   *   ↑ ../
   * dist/cli
   *   ↑ ../
   * dist
   *   ↑ package root
   */
  const packageJsonPath = resolve(dirname(currentFile), "../../package.json");

  try {
    const packageJson = await readJsonFile<{
      version?: string;
    }>(packageJsonPath);

    return packageJson.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

export function summarizeFiles(files: FolderFile[]): {
  count: number;
  bytes: number;
} {
  return {
    count: files.length,
    bytes: files.reduce((total, file) => total + file.size, 0),
  };
}
