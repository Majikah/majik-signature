/**
 * image-utils.ts — Cross-platform image pixel I/O
 *
 * Handles the messy job of getting RGBA pixel data in and out of images,
 * across browser (Canvas API) and Node.js (sharp or canvas package) contexts.
 *
 * All functions accept/return Blob in browser and Buffer/Blob in Node.
 *
 * Minimum image dimensions we enforce: 600×600 px.
 * Smaller images are padded with white before embedding.
 */

export const MIN_DIMENSION = 640;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ImagePixels {
  pixels: Uint8ClampedArray;
  width: number;
  height: number;
}

export interface ImageEncodeOptions {
  mimeType?: "image/png" | "image/jpeg" | "image/webp";
  quality?: number; // 0-1 for JPEG/WebP, default 0.92
}

// ─── Browser implementation ───────────────────────────────────────────────────

/**
 * Decode an image Blob to RGBA pixel data using browser Canvas API.
 *
 * @param blob  Any image format the browser supports (JPEG, PNG, WebP, GIF, etc.)
 * @returns     RGBA pixels, width, height
 */
export async function decodeImage(blob: Blob): Promise<ImagePixels> {
  if (typeof createImageBitmap === "undefined") {
    throw new Error(
      "decodeImage requires a browser environment with createImageBitmap. " +
        "In Node.js, use decodeImageNode() with the sharp package.",
    );
  }

  const bitmap = await createImageBitmap(blob);
  const { width, height } = bitmap;

  const canvas = new OffscreenCanvas(width, height);
  const ctx = canvas.getContext("2d")!;
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();

  const imageData = ctx.getImageData(0, 0, width, height);
  return {
    pixels: imageData.data,
    width,
    height,
  };
}

/**
 * Encode RGBA pixel data to an image Blob using browser Canvas API.
 *
 * @param pixels  RGBA pixel data
 * @param width   Image width
 * @param height  Image height
 * @param options Encoding options
 * @returns       Image Blob
 */
export async function encodeImage(
  pixels: Uint8ClampedArray,
  width: number,
  height: number,
  options: ImageEncodeOptions = {},
): Promise<Blob> {
  if (typeof OffscreenCanvas === "undefined") {
    throw new Error(
      "encodeImage requires a browser environment with OffscreenCanvas. " +
        "In Node.js, use encodeImageNode() with the sharp package.",
    );
  }

  const mimeType = options.mimeType ?? "image/png";
  const quality = options.quality ?? 0.92;

  const canvas = new OffscreenCanvas(width, height);
  const ctx = canvas.getContext("2d")!;
  // ImageData's data-first overload requires Uint8ClampedArray<ArrayBuffer>
  // strictly — no SharedArrayBuffer, no pooled buffers with non-zero byteOffset.
  // The safest fix is to allocate a fresh Uint8ClampedArray (which always owns
  // a plain ArrayBuffer) and copy into it via set(), then construct ImageData
  // from width/height and write pixels via putImageData on the blank canvas.
  const imageData = ctx.createImageData(width, height);
  imageData.data.set(pixels);
  ctx.putImageData(imageData, 0, 0);

  return canvas.convertToBlob({ type: mimeType, quality });
}
/**
 * Pad image to minimum dimensions, centering the original content.
 * Used to ensure small signature images have enough DCT blocks.
 */
export function padToMinimum(img: ImagePixels): ImagePixels {
  const { pixels, width, height } = img;

  if (width >= MIN_DIMENSION && height >= MIN_DIMENSION) {
    return img; // already large enough
  }

  const newW = Math.max(width, MIN_DIMENSION);
  const newH = Math.max(height, MIN_DIMENSION);
  const newPixels = new Uint8ClampedArray(newW * newH * 4);

  // Fill with white
  for (let i = 0; i < newPixels.length; i += 4) {
    newPixels[i] = 255; // R
    newPixels[i + 1] = 255; // G
    newPixels[i + 2] = 255; // B
    newPixels[i + 3] = 255; // A
  }

  // Copy original image, centered
  const offsetX = Math.floor((newW - width) / 2);
  const offsetY = Math.floor((newH - height) / 2);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const srcIdx = (y * width + x) * 4;
      const dstIdx = ((offsetY + y) * newW + (offsetX + x)) * 4;
      newPixels[dstIdx] = pixels[srcIdx];
      newPixels[dstIdx + 1] = pixels[srcIdx + 1];
      newPixels[dstIdx + 2] = pixels[srcIdx + 2];
      newPixels[dstIdx + 3] = pixels[srcIdx + 3];
    }
  }

  return { pixels: newPixels, width: newW, height: newH };
}

/**
 * Check if the runtime environment is a browser with Canvas API.
 */
export function hasBrowserCanvas(): boolean {
  return (
    typeof createImageBitmap !== "undefined" &&
    typeof OffscreenCanvas !== "undefined"
  );
}
