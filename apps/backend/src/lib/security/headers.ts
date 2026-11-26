import type { MedusaNextFunction, MedusaRequest, MedusaResponse } from "@medusajs/framework/http";
import { getHttpSecurityConfig } from "./config";

/**
 * Header bảo mật cho phản hồi API JSON của backend (SEC05): `/store`, `/admin` (API), `/auth`, `/x`. Không áp cho giao
 * diện Admin native (`/app`) — trang đó có CSP riêng của Medusa/Vite.
 *
 * CSP của API: không tài nguyên nào được nạp/thực thi, không được nhúng khung — phản hồi JSON bị mở thẳng trên trình duyệt
 * cũng không chạy được gì. HSTS chỉ ở production (trình duyệt bỏ qua HSTS trên http, nhưng không ghim localhost dev).
 */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
export const HSTS_VALUE = "max-age=31536000; includeSubDomains";

export function apiSecurityHeaders(production: boolean): Record<string, string> {
  return {
    "Content-Security-Policy": API_CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    ...(production && { "Strict-Transport-Security": HSTS_VALUE }),
  };
}

export function securityHeaders(_req: MedusaRequest, res: MedusaResponse, next: MedusaNextFunction) {
  // GHI ĐÈ, không "chỉ đặt khi chưa có": từ Medusa 2.22.x lõi đặt sẵn cho MỌI request `Content-Security-Policy:
  // frame-ancestors 'self'` + `X-Frame-Options: SAMEORIGIN` (framework/dist/http/express-loader.js `applySecurityHeaders`,
  // chạy trước middleware dự án) — giữ giá trị đó là hạ CSP chặt của API xuống. Handler route vẫn ghi đè được sau bước này.
  for (const [k, v] of Object.entries(apiSecurityHeaders(getHttpSecurityConfig().production)))
    res.setHeader(k, v);
  // Không quảng cáo framework/phiên bản (Express đặt mặc định).
  res.removeHeader("X-Powered-By");
  next();
}
