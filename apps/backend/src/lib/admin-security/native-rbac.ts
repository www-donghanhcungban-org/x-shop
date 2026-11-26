import type { MedusaNextFunction, MedusaRequest, MedusaResponse } from "@medusajs/framework/http";
import { sendProblem } from "../http/problem";

/**
 * Route RBAC native `/rbac/*` của Medusa (từ 2.22.3, chuyển từ `/admin/rbac/*`): nằm NGOÀI `/admin` nên cổng
 * `adminSecurityGuard` không phủ; lõi chỉ đòi actor `user` đã đăng nhập (`http.rbacActorTypes`) — user chưa có vai trò
 * nào của dự án cũng tới được handler tạo/sửa vai trò, gán policy. Dự án không dùng RBAC native (Enterprise,
 * `MEDUSA_FF_RBAC`): ma trận vai trò ở `src/modules/rbac` (khoá `xRbac`) là nguồn duy nhất, nên đóng TOÀN BỘ `/rbac/*` với
 * mọi actor và mọi method, kể cả owner. Dashboard chỉ gọi `/rbac/*` khi `GET /admin/modules` có khoá `rbac` — không có ở
 * dự án này (rbac.spec.ts kiểm cả hai).
 */
export const NATIVE_RBAC_PREFIX = "/rbac";

export const isNativeRbacPath = (path: string) =>
  path === NATIVE_RBAC_PREFIX || path.startsWith(`${NATIVE_RBAC_PREFIX}/`);

export function blockNativeRbac(_req: MedusaRequest, res: MedusaResponse, _next: MedusaNextFunction): void {
  sendProblem(res, 403, "FORBIDDEN", "Bạn không có quyền thực hiện thao tác này", [], {
    reason: "NATIVE_RBAC_DISABLED",
  });
}
