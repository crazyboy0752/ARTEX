"use client";

import * as React from "react";

import { toast } from "sonner";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// 出口探测结果的统一形状（与后端 proxyProbeResult 对齐）。
export interface ProxyEgressResult {
  ok: boolean;
  reachable: boolean;
  egress_ip: string;
  direct_ip: string;
  error?: string;
  elapsed_ms: number;
}

// ProxyEgressStatus 显示「这条出口代理现在是否真的生效」：实拨一次，对比经代理
// 观察到的出口 IP 与本机直连对照。仅端口可达不等于生效——半死的 ssh -D 隧道能过
// TCP 检查却过不了请求，因此按真实出网判定；出口 IP 与直连相同视为未生效。
//
// 同一组件服务于三条独立出网路径（全局代理 / 网络搜索代理 / 每条 LLM 配置的代理），
// 因为它们各有自己的 proxy 字段，是否生效互不影响。
export function ProxyEgressStatus({
  proxy,
  draftProxy,
  auto = true,
  revision = 0,
  onResult,
  className,
}: {
  proxy: string; // 要探测的代理值（取已保存配置；空=探测直连出口）
  draftProxy?: string; // 表单当前值；与 proxy 不同则提示「有未保存修改」
  auto?: boolean; // 挂载后自动探测一次
  revision?: number; // 递增即触发重新探测（如保存成功后）
  onResult?: (r: ProxyEgressResult | null) => void;
  className?: string;
}) {
  const [result, setResult] = React.useState<ProxyEgressResult | null>(null);
  const [probing, setProbing] = React.useState(false);

  const run = React.useCallback(
    (notify: boolean) => {
      setProbing(true);
      setResult(null);
      onResult?.(null);
      api
        .testProxyEgress(proxy.trim())
        .then((r) => {
          setResult(r);
          onResult?.(r);
          if (!notify) return;
          if (r.ok) {
            toast.success(`${proxy.trim() ? "代理生效" : "直连可用"} · 出口 IP ${r.egress_ip}`);
          } else if (r.error) {
            toast.error(r.error);
          }
        })
        .catch((e) => {
          const message = (e as Error).message;
          const failed: ProxyEgressResult = {
            ok: false,
            reachable: false,
            egress_ip: "",
            direct_ip: "",
            error: message,
            elapsed_ms: 0,
          };
          setResult(failed);
          onResult?.(failed);
          if (notify) toast.error("探测失败：" + message);
        })
        .finally(() => setProbing(false));
    },
    // proxy 变化即代表探测目标变了；onResult 由调用方用 useCallback 固定。
    [proxy, onResult],
  );

  // 自动探测：首次挂载、探测目标（已保存值）变化、以及 revision 递增（保存成功后
  // 值未变也重测）时触发。探测目标始终是已保存配置，避免把未保存草稿误报为当前状态。
  React.useEffect(() => {
    if (!auto) return;
    run(false);
    // run 已随 proxy 变化重建，这里只需声明触发条件。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, revision, proxy]);

  const dirty = draftProxy !== undefined && proxy.trim() !== draftProxy.trim();

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => run(true)}
          disabled={probing}
          className="border-border hover:bg-accent rounded-md border px-2.5 py-1 text-xs disabled:opacity-50"
        >
          {probing ? "探测中…" : "重新检测"}
        </button>
        {result && !probing && (
          <span
            className={cn(
              "text-xs",
              result.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive",
            )}
          >
            {result.ok ? (
              <>
                生效 · 出口 IP <code>{result.egress_ip}</code>
                {result.direct_ip && (
                  <>
                    {" "}
                    （直连对照 <code>{result.direct_ip}</code>）
                  </>
                )}
                <span className="text-muted-foreground"> · {result.elapsed_ms}ms</span>
              </>
            ) : (
              <>
                未生效
                {result.reachable ? " · 端点可达但出网失败" : " · 端点不可达"}
                {result.error ? ` · ${result.error}` : ""}
              </>
            )}
          </span>
        )}
        {probing && <span className="text-muted-foreground text-xs">正在检测实际出口…</span>}
      </div>
      {dirty && (
        <p className="text-muted-foreground text-xs">
          表单有未保存修改，上方状态仍对应<b>已保存</b>配置。
        </p>
      )}
    </div>
  );
}
