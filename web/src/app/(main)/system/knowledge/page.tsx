"use client";

import * as React from "react";

import { CheckCircle2Icon, CopyIcon, PencilIcon, PlusIcon, SearchIcon, TargetIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { PocCategory, PocEntry, PocOverview } from "@/lib/types";
import { cn } from "@/lib/utils";

// kind 的中文展示名（poc/exp/script/template/payload）。
const KIND_LABEL: Record<string, string> = {
  poc: "POC",
  exp: "EXP",
  script: "脚本",
  template: "模板",
  payload: "Payload",
};

// severity → 色调。nuclei 层还会带 info，status.ts 的 severity 域没有它，
// 这里自己映射：critical 实心 rose，info 归 neutral。
const SEV_TONE: Record<string, string> = {
  critical: "border-rose-600 bg-rose-600 text-white",
  high: "border-red-500/20 bg-red-500/15 text-red-600 dark:text-red-400",
  medium: "border-amber-500/20 bg-amber-500/15 text-amber-600 dark:text-amber-400",
  low: "border-slate-500/20 bg-slate-500/15 text-slate-600 dark:text-slate-400",
  info: "border-transparent bg-muted text-muted-foreground",
};

const SEV_LABEL: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};

function fmtTime(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtBytes(n: number) {
  if (n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

type Layer = "all" | "poc" | "nuclei";

// 空编辑态。id 存在 = 编辑该条；否则新建。
const emptyForm = {
  code: "",
  title: "",
  kind: "poc",
  category: "other",
  cve: "",
  component: "",
  versions: "",
  severity: "",
  language: "",
  source_url: "",
  description: "",
  usage: "",
  content: "",
  tags: "",
};

export default function KnowledgePage() {
  // ── 检索状态 ──
  const [query, setQuery] = React.useState("");
  const [layer, setLayer] = React.useState<Layer>("all");
  const [category, setCategory] = React.useState<string>(""); // "" = 全部
  const [verifiedOnly, setVerifiedOnly] = React.useState(false);

  // ── 数据 ──
  const [entries, setEntries] = React.useState<PocEntry[]>([]);
  const [categories, setCategories] = React.useState<PocCategory[]>([]);
  const [overview, setOverview] = React.useState<PocOverview | null>(null);
  const [loading, setLoading] = React.useState(false);

  // ── 选中与详情 ──
  const [selected, setSelected] = React.useState<PocEntry | null>(null);
  const [detail, setDetail] = React.useState<PocEntry | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  // ── 编辑 / 删除 ──
  const [form, setForm] = React.useState({ ...emptyForm });
  const [editingId, setEditingId] = React.useState<number | null>(null);
  const [sheetOpen, setSheetOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [pendingDelete, setPendingDelete] = React.useState<PocEntry | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  // ── 载入：归类导航 + 总览（不随筛选变化） ──
  const loadStatic = React.useCallback(() => {
    api
      .pocKbCategories()
      .then(setCategories)
      .catch(() => undefined);
    api
      .pocKbOverview()
      .then(setOverview)
      .catch(() => undefined);
  }, []);

  React.useEffect(() => {
    loadStatic();
  }, [loadStatic]);

  // ── 检索：query 防抖 300ms；layer/category/verifiedOnly 即时 ──
  const search = React.useCallback(
    async (opts: { q: string; layer: Layer; category: string; verifiedOnly: boolean }) => {
      setLoading(true);
      try {
        const list = await api.pocKbList({
          q: opts.q || undefined,
          layer: opts.layer === "all" ? undefined : opts.layer,
          category: opts.category || undefined,
          verified_only: opts.verifiedOnly || undefined,
          limit: 500,
        });
        setEntries(list);
      } catch (e) {
        toast.error(`检索失败：${(e as Error).message}`);
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  // 防抖只挂在 query 上；其余状态变化立即检索。
  React.useEffect(() => {
    const t = setTimeout(() => void search({ q: query, layer, category, verifiedOnly }), query ? 300 : 0);
    return () => clearTimeout(t);
  }, [query, layer, category, verifiedOnly, search]);

  // ── 详情：选中 code 变化时拉全文 ──
  React.useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    api
      .pocKbGet(selected.code)
      .then(setDetail)
      .catch((e) => toast.error(`读取详情失败：${(e as Error).message}`))
      .finally(() => setDetailLoading(false));
  }, [selected]);

  // ── 客户端排序（verified → hits → updated） ──
  const sorted = React.useMemo(() => {
    const arr = [...entries];
    arr.sort((a, b) => {
      if (a.verified !== b.verified) return a.verified ? -1 : 1;
      if (a.hit_count !== b.hit_count) return b.hit_count - a.hit_count;
      return (b.updated_at ?? "").localeCompare(a.updated_at ?? "");
    });
    return arr;
  }, [entries]);

  const shown = React.useMemo(() => {
    if (category) return sorted.filter((e) => e.category === category);
    return sorted;
  }, [sorted, category]);

  // ── 编辑表单 ──
  function openCreate() {
    setEditingId(null);
    setForm({ ...emptyForm });
    setSheetOpen(true);
  }

  function openEdit(p: PocEntry) {
    setEditingId(p.id);
    setForm({
      code: p.code,
      title: p.title,
      kind: p.kind,
      category: p.category,
      cve: p.cve,
      component: p.component,
      versions: p.versions,
      severity: p.severity,
      language: p.language,
      source_url: p.source_url ?? "",
      description: p.description,
      usage: p.usage,
      content: detail?.content ?? "", // 正文以已拉取的详情为准，列表行不含 content
      tags: p.tags ?? "",
    });
    setSheetOpen(true);
  }

  function setF(patch: Partial<typeof form>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  async function save() {
    if (!form.title.trim()) {
      toast.error("标题为必填项（写清是什么漏洞/组件的 POC）");
      return;
    }
    setSaving(true);
    try {
      const r = await api.pocKbSave(form);
      toast.success(r.created ? `已新增：${r.poc.code}` : `已更新：${r.poc.code}`);
      setSheetOpen(false);
      loadStatic();
      void search({ q: query, layer, category, verifiedOnly });
      setSelected(r.poc);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    const p = pendingDelete;
    if (!p) return;
    setDeleting(true);
    try {
      await api.pocKbDelete(p.code);
      toast.success(`已删除：${p.title}`);
      if (selected?.code === p.code) setSelected(null);
      loadStatic();
      void search({ q: query, layer, category, verifiedOnly });
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }

  async function registerHit() {
    const p = detail ?? selected;
    if (!p) return;
    try {
      await api.pocKbHit(p.code);
      toast.success("已登记一次复用");
      setDetail({ ...p, hit_count: p.hit_count + 1 });
      loadStatic();
      void search({ q: query, layer, category, verifiedOnly });
    } catch (e) {
      toast.error(`登记失败：${(e as Error).message}`);
    }
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      toast.success("已复制 code");
    } catch {
      toast.error("复制失败");
    }
  }

  const active = detail ?? selected;

  // ── 渲染 ──
  return (
    <div data-content-padding="false" className="flex flex-1 flex-col overflow-hidden">
      {/* ── 顶栏 ── */}
      <div className="flex items-center gap-3 border-b px-4 py-2.5 lg:px-6">
        <div className="flex flex-col gap-0.5">
          <h1 className="font-semibold text-sm leading-tight">知识库</h1>
          <p className="text-muted-foreground text-xs">POC/EXP · 全局共享 · 自建库与 nuclei 模板库两层同搜 · 14 归类</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {overview && (
            <div className="hidden items-center gap-3 text-muted-foreground text-xs sm:flex">
              <span>
                共 <span className="text-foreground tabular-nums">{overview.total}</span> 条
              </span>
              <span>
                已验证 <span className="text-foreground tabular-nums">{overview.verified}</span>
              </span>
              <span>
                复用 <span className="text-foreground tabular-nums">{overview.hits}</span> 次
              </span>
            </div>
          )}
          <Button size="sm" onClick={openCreate}>
            <PlusIcon className="size-3.5" />
            新建
          </Button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* ── 左栏：筛选 + 列表 ── */}
        <div className="flex w-80 shrink-0 flex-col border-r">
          <div className="space-y-2.5 border-b p-3">
            {/* 搜索 */}
            <div className="relative">
              <SearchIcon className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="h-8 pl-8 text-xs"
                placeholder="CVE / 组件 / 关键字"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>

            {/* 分层：全部 / 自建 / 模板 */}
            <div className="flex gap-1 rounded-md bg-muted p-0.5">
              {(
                [
                  ["all", "全部"],
                  ["poc", "自建库"],
                  ["nuclei", "模板库"],
                ] as [Layer, string][]
              ).map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  onClick={() => setLayer(val)}
                  className={cn(
                    "flex-1 rounded px-2 py-1 text-xs transition-colors",
                    layer === val
                      ? "bg-background font-medium shadow-sm"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* 只看已验证 */}
            <label htmlFor="poc-verified-only" className="flex cursor-pointer items-center gap-2 text-xs">
              <Checkbox id="poc-verified-only" checked={verifiedOnly} onCheckedChange={(v) => setVerifiedOnly(!!v)} />
              只看已实测验证
            </label>

            {/* 归类导航 */}
            <div className="space-y-0.5">
              <button
                type="button"
                onClick={() => setCategory("")}
                className={cn(
                  "flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs",
                  category === "" ? "bg-accent font-medium text-accent-foreground" : "hover:bg-muted",
                )}
              >
                <span className="min-w-0 flex-1 truncate">全部归类</span>
                <span className="text-muted-foreground tabular-nums">{entries.length}</span>
              </button>
              {categories.map((c) => (
                <button
                  key={c.code}
                  type="button"
                  title={c.hint}
                  onClick={() => setCategory(category === c.code ? "" : c.code)}
                  className={cn(
                    "flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs",
                    category === c.code ? "bg-accent font-medium text-accent-foreground" : "hover:bg-muted",
                    c.count === 0 && "text-muted-foreground/60",
                  )}
                >
                  <span className="min-w-0 flex-1 truncate">{c.name}</span>
                  <span className="text-muted-foreground tabular-nums">{c.count}</span>
                </button>
              ))}
            </div>
          </div>

          {/* 条目列表 */}
          <ScrollArea className="[&>[data-slot=scroll-area-viewport]>div]:!block flex-1">
            <div className="space-y-1 p-2">
              {/* 选中归类时先给中文释义：这条归类收的是什么漏洞 */}
              {category && (
                <p className="px-1 pb-1 text-[11px] text-muted-foreground">
                  {categories.find((c) => c.code === category)?.hint ??
                    categories.find((c) => c.code === category)?.name}
                </p>
              )}
              {shown.map((p) => {
                const isSel = selected?.code === p.code;
                return (
                  <button
                    key={p.code}
                    type="button"
                    onClick={() => setSelected(p)}
                    className={cn(
                      "w-full rounded-md border px-2.5 py-2 text-left transition-colors",
                      isSel ? "border-accent bg-accent text-accent-foreground" : "hover:bg-muted",
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <span className="min-w-0 flex-1 truncate font-medium text-xs" title={p.title}>
                        {p.title}
                      </span>
                      {p.verified && <CheckCircle2Icon className="size-3.5 shrink-0 text-emerald-500" />}
                    </div>
                    {/* 中文归类 + 严重度：一眼看出收的是什么漏洞、多严重 */}
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        {p.category_name}
                      </span>
                      {p.severity && (
                        <span
                          className={cn(
                            "rounded border px-1.5 py-0.5 text-[10px] font-medium",
                            SEV_TONE[p.severity] ?? SEV_TONE.info,
                          )}
                        >
                          {SEV_LABEL[p.severity] ?? p.severity}
                        </span>
                      )}
                      {p.cve && <span className="text-[10px] text-blue-500">{p.cve.split(",")[0]}</span>}
                      {p.hit_count > 0 && (
                        <span className="ml-auto shrink-0 text-[10px] text-muted-foreground tabular-nums">
                          ×{p.hit_count}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1">
                      <code
                        className="min-w-0 flex-1 truncate font-mono text-[10px] text-muted-foreground/70"
                        title={p.code}
                      >
                        {p.code}
                      </code>
                    </div>
                  </button>
                );
              })}

              {!loading && shown.length === 0 && (
                <p className="px-2 py-6 text-center text-muted-foreground text-xs">没有匹配的条目</p>
              )}
              {loading && <p className="px-2 py-6 text-center text-muted-foreground text-xs">检索中…</p>}
            </div>
          </ScrollArea>
        </div>

        {/* ── 右侧：详情 / 总览 ── */}
        <div className="flex flex-1 flex-col overflow-auto p-4 lg:p-6">
          {!active && (
            <div className="mx-auto w-full max-w-3xl space-y-6">
              {/* 总览指标 */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  { label: "知识条数", value: overview?.total, hint: "跨靶标全局共享" },
                  { label: "已验证", value: overview?.verified, hint: "实测跑通过" },
                  {
                    label: "自建 / 模板",
                    value: overview != null ? `${overview.poc_layer} / ${overview.nuclei_layer}` : undefined,
                    hint: "两层一体",
                  },
                  { label: "累计复用", value: overview?.hits, hint: "被实际拿去打过" },
                ].map((s) => (
                  <div key={s.label} className="rounded-lg border p-3">
                    <p className="font-semibold text-2xl tabular-nums">{s.value ?? "—"}</p>
                    <p className="font-medium text-xs">{s.label}</p>
                    {s.hint && <p className="mt-0.5 text-[11px] text-muted-foreground">{s.hint}</p>}
                  </div>
                ))}
              </div>

              {/* 空态 */}
              <Empty>
                <EmptyHeader>
                  <EmptyTitle className="text-sm">选择左侧条目查看详情</EmptyTitle>
                  <EmptyDescription className="text-xs">
                    按 CVE / 组件 / 关键字一次搜两层——自建 POC/EXP 库 + 本机 nuclei 模板库。 Nday/1day
                    动手前先查这里，命中后取全文直接用。
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>

              {/* 高频复用 Top */}
              {overview && overview.hits > 0 && (
                <div className="space-y-2">
                  <Label className="text-muted-foreground text-xs">最常用（按复用次数）</Label>
                  <div className="space-y-1">
                    {[...entries]
                      .sort((a, b) => b.hit_count - a.hit_count)
                      .slice(0, 6)
                      .filter((e) => e.hit_count > 0)
                      .map((e) => (
                        <button
                          key={e.code}
                          type="button"
                          onClick={() => setSelected(e)}
                          className="flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left hover:bg-muted"
                        >
                          <span className="w-56 shrink-0 truncate text-xs" title={e.title}>
                            {e.title}
                          </span>
                          <span className="relative h-2 flex-1 overflow-hidden rounded-full bg-muted">
                            <span
                              className="absolute inset-y-0 left-0 rounded-full bg-primary/70"
                              style={{
                                width: `${(e.hit_count / Math.max(...entries.map((x) => x.hit_count), 1)) * 100}%`,
                              }}
                            />
                          </span>
                          <span className="w-12 shrink-0 text-right text-muted-foreground text-xs tabular-nums">
                            {e.hit_count} 次
                          </span>
                        </button>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {active && (
            <div className="mx-auto w-full max-w-4xl space-y-5">
              {/* 标题区 */}
              <div>
                <div className="flex items-start gap-2">
                  <h2 className="min-w-0 flex-1 font-semibold text-base">{active.title}</h2>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <Button size="sm" variant="outline" onClick={() => registerHit()}>
                      <TargetIcon className="size-3.5" />
                      登记复用
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => openEdit(active)}>
                      <PencilIcon className="size-3.5" />
                      编辑
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-destructive"
                      onClick={() => setPendingDelete(active)}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </div>

                {/* code + 复制 */}
                <div className="mt-1.5 flex items-center gap-1.5">
                  <code className="font-mono text-muted-foreground text-xs">{active.code}</code>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-5"
                    title="复制 code"
                    onClick={() => void copyCode(active.code)}
                  >
                    <CopyIcon className="size-3 text-muted-foreground" />
                  </Button>
                </div>

                {/* 徽章行 */}
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Badge variant="outline" className="font-normal text-xs">
                    {KIND_LABEL[active.kind] ?? active.kind}
                  </Badge>
                  <Badge variant="secondary" className="font-normal text-xs">
                    {active.category_name}
                  </Badge>
                  {active.layer === "nuclei" && (
                    <Badge variant="outline" className="font-normal text-xs">
                      nuclei 模板层
                    </Badge>
                  )}
                  {active.severity && (
                    <span
                      className={cn(
                        "inline-flex items-center rounded-md border px-2 py-0.5 font-medium text-xs",
                        SEV_TONE[active.severity] ?? SEV_TONE.info,
                      )}
                    >
                      {SEV_LABEL[active.severity] ?? active.severity}
                    </span>
                  )}
                  {active.verified && (
                    <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/20 bg-emerald-500/15 px-2 py-0.5 font-medium text-emerald-600 text-xs dark:text-emerald-400">
                      <CheckCircle2Icon className="size-3" />
                      已验证
                    </span>
                  )}
                  {active.cve && (
                    <Badge variant="outline" className="font-mono font-normal text-xs">
                      {active.cve}
                    </Badge>
                  )}
                </div>
              </div>

              {detailLoading ? (
                <p className="text-muted-foreground text-xs">加载详情…</p>
              ) : (
                <>
                  {/* 元数据网格 */}
                  <div className="grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border p-4 text-xs sm:grid-cols-3 lg:grid-cols-4">
                    {[
                      ["组件", active.component],
                      ["版本", active.versions],
                      ["语言", active.language],
                      ["来源", active.source],
                      ["复用次数", String(active.hit_count)],
                      ["最近使用", active.used_on || "—"],
                      ["来源靶标", active.engagement || "—"],
                      ["发现资产", active.asset || "—"],
                      ["建立时间", fmtTime(active.created_at)],
                      ["更新时间", fmtTime(active.updated_at)],
                      ["建立人", active.created_by || "—"],
                      ["路径", active.path || "—"],
                    ]
                      .filter(([, v]) => v && v !== "—")
                      .map(([k, v]) => (
                        <div key={k}>
                          <p className="text-muted-foreground">{k}</p>
                          <p className="mt-0.5 truncate font-medium" title={v}>
                            {v}
                          </p>
                        </div>
                      ))}
                  </div>

                  {/* 描述 */}
                  {active.description && (
                    <div className="space-y-1.5">
                      <Label className="text-muted-foreground text-xs">描述</Label>
                      <p className="whitespace-pre-wrap text-sm leading-relaxed">{active.description}</p>
                    </div>
                  )}

                  {/* 用法 */}
                  {active.usage && (
                    <div className="space-y-1.5">
                      <Label className="text-muted-foreground text-xs">用法</Label>
                      <pre className="overflow-x-auto whitespace-pre-wrap rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">
                        {active.usage}
                      </pre>
                    </div>
                  )}

                  {/* 验证证据 */}
                  {active.verified_note && (
                    <div className="space-y-1.5">
                      <Label className="text-muted-foreground text-xs">验证证据</Label>
                      <p className="whitespace-pre-wrap rounded-md border border-emerald-500/20 bg-emerald-500/10 p-3 text-sm">
                        {active.verified_note}
                      </p>
                    </div>
                  )}

                  {/* 正文 */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <Label className="text-muted-foreground text-xs">
                        正文 {detail && <span className="font-normal">（{fmtBytes(detail.content_bytes)}）</span>}
                      </Label>
                      {active.source_url && (
                        <a
                          href={active.source_url.split("\n")[0]}
                          target="_blank"
                          rel="noreferrer"
                          className="text-blue-500 text-xs hover:underline"
                        >
                          参考链接 ↗
                        </a>
                      )}
                    </div>
                    {active.has_content ? (
                      <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">
                        {detail?.content ?? ""}
                      </pre>
                    ) : (
                      <p className="rounded-md border border-dashed p-3 text-muted-foreground text-xs">
                        正文为空（模板层条目只存元数据，用法见上方「用法」）。
                      </p>
                    )}
                  </div>

                  {/* 标签 */}
                  {active.tags && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Label className="text-muted-foreground text-xs">标签</Label>
                      {active.tags
                        .split(/[,\s]+/)
                        .filter(Boolean)
                        .map((t) => (
                          <Badge key={t} variant="outline" className="font-mono font-normal text-xs">
                            {t}
                          </Badge>
                        ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── 删除二次确认 ── */}
      <AlertDialog
        open={!!pendingDelete}
        onOpenChange={(o) => {
          if (!o) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除「{pendingDelete?.title}」？</AlertDialogTitle>
            <AlertDialogDescription>
              将从知识库移除该条目（code：
              <code className="font-mono">{pendingDelete?.code}</code>
              ）。nuclei 模板层条目可在下次导入时重建，自建条目不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleting}
              onClick={(e) => {
                e.preventDefault();
                void remove();
              }}
            >
              {deleting ? "删除中…" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── 新建 / 编辑 ── */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent side="right" className="flex w-full flex-col gap-0 data-[side=right]:sm:max-w-2xl">
          <SheetHeader className="px-4 pt-4">
            <SheetTitle>{editingId ? "编辑条目" : "新建条目"}</SheetTitle>
          </SheetHeader>
          <ScrollArea className="min-h-0 flex-1 px-4">
            <div className="space-y-4 py-4">
              <div className="grid gap-1.5">
                <Label htmlFor="poc-title">
                  标题 <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="poc-title"
                  placeholder="如：Log4j2 远程代码执行（CVE-2021-44228）"
                  value={form.title}
                  onChange={(e) => setF({ title: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">code</Label>
                  <Input
                    placeholder="留空自动生成"
                    value={form.code}
                    onChange={(e) => setF({ code: e.target.value })}
                  />
                  <p className="text-[11px] text-muted-foreground">智能体引用标识；同 code 再存=覆盖刷新</p>
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">CVE / 编号</Label>
                  <Input
                    placeholder="CVE-2021-44228"
                    value={form.cve}
                    onChange={(e) => setF({ cve: e.target.value })}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">类型</Label>
                  <select
                    className="h-9 rounded-md border bg-background px-2 text-sm"
                    value={form.kind}
                    onChange={(e) => setF({ kind: e.target.value })}
                  >
                    <option value="poc">POC</option>
                    <option value="exp">EXP</option>
                    <option value="script">脚本</option>
                    <option value="template">模板</option>
                    <option value="payload">Payload</option>
                  </select>
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">归类</Label>
                  <select
                    className="h-9 rounded-md border bg-background px-2 text-sm"
                    value={form.category}
                    onChange={(e) => setF({ category: e.target.value })}
                  >
                    {categories.map((c) => (
                      <option key={c.code} value={c.code}>
                        {c.name}
                      </option>
                    ))}
                    {categories.length === 0 && <option value="other">其它</option>}
                  </select>
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">严重度</Label>
                  <select
                    className="h-9 rounded-md border bg-background px-2 text-sm"
                    value={form.severity}
                    onChange={(e) => setF({ severity: e.target.value })}
                  >
                    <option value="">未设</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                    <option value="info">信息</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">组件/产品</Label>
                  <Input
                    placeholder="Weblogic / Shiro…"
                    value={form.component}
                    onChange={(e) => setF({ component: e.target.value })}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">版本</Label>
                  <Input
                    placeholder="受影响版本"
                    value={form.versions}
                    onChange={(e) => setF({ versions: e.target.value })}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">语言</Label>
                  <Input
                    placeholder="python / go / http…"
                    value={form.language}
                    onChange={(e) => setF({ language: e.target.value })}
                  />
                </div>
              </div>

              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">描述</Label>
                <Textarea
                  rows={2}
                  className="resize-none"
                  placeholder="漏洞成因、影响范围、适用场景"
                  value={form.description}
                  onChange={(e) => setF({ description: e.target.value })}
                />
              </div>

              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">用法</Label>
                <Textarea
                  rows={2}
                  className="resize-none font-mono text-xs"
                  placeholder={"nuclei -t ./template.yaml -u <目标>\n或手工请求示例"}
                  value={form.usage}
                  onChange={(e) => setF({ usage: e.target.value })}
                />
              </div>

              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">
                  正文 <span className="font-normal">（POC/脚本/原始请求；留空不覆盖已有正文）</span>
                </Label>
                <Textarea
                  rows={8}
                  className="resize-none font-mono text-xs"
                  placeholder="完整 POC、exploit 脚本或请求报文"
                  value={form.content}
                  onChange={(e) => setF({ content: e.target.value })}
                />
              </div>

              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">标签（逗号分隔）</Label>
                <Input
                  placeholder="rce, log4j, jndi"
                  value={form.tags}
                  onChange={(e) => setF({ tags: e.target.value })}
                />
              </div>

              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">参考链接</Label>
                <Input
                  placeholder="https://…"
                  value={form.source_url}
                  onChange={(e) => setF({ source_url: e.target.value })}
                />
              </div>
            </div>
          </ScrollArea>
          <SheetFooter className="flex-row justify-end gap-2 border-t px-4 py-3">
            <Button variant="outline" onClick={() => setSheetOpen(false)}>
              取消
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving ? "保存中…" : "保存"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
