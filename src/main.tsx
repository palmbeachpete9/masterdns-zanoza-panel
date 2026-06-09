import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Copy,
  Edit3,
  Globe,
  KeyRound,
  Link as LinkIcon,
  Lock,
  LogOut,
  Plus,
  RefreshCw,
  Server,
  Settings,
  Trash2,
  X,
} from "lucide-react";
import "./index.css";

// ---------------------------------------------------------------------------
// Types — an "instance" is one (domain, key, method) tuple. The panel groups
// instances by domain (model: many domains, many keys per domain).
// ---------------------------------------------------------------------------

type Instance = {
  id: string;
  label: string;
  domain: string;
  key: string;
  method: number; // 0 None, 1 XOR, 2 ChaCha20, 3 AES-128, 4 AES-192, 5 AES-256
  created_at: string;
  zanoza_link: string;
};

type DomainGroup = {
  domain: string;
  instances: Instance[];
};

type RuntimeState = {
  status: string;
  running: boolean;
  pid?: number;
  memory_bytes?: number;
  started_at?: string;
  exited_at?: string;
  exit_error?: string;
  desired_keyring?: string;
  applied_keyring?: string;
  apply_pending?: boolean;
  apply_error?: string;
};

type State = {
  name: string;
  panel_path: string;
  domain_count: number;
  instance_count: number;
  server: RuntimeState;
  instances: Instance[];
};

type Metrics = {
  go: { version: string; goroutines: number };
  memory: { heap_alloc_bytes: number };
  panel: { pid: number };
  server: RuntimeState;
};

type SettingsState = {
  name: string;
  panel_path: string;
  admin_user: string;
};

type InstanceForm = {
  id?: string;
  label: string;
  domain: string;
  key: string;
  method: number;
};

const ENCRYPTION_METHODS: Array<{ value: number; label: string; aead: boolean }> = [
  { value: 0, label: "None", aead: false },
  { value: 1, label: "XOR", aead: false },
  { value: 2, label: "ChaCha20", aead: true },
  { value: 3, label: "AES-128-GCM", aead: true },
  { value: 4, label: "AES-192-GCM", aead: true },
  { value: 5, label: "AES-256-GCM", aead: true },
];

function methodLabel(method: number): string {
  return ENCRYPTION_METHODS.find((entry) => entry.value === method)?.label ?? `#${method}`;
}

function isAEAD(method: number): boolean {
  return ENCRYPTION_METHODS.find((entry) => entry.value === method)?.aead ?? false;
}

const defaultForm: InstanceForm = {
  label: "",
  domain: "",
  key: "",
  method: 1,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function request(path: string, options?: RequestInit) {
  const res = await fetch(path, options);
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event("zanoza-auth-required"));
    throw new Error((await res.text()).trim() || res.statusText);
  }
  return res;
}

function randomHex64() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function formatBytes(bytes?: number) {
  if (!bytes) return "...";
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function maskKey(key: string): string {
  if (key.length <= 12) return key;
  return `${key.slice(0, 6)}…${key.slice(-6)}`;
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    if (!document.execCommand("copy")) throw new Error("copy command failed");
  } finally {
    document.body.removeChild(textarea);
  }
}

function groupByDomain(instances: Instance[]): DomainGroup[] {
  const map = new Map<string, Instance[]>();
  for (const instance of instances) {
    const list = map.get(instance.domain) ?? [];
    list.push(instance);
    map.set(instance.domain, list);
  }
  return Array.from(map.entries())
    .map(([domain, list]) => ({ domain, instances: list }))
    .sort((a, b) => a.domain.localeCompare(b.domain));
}

// ---------------------------------------------------------------------------
// Small presentational pieces (styling mirrors the olcrtc panel)
// ---------------------------------------------------------------------------

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-normal">{value}</div>
    </div>
  );
}

function HeaderMetric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid h-9 min-w-24 content-center rounded-md border border-border bg-card px-3">
      <div className="text-[10px] uppercase leading-3 text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold leading-4">{value}</div>
    </div>
  );
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-auto rounded-lg border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-lg font-semibold tracking-normal">{title}</h2>
          <button
            className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-muted hover:bg-muted/80"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function LoginView({ setupRequired, onLogin }: { setupRequired: boolean; onLogin: () => void }) {
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (setupRequired && password !== repeat) throw new Error("Пароли не совпадают");
      await request(setupRequired ? "api/auth/setup" : "api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, password }),
      });
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen place-items-center bg-background px-5">
      <form className="grid w-full max-w-sm gap-4 rounded-lg border border-border bg-card p-5" onSubmit={submit}>
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-md bg-primary/15 text-primary">
            <Lock className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-normal">Zanoza Panel</h1>
            <div className="text-sm text-muted-foreground">{setupRequired ? "Первичная настройка" : "Вход в панель"}</div>
          </div>
        </div>
        <label className="grid gap-2 text-sm text-muted-foreground">
          Логин
          <input
            className="h-10 rounded-md border border-border bg-background px-3 text-foreground outline-none focus:border-primary"
            value={user}
            onChange={(event) => setUser(event.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="grid gap-2 text-sm text-muted-foreground">
          Пароль
          <input
            className="h-10 rounded-md border border-border bg-background px-3 text-foreground outline-none focus:border-primary"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </label>
        {setupRequired && (
          <label className="grid gap-2 text-sm text-muted-foreground">
            Повтор пароля
            <input
              className="h-10 rounded-md border border-border bg-background px-3 text-foreground outline-none focus:border-primary"
              type="password"
              value={repeat}
              onChange={(event) => setRepeat(event.target.value)}
              autoComplete="new-password"
            />
          </label>
        )}
        {error && <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>}
        <button
          className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-primary px-3 text-sm font-medium text-black hover:bg-primary/90 disabled:opacity-60"
          disabled={busy}
        >
          <Lock className="h-4 w-4" />
          {setupRequired ? "Сохранить пароль" : "Войти"}
        </button>
      </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Instance create/edit form
// ---------------------------------------------------------------------------

function InstanceFormFields({
  form,
  setForm,
  siblingMethods,
}: {
  form: InstanceForm;
  setForm: (form: InstanceForm) => void;
  siblingMethods: number[];
}) {
  const set = (patch: Partial<InstanceForm>) => setForm({ ...form, ...patch });
  // A domain that already holds another key forces AEAD on all of its keys.
  const requiresAEAD = siblingMethods.length > 0;

  return (
    <div className="grid gap-4">
      <label className="grid gap-2 text-sm text-muted-foreground">
        Метка (для администратора)
        <input
          className="h-10 rounded-md border border-border bg-background px-3 text-foreground outline-none focus:border-primary"
          value={form.label}
          onChange={(event) => set({ label: event.target.value })}
          placeholder="например, user-alice"
        />
      </label>

      <label className="grid gap-2 text-sm text-muted-foreground">
        Делегированный домен
        <input
          className="h-10 rounded-md border border-border bg-background px-3 font-mono text-sm text-foreground outline-none focus:border-primary"
          value={form.domain}
          onChange={(event) => set({ domain: event.target.value.trim().toLowerCase() })}
          placeholder="v.example.com"
        />
        <span className="text-xs text-muted-foreground">
          A-запись этого домена (и NS-делегирование) должны указывать на IP этого сервера панели.
          Несколько доменов могут вести на один IP.
        </span>
      </label>

      <label className="grid gap-2 text-sm text-muted-foreground">
        Ключ шифрования
        <div className="flex gap-2">
          <input
            className="h-10 flex-1 rounded-md border border-border bg-background px-3 font-mono text-xs text-foreground outline-none focus:border-primary"
            value={form.key}
            onChange={(event) => set({ key: event.target.value.trim() })}
            placeholder="64 hex-символа"
          />
          <button
            className="inline-flex h-10 items-center rounded-md border border-primary bg-secondary px-3 text-xs font-medium text-primary hover:bg-primary/10"
            type="button"
            onClick={() => set({ key: randomHex64() })}
          >
            Сгенерировать
          </button>
        </div>
      </label>

      <label className="grid gap-2 text-sm text-muted-foreground">
        Метод шифрования
        <select
          className="h-10 rounded-md border border-border bg-background px-3 text-foreground outline-none focus:border-primary"
          value={form.method}
          onChange={(event) => set({ method: Number(event.target.value) })}
        >
          {ENCRYPTION_METHODS.map((entry) => (
            <option key={entry.value} value={entry.value} disabled={requiresAEAD && !entry.aead}>
              {entry.label}
              {requiresAEAD && !entry.aead ? " — недоступно (нужен AEAD)" : ""}
            </option>
          ))}
        </select>
        {requiresAEAD ? (
          <span className="text-xs text-primary">
            На этом домене уже есть другой ключ — для всех ключей домена требуется AEAD
            (ChaCha20 / AES-GCM), чтобы сервер мог различать ключи.
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">
            Для домена с одним ключом подойдёт любой метод, включая XOR (самый быстрый).
            Должен совпадать с методом в приложении Zanoza.
          </span>
        )}
      </label>
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [setupRequired, setSetupRequired] = useState(false);
  const [state, setState] = useState<State | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [editing, setEditing] = useState<Instance | null>(null);
  const [form, setForm] = useState<InstanceForm>(defaultForm);
  const [nameDraft, setNameDraft] = useState("");
  const [pwdCurrent, setPwdCurrent] = useState("");
  const [pwdNew, setPwdNew] = useState("");

  const loadState = async () => {
    const res = await request("api/state");
    setState((await res.json()) as State);
  };
  const loadMetrics = async () => {
    const res = await request("api/metrics");
    setMetrics((await res.json()) as Metrics);
  };
  const loadSettings = async () => {
    const res = await request("api/settings");
    const body = (await res.json()) as SettingsState;
    setSettings(body);
    setNameDraft(body.name);
  };

  const bootstrap = async () => {
    try {
      const res = await request("api/auth/status");
      const body = (await res.json()) as { authenticated: boolean; setup_required: boolean };
      setSetupRequired(body.setup_required);
      setAuthenticated(body.authenticated);
      if (body.authenticated) {
        await Promise.all([loadState(), loadMetrics(), loadSettings()]);
      }
    } catch {
      setAuthenticated(false);
    }
  };

  useEffect(() => {
    bootstrap();
    const onAuthRequired = () => setAuthenticated(false);
    window.addEventListener("zanoza-auth-required", onAuthRequired);
    return () => window.removeEventListener("zanoza-auth-required", onAuthRequired);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    const timer = setInterval(() => {
      loadMetrics().catch(() => undefined);
    }, 5000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated]);

  const runAction = async (fn: () => Promise<void>, message?: string) => {
    setBusy(true);
    setNotice("");
    try {
      await fn();
      if (message) setNotice(message);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const afterLogin = async () => {
    setAuthenticated(true);
    await Promise.all([loadState(), loadMetrics(), loadSettings()]);
  };

  const logout = () =>
    runAction(async () => {
      await request("api/auth/logout", { method: "POST" });
      setAuthenticated(false);
    });

  const instances = state?.instances ?? [];
  const groups = useMemo(() => groupByDomain(instances), [instances]);

  const openCreate = (domain?: string) => {
    setEditing(null);
    setForm({ ...defaultForm, domain: domain ?? "" });
    setShowCreate(true);
  };

  const openEdit = (instance: Instance) => {
    setEditing(instance);
    setForm({
      id: instance.id,
      label: instance.label,
      domain: instance.domain,
      key: instance.key,
      method: instance.method,
    });
    setShowCreate(true);
  };

  const siblingMethodsFor = (domain: string, excludeId?: string) =>
    instances
      .filter((instance) => instance.domain === domain.trim().toLowerCase() && instance.id !== excludeId)
      .map((instance) => instance.method);

  const submitInstance = () =>
    runAction(async () => {
      const payload = {
        label: form.label.trim(),
        domain: form.domain.trim().toLowerCase(),
        key: form.key.trim(),
        method: form.method,
      };
      if (editing) {
        await request(`api/instances/${encodeURIComponent(editing.id)}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      } else {
        await request("api/instances", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
      }
      setShowCreate(false);
      await loadState();
    }, editing ? "Хост сохранён" : "Хост создан");

  const deleteInstance = (instance: Instance) =>
    runAction(async () => {
      if (!window.confirm(`Удалить ключ «${instance.label || instance.id}» на домене ${instance.domain}?`)) return;
      await request(`api/instances/${encodeURIComponent(instance.id)}`, { method: "DELETE" });
      await loadState();
    }, "Хост удалён");

  const restartServer = () =>
    runAction(async () => {
      await request("api/server/restart", { method: "POST" });
      await Promise.all([loadState(), loadMetrics()]);
    }, "Сервер MasterDnsVPN перезапущен");

  const saveName = () =>
    runAction(async () => {
      await request("api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: nameDraft.trim() }),
      });
      await Promise.all([loadState(), loadSettings()]);
    }, "Настройки сохранены");

  const changePassword = () =>
    runAction(async () => {
      await request("api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current: pwdCurrent, password: pwdNew }),
      });
      setPwdCurrent("");
      setPwdNew("");
      setShowSettings(false);
      setAuthenticated(false);
    }, "Пароль изменён, войдите заново");

  const copyDomainKey = (instance: Instance) =>
    runAction(async () => {
      await copyText(`${instance.domain} | ${instance.key}`);
    }, "Домен и ключ скопированы");

  const copyLink = (instance: Instance) =>
    runAction(async () => {
      await copyText(instance.zanoza_link);
    }, "Ссылка zanoza:// скопирована");

  if (authenticated === null) {
    return <div className="grid min-h-screen place-items-center text-sm text-muted-foreground">Загрузка...</div>;
  }
  if (!authenticated) {
    return <LoginView setupRequired={setupRequired} onLogin={afterLogin} />;
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-background/95">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-4">
          <h1 className="text-2xl font-semibold tracking-normal">Zanoza Panel</h1>
          <div className="flex flex-wrap items-center gap-2">
            <HeaderMetric label="Panel mem" value={formatBytes(metrics?.memory.heap_alloc_bytes)} />
            <HeaderMetric label="Server" value={metrics?.server.running ? "Running" : "Stopped"} />
            <HeaderMetric label="Server PID" value={metrics?.server.pid ?? "..."} />
            <button
              className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-muted px-3 text-sm hover:bg-muted/80"
              onClick={() => setShowSettings(true)}
            >
              <Settings className="h-4 w-4" />
              Настройки
            </button>
            <button
              className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-muted px-3 text-sm hover:bg-muted/80 disabled:opacity-60"
              disabled={busy}
              onClick={() => runAction(async () => { await loadState(); await loadMetrics(); }, "Обновлено")}
            >
              <RefreshCw className="h-4 w-4" />
              Обновить
            </button>
            <button
              className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-muted px-3 text-sm hover:bg-muted/80"
              onClick={logout}
            >
              <LogOut className="h-4 w-4" />
              Выйти
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-5 py-6">
        <section className="grid gap-3 md:grid-cols-4">
          <StatCard icon={<Server className="h-4 w-4" />} label="Профиль" value={state?.name ?? "..."} />
          <StatCard icon={<Globe className="h-4 w-4" />} label="Домены" value={state?.domain_count ?? "..."} />
          <StatCard icon={<KeyRound className="h-4 w-4" />} label="Ключи" value={state?.instance_count ?? "..."} />
          <StatCard
            icon={<Activity className="h-4 w-4" />}
            label="Сервер"
            value={
              <span className="flex flex-col">
                <span className={state?.server.running ? "text-primary" : "text-destructive"}>
                  {state?.server.running ? "Running" : "Stopped"}
                </span>
                {state?.server.apply_pending && (
                  <span className="text-xs font-normal text-yellow-500">Применение…</span>
                )}
                {state?.server.apply_error && (
                  <span className="text-xs font-normal text-destructive">{state.server.apply_error}</span>
                )}
              </span>
            }
          />
        </section>

        <section className="mt-4 rounded-lg border border-border bg-card p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold tracking-normal">Хосты</h2>
            <div className="flex flex-wrap gap-2">
              <button
                className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-muted px-3 text-sm hover:bg-muted/80 disabled:opacity-60"
                disabled={busy}
                onClick={restartServer}
              >
                <RefreshCw className="h-4 w-4" />
                Перезапустить сервер
              </button>
              <button
                className="inline-flex h-9 items-center gap-2 rounded-md bg-primary px-3 text-sm font-medium text-black hover:bg-primary/90"
                onClick={() => openCreate()}
              >
                <Plus className="h-4 w-4" />
                Создать хост
              </button>
            </div>
          </div>

          <div className="mt-3 min-h-5 text-sm text-muted-foreground">{notice}</div>

          {groups.length === 0 ? (
            <div className="mt-6 grid place-items-center gap-2 rounded-md border border-dashed border-border py-12 text-center">
              <Globe className="h-8 w-8 text-muted-foreground" />
              <div className="text-sm text-muted-foreground">
                Хостов пока нет. Создайте первый — домен + ключ.
              </div>
            </div>
          ) : (
            <div className="mt-4 grid gap-3">
              {groups.map((group) => {
                const open = expanded[group.domain] ?? true;
                return (
                  <div key={group.domain} className="overflow-hidden rounded-lg border border-border bg-background">
                    <div className="grid gap-3 p-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
                      <button
                        className="flex min-w-0 items-center gap-3 text-left"
                        onClick={() => setExpanded((cur) => ({ ...cur, [group.domain]: !open }))}
                      >
                        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md border border-border bg-card text-muted-foreground">
                          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        </span>
                        <span className="min-w-0">
                          <span className="block truncate font-mono font-semibold">{group.domain}</span>
                          <span className="mt-1 block text-xs text-muted-foreground">
                            {group.instances.length} ключ(ей)
                            {group.instances.length > 1 ? " · AEAD" : ""}
                          </span>
                        </span>
                      </button>
                      <div className="flex flex-wrap gap-2 lg:justify-end">
                        <button
                          className="inline-flex h-8 items-center gap-2 rounded-md border border-border px-2 text-sm hover:bg-muted disabled:opacity-60"
                          disabled={busy}
                          onClick={() => openCreate(group.domain)}
                        >
                          <Plus className="h-4 w-4" />
                          Добавить ключ
                        </button>
                      </div>
                    </div>

                    {open && (
                      <div className="border-t border-border/70 p-3">
                        <div className="overflow-x-auto">
                          <table className="w-full min-w-[860px] border-collapse text-sm">
                            <thead>
                              <tr className="border-b border-border text-left text-muted-foreground">
                                <th className="py-2 pr-3 font-medium">Метка</th>
                                <th className="py-2 pr-3 font-medium">Ключ</th>
                                <th className="py-2 pr-3 font-medium">Метод</th>
                                <th className="py-2 pr-3 font-medium">Создан</th>
                                <th className="py-2 text-right font-medium">Действия</th>
                              </tr>
                            </thead>
                            <tbody>
                              {group.instances.map((instance) => (
                                <tr key={instance.id} className="border-b border-border/60 last:border-0">
                                  <td className="py-3 pr-3 font-medium">{instance.label || "—"}</td>
                                  <td className="py-3 pr-3 font-mono text-xs text-muted-foreground">{maskKey(instance.key)}</td>
                                  <td className="py-3 pr-3">
                                    <span
                                      className={`inline-flex rounded-full px-2 py-1 text-xs ${
                                        isAEAD(instance.method) ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                                      }`}
                                    >
                                      {methodLabel(instance.method)}
                                    </span>
                                  </td>
                                  <td className="py-3 pr-3 text-muted-foreground">{instance.created_at?.slice(0, 10)}</td>
                                  <td className="py-3">
                                    <div className="flex flex-wrap justify-end gap-2">
                                      <button
                                        className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2 text-xs hover:bg-muted disabled:opacity-60"
                                        disabled={busy}
                                        onClick={() => copyDomainKey(instance)}
                                        title="Скопировать домен и ключ"
                                      >
                                        <Copy className="h-3.5 w-3.5" />
                                        Домен+ключ
                                      </button>
                                      <button
                                        className="inline-flex h-8 items-center gap-1 rounded-md border border-primary px-2 text-xs text-primary hover:bg-primary/10 disabled:opacity-60"
                                        disabled={busy}
                                        onClick={() => copyLink(instance)}
                                        title="Скопировать zanoza:// ссылку"
                                      >
                                        <LinkIcon className="h-3.5 w-3.5" />
                                        zanoza://
                                      </button>
                                      <button
                                        className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2 text-xs hover:bg-muted disabled:opacity-60"
                                        disabled={busy}
                                        onClick={() => openEdit(instance)}
                                      >
                                        <Edit3 className="h-3.5 w-3.5" />
                                        Изм.
                                      </button>
                                      <button
                                        className="inline-flex h-8 items-center gap-1 rounded-md border border-destructive/40 px-2 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-60"
                                        disabled={busy}
                                        onClick={() => deleteInstance(instance)}
                                      >
                                        <Trash2 className="h-3.5 w-3.5" />
                                        Удал.
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </main>

      {showCreate && (
        <Modal title={editing ? "Изменить хост" : "Создать хост"} onClose={() => setShowCreate(false)}>
          <div className="grid gap-4 p-5">
            <InstanceFormFields
              form={form}
              setForm={setForm}
              siblingMethods={siblingMethodsFor(form.domain, editing?.id)}
            />
            <div className="flex justify-end gap-2">
              <button
                className="inline-flex h-10 items-center rounded-md border border-border bg-muted px-4 text-sm hover:bg-muted/80"
                onClick={() => setShowCreate(false)}
              >
                Отмена
              </button>
              <button
                className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-black hover:bg-primary/90 disabled:opacity-60"
                disabled={busy}
                onClick={submitInstance}
              >
                {editing ? "Сохранить" : "Создать"}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {showSettings && (
        <Modal title="Настройки" onClose={() => setShowSettings(false)}>
          <div className="grid gap-5 p-5">
            <div className="grid gap-3 rounded-md border border-border bg-background p-3">
              <div className="text-sm font-medium text-foreground">Профиль</div>
              <label className="grid gap-2 text-sm text-muted-foreground">
                Название панели
                <input
                  className="h-10 rounded-md border border-border bg-card px-3 text-foreground outline-none focus:border-primary"
                  value={nameDraft}
                  onChange={(event) => setNameDraft(event.target.value)}
                />
              </label>
              <div className="text-xs text-muted-foreground">
                Путь панели: <span className="font-mono">{settings?.panel_path}</span> · Админ:{" "}
                <span className="font-mono">{settings?.admin_user}</span>
              </div>
              <button
                className="inline-flex h-9 w-fit items-center rounded-md bg-primary px-3 text-sm font-medium text-black hover:bg-primary/90 disabled:opacity-60"
                disabled={busy}
                onClick={saveName}
              >
                Сохранить
              </button>
            </div>

            <div className="grid gap-3 rounded-md border border-border bg-background p-3">
              <div className="text-sm font-medium text-foreground">Пароль администратора</div>
              <label className="grid gap-2 text-sm text-muted-foreground">
                Текущий пароль
                <input
                  className="h-10 rounded-md border border-border bg-card px-3 text-foreground outline-none focus:border-primary"
                  type="password"
                  value={pwdCurrent}
                  onChange={(event) => setPwdCurrent(event.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <label className="grid gap-2 text-sm text-muted-foreground">
                Новый пароль
                <input
                  className="h-10 rounded-md border border-border bg-card px-3 text-foreground outline-none focus:border-primary"
                  type="password"
                  value={pwdNew}
                  onChange={(event) => setPwdNew(event.target.value)}
                  autoComplete="new-password"
                />
              </label>
              <button
                className="inline-flex h-9 w-fit items-center rounded-md border border-border bg-muted px-3 text-sm hover:bg-muted/80 disabled:opacity-60"
                disabled={busy || !pwdCurrent || !pwdNew}
                onClick={changePassword}
              >
                Изменить пароль
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
