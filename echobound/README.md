# ECHOBOUND — Security Boundary Memory

<p align="center"><b>A Temporal Behavioral Security Platform</b><br/>
Python · eBPF · Temporal Graph · FastAPI · Local AI Investigator · Next.js/React Command Center</p>

<p align="center">
<a href="#english">English</a> ·
<a href="#فارسی">فارسی</a> ·
<a href="#中文">中文</a>
</p>

---

## English

### What ECHOBOUND is

Most security tools collect and store events. ECHOBOUND does something different: for every **Process, User, Container, Service, Host, API, Workload and Identity** it builds a living, time-aware **Security Boundary Memory** — a continuously learned model of that entity's *normal behavioral boundary* — and then watches, over time, for the moment that boundary changes.

The question ECHOBOUND asks is not *"is this event suspicious?"* but:

> *What boundary has this entity had over time, how did that boundary form, exactly where did it change, is the change expected, what evidence supports it, and what does that change mean for the security of the whole system?*

### Architecture at a glance

| Layer | Responsibility | Technology |
|---|---|---|
| Kernel observability | Metadata-only collection of process, network, file, identity and container events | eBPF (BCC), tracepoints/kprobes, graceful `/proc` fallback |
| Temporal Graph | Versioned nodes/edges with start/end/last-seen/frequency/confidence/state | SQLite (reference), provider-independent storage layer |
| Behavioral intelligence | Boundary memory, baselines, drift, policy, violation, query, investigation | Python 3.11 |
| Local AI | Explanation, hypothesis generation, evidence-grounded investigation tools | Local model abstraction (Ollama-compatible or deterministic fallback) |
| API | Versioned REST + WebSocket | FastAPI |
| Command Center | Security operations UI | Static HTML/CSS/JS SPA (ships working out of the box) + Next.js/React/TypeScript/React Flow/Three.js reference frontend |

### Key capabilities implemented in this repository

- **Security Boundary Model**: Identity, Process, File, Network, Data, Temporal, Privilege, Container, Service and Trust boundaries per entity.
- **Temporal Security Graph**: every relationship (`spawned`, `connected_to`, `queried`, `authenticated_to`, `contained_by`, …) carries start/end/last-seen/frequency/confidence/state/version.
- **Boundary Memory Engine**: candidate → observed → expected promotion driven by frequency, recency, duration, repetition and source reliability — never a single event flipping the canonical boundary.
- **Context-aware Baseline Engine**: versioned, freezable, rollback-able baselines scoped by environment, host, deployment version, time-of-day and more.
- **Drift Engine family**: Boundary Diff Engine, First Boundary Divergence Detector, Expansion/Contraction/Collapse detectors, Deployment-Aware Drift Engine, Change Correlation Engine, Recovery Boundary Engine.
- **Policy Engine**: Expected Boundary Contracts, forbidden/allowed relationships, and a Policy Simulator that evaluates a hypothetical relationship before it exists.
- **Incident Correlator**: groups temporally- and graph-adjacent drifts into Compound Boundary Incidents, with a First Cause Timeline.
- **Local AI Investigator**: tool-calling (`inspect_boundary`, `compare_behavior`, `trace_relationship`, `query_history`, `find_first_divergence`, `correlate_changes`, `compare_entities`, `summarize_incident`) grounded entirely in real stored evidence — it explains and hypothesizes, it never issues the final security verdict.
- **Collector Confidence Model + Telemetry Integrity Layer + Blind Spot Detector**: a drop in events from a broken collector is never mistaken for "nothing happened."
- **Self-Observing Detection Layer + Platform Boundary Guard**: ECHOBOUND models its own health the same way it models any monitored entity.
- **Synthetic Security World Generator + Benchmark Lab + Regression Suite**: seeded, reproducible scenarios (new/removed relationship, gradual/burst/periodic/contextual/false drift, deployment-induced drift, collector failure, recovery) for testing and CI.
- **Operating Hours & Maintenance Context Engine**: you tell ECHOBOUND your organization's real operating hours (per weekday, any timezone) directly from the Settings screen; the system continuously computes whether it is currently open or closed, whether a maintenance window is active, and exactly how long until the next change — and folds that into Schedule Boundary Drift detection automatically.
- **Full REST + WebSocket API**, a professional **CLI** (`agent`, `collect`, `baseline`, `boundary`, `graph`, `query`, `drift`, `replay`, `investigate`, `snapshot`, `simulate`, `benchmark`, `report`, `operating-hours`), Docker + Kubernetes manifests, and an automated **pytest** suite.

### Project layout

```
echobound/
├── backend/                     Python core: graph, boundary memory, drift, policy,
│   ├── echobound/                query engine, incidents, AI investigator, API, CLI
│   │   ├── collectors/           eBPF + /proc-fallback telemetry collectors
│   │   └── ai/                   Local AI investigator + tool functions
│   ├── tests/                    pytest suite
│   └── requirements.txt
├── frontend/
│   ├── dashboard/                Ready-to-run static Security Command Center (HTML/CSS/JS)
│   └── web-nextjs/               Next.js + React + TypeScript reference frontend
└── deploy/
    ├── docker-compose.yml        (repo root)
    └── k8s/                      Kubernetes Deployment/DaemonSet/HPA manifests
```

### Installation

**Requirements:** Python 3.10+, Node.js 18+ (only if you build the Next.js frontend), Linux with kernel BPF support + the `bcc` package (only for the real eBPF collector — everything else runs on any OS).

```bash
# 1. Clone or extract this project, then enter the backend folder
cd echobound/backend

# 2. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Linux only, optional, needed for the real kernel-level eBPF collector)
sudo apt install bpfcc-tools python3-bpfcc   # Debian/Ubuntu
# or: sudo dnf install bcc-tools python3-bcc  # Fedora

# 5. Run the API server
python -m echobound.main
# → http://localhost:8088   (docs at /docs)

# 6. Open the dashboard (in another terminal / from your browser)
cd ../frontend/dashboard
python3 -m http.server 8089
# → open http://localhost:8089 and set the API Base URL in Settings if needed

# 7. (optional) seed a synthetic security world to explore the UI immediately
curl -X POST http://localhost:8088/api/v1/synthetic/generate \
  -H "Content-Type: application/json" -d '{"seed":42,"tenant":"default"}'

# 8. (optional) run the automated test suite
cd ../../backend
pytest -q

# 9. (optional) install the CLI as a command
pip install -e .
echobound --help
```

**Docker (backend + dashboard together):**

```bash
docker compose up --build
# API:       http://localhost:8088
# Dashboard: http://localhost:8089
```

**Next.js reference frontend (optional):**

```bash
cd frontend/web-nextjs
npm install
npm run dev
# → http://localhost:3000
```

### Configuring your operating hours (no code required)

Open the dashboard → **Settings → Operating Hours**. Enter your timezone, start/end time and the weekdays you operate on, press **Quick setup**, and the system immediately shows whether you're currently **OPEN**, **CLOSED** or inside a **maintenance window**, plus a live countdown to the next change. This is used automatically by the Drift Engine's Schedule Boundary Drift detector, and is available identically through `POST /api/v1/context/operating-hours/quick-setup` and the `echobound operating-hours` CLI command.

### Themes & languages

The Command Center ships five themes (Windows 11 Light, Windows 11 Dark, AMOLED Black, Crimson Red, Azure Blue) and three languages (English, فارسی, 中文) with correct RTL layout for Persian and LTR for English/Chinese — switch either from **Settings**, no reload required.

### License

Licensed under the Apache License 2.0 — see `LICENSE`.

---

## فارسی

### اکوباند چیست

بیشتر ابزارهای امنیتی صرفاً رویدادها را جمع‌آوری و ذخیره می‌کنند. اکوباند کار متفاوتی انجام می‌دهد: برای هر **Process، User، Container، Service، Host، API، Workload و Identity** یک **حافظه مرز امنیتی** زنده و زمان‌محور می‌سازد — مدلی که به‌طور پیوسته یاد می‌گیرد «مرز رفتاری طبیعی» آن موجودیت دقیقاً چگونه است — و سپس در طول زمان مراقب لحظه‌ای است که این مرز تغییر می‌کند.

سؤال اصلی اکوباند این نیست که «این رویداد مشکوک است؟»، بلکه این است:

> این موجودیت در طول زمان چه مرزی داشته، این مرز چگونه شکل گرفته، دقیقاً کجا تغییر کرده، آیا این تغییر مورد انتظار است، چه شواهدی آن را تأیید می‌کنند و این تغییر چه معنایی برای امنیت کل سیستم دارد؟

### معماری در یک نگاه

| لایه | مسئولیت | فناوری |
|---|---|---|
| مشاهده‌پذیری سطح کرنل | جمع‌آوری فقط-متادیتای رویدادهای Process، Network، File، Identity و Container | eBPF (BCC)، Tracepoint/Kprobe، بازگشت خودکار به `/proc` |
| گراف زمان‌محور | Nodeها و Edgeهای نسخه‌بندی‌شده با start/end/last-seen/frequency/confidence/state | SQLite (پیاده‌سازی مرجع)، لایه ذخیره‌سازی مستقل از Provider |
| هوش رفتاری | حافظه مرز، خط پایه، دریفت، سیاست، تخلف، پرس‌وجو، بازجویی | Python 3.11 |
| هوش مصنوعی محلی | توضیح، تولید فرضیه، ابزارهای بازجویی مبتنی بر شواهد واقعی | لایه انتزاع مدل محلی (سازگار با Ollama یا حالت قطعی جایگزین) |
| API | REST نسخه‌بندی‌شده + WebSocket | FastAPI |
| مرکز فرماندهی | رابط عملیات امنیتی | یک SPA استاتیک HTML/CSS/JS آماده اجرا + رابط مرجع Next.js/React/TypeScript/React Flow/Three.js |

### قابلیت‌های کلیدی پیاده‌سازی‌شده در این مخزن

- **مدل مرز امنیتی**: مرزهای Identity، Process، File، Network، Data، Temporal، Privilege، Container، Service و Trust برای هر موجودیت.
- **گراف امنیتی زمان‌محور**: هر رابطه (`spawned`، `connected_to`، `queried`، `authenticated_to`، `contained_by` و…) دارای start/end/last-seen/frequency/confidence/state/version است.
- **موتور حافظه مرز**: ترفیع Candidate ← Observed ← Expected بر اساس فراوانی، تازگی، مدت، تکرار و اعتبار منبع — هرگز یک رویداد به‌تنهایی مرز اصلی را تغییر نمی‌دهد.
- **موتور خط پایه متناسب با زمینه**: خطوط پایه نسخه‌بندی‌شده، قابل انجماد و قابل بازگشت، متناسب با محیط، میزبان، نسخه استقرار، ساعت روز و موارد دیگر.
- **خانواده موتور دریفت**: موتور Diff مرزی، تشخیص‌دهنده اولین انحراف مرزی، تشخیص‌دهنده‌های گسترش/انقباض/فروپاشی، موتور دریفت آگاه از Deployment، موتور همبستگی تغییرات، موتور بازیابی مرز.
- **موتور سیاست**: قراردادهای مرز مورد انتظار، روابط مجاز/ممنوع، و شبیه‌ساز سیاست که یک رابطه فرضی را پیش از وقوع ارزیابی می‌کند.
- **همبسته‌ساز حوادث**: دریفت‌های نزدیک از نظر زمانی و گرافی را در قالب حوادث مرکب مرزی گروه‌بندی می‌کند، همراه با جدول زمانی علت اولیه.
- **بازجوی هوش مصنوعی محلی**: با ابزارهایی مانند `inspect_boundary`، `compare_behavior`، `trace_relationship`، `query_history`، `find_first_divergence`، `correlate_changes`، `compare_entities` و `summarize_incident` کاملاً بر پایه شواهد واقعی ذخیره‌شده کار می‌کند — فقط توضیح و فرضیه می‌دهد و هرگز تصمیم نهایی امنیتی نمی‌گیرد.
- **مدل اعتماد کالکتور + لایه یکپارچگی تله‌متری + تشخیص‌دهنده نقاط کور**: افت رویدادها به‌دلیل خرابی کالکتور هرگز به اشتباه «هیچ اتفاقی نیفتاده» تفسیر نمی‌شود.
- **لایه تشخیص خودنظاره‌گر + نگهبان مرز پلتفرم**: اکوباند سلامت خودش را دقیقاً مانند هر موجودیت تحت پایش مدل می‌کند.
- **مولد دنیای امنیتی مصنوعی + آزمایشگاه Benchmark + مجموعه رگرسیون**: سناریوهای Seed-دار و قابل تکرار (رابطه جدید/حذف‌شده، دریفت تدریجی/انفجاری/دوره‌ای/زمینه‌ای/کاذب، دریفت ناشی از Deployment، خرابی کالکتور، بازیابی) برای تست و CI.
- **موتور زمینه ساعات کاری و تعمیر و نگهداری**: شما مستقیماً از صفحه تنظیمات، ساعات کاری واقعی سازمان خود را (به تفکیک روز هفته، با هر منطقه زمانی) به اکوباند می‌گویید؛ سیستم به‌طور پیوسته محاسبه می‌کند که هم‌اکنون باز است یا بسته، آیا در پنجره تعمیر و نگهداری قرار دارد، و دقیقاً چقدر تا تغییر بعدی زمان باقی مانده — و این اطلاعات به‌طور خودکار در تشخیص دریفت زمانی لحاظ می‌شود.
- **API کامل REST و WebSocket**، یک **CLI حرفه‌ای** (`agent`، `collect`، `baseline`، `boundary`، `graph`، `query`، `drift`، `replay`، `investigate`، `snapshot`، `simulate`، `benchmark`، `report`، `operating-hours`)، فایل‌های Docker و Kubernetes، و مجموعه تست خودکار **pytest**.

### ساختار پروژه

```
echobound/
├── backend/                     هسته پایتون: گراف، حافظه مرز، دریفت، سیاست،
│   ├── echobound/                موتور پرس‌وجو، حوادث، بازجوی هوش مصنوعی، API، CLI
│   │   ├── collectors/           کالکتورهای تله‌متری eBPF و proc-fallback
│   │   └── ai/                   بازجوی هوش مصنوعی محلی + توابع ابزار
│   ├── tests/                    مجموعه تست pytest
│   └── requirements.txt
├── frontend/
│   ├── dashboard/                مرکز فرماندهی امنیتی استاتیک آماده اجرا (HTML/CSS/JS)
│   └── web-nextjs/               رابط مرجع Next.js + React + TypeScript
└── deploy/
    ├── docker-compose.yml        (ریشه مخزن)
    └── k8s/                      مانیفست‌های Kubernetes Deployment/DaemonSet/HPA
```

### نصب

**پیش‌نیازها:** Python نسخه ۳.۱۰ به بالا، Node.js نسخه ۱۸ به بالا (فقط در صورت ساخت رابط Next.js)، لینوکس با پشتیبانی کرنل از BPF به‌همراه پکیج `bcc` (فقط برای کالکتور واقعی eBPF — بقیه بخش‌ها روی هر سیستم‌عاملی اجرا می‌شوند).

```bash
# ۱. پروژه را باز کرده و وارد پوشه backend شوید
cd echobound/backend

# ۲. ساخت و فعال‌سازی محیط مجازی (توصیه‌شده)
python3 -m venv .venv
source .venv/bin/activate          # ویندوز: .venv\Scripts\activate

# ۳. نصب وابستگی‌های پایتون
pip install -r requirements.txt

# ۴. (فقط لینوکس، اختیاری، برای کالکتور واقعی eBPF سطح کرنل)
sudo apt install bpfcc-tools python3-bpfcc   # دبیان/اوبونتو
# یا: sudo dnf install bcc-tools python3-bcc  # فدورا

# ۵. اجرای سرور API
python -m echobound.main
# → http://localhost:8088   (مستندات در آدرس /docs)

# ۶. باز کردن داشبورد (در ترمینال دیگر / در مرورگر)
cd ../frontend/dashboard
python3 -m http.server 8089
# → آدرس http://localhost:8089 را باز کنید و در صورت نیاز آدرس API را در تنظیمات وارد کنید

# ۷. (اختیاری) ساخت یک دنیای امنیتی مصنوعی برای کاوش فوری در رابط کاربری
curl -X POST http://localhost:8088/api/v1/synthetic/generate \
  -H "Content-Type: application/json" -d '{"seed":42,"tenant":"default"}'

# ۸. (اختیاری) اجرای مجموعه تست خودکار
cd ../../backend
pytest -q

# ۹. (اختیاری) نصب CLI به‌عنوان یک دستور
pip install -e .
echobound --help
```

**Docker (بک‌اند و داشبورد با هم):**

```bash
docker compose up --build
# API:      http://localhost:8088
# داشبورد:  http://localhost:8089
```

**رابط مرجع Next.js (اختیاری):**

```bash
cd frontend/web-nextjs
npm install
npm run dev
# → http://localhost:3000
```

### پیکربندی ساعات کاری (بدون نیاز به کد)

داشبورد را باز کنید ← **تنظیمات ← ساعات کاری**. منطقه زمانی، زمان شروع/پایان و روزهای هفته‌ای که فعال هستید را وارد کنید، روی **تنظیم سریع** بزنید؛ سیستم بلافاصله نشان می‌دهد که هم‌اکنون **باز**، **بسته** یا در **پنجره تعمیر و نگهداری** هستید، به‌همراه شمارش معکوس زنده تا تغییر بعدی. این قابلیت به‌طور خودکار توسط تشخیص‌دهنده دریفت زمانی موتور دریفت استفاده می‌شود و از طریق `POST /api/v1/context/operating-hours/quick-setup` و دستور `echobound operating-hours` نیز به همین شکل در دسترس است.

### پوسته‌ها و زبان‌ها

مرکز فرماندهی با پنج پوسته (ویندوز ۱۱ روشن، ویندوز ۱۱ تیره، آمولد مشکی، قرمز زرشکی، آبی لاجوردی) و سه زبان (English، فارسی، 中文) با چیدمان صحیح راست‌به‌چپ برای فارسی و چپ‌به‌راست برای انگلیسی/چینی عرضه می‌شود — هر دو را می‌توانید از بخش **تنظیمات** و بدون نیاز به بارگذاری مجدد صفحه تغییر دهید.

### مجوز

این پروژه تحت مجوز Apache License 2.0 منتشر شده است — به فایل `LICENSE` مراجعه کنید.

---

## 中文

### ECHOBOUND 是什么

大多数安全工具只是收集和存储事件。ECHOBOUND 的做法不同：它为每一个 **Process（进程）、User（用户）、Container（容器）、Service（服务）、Host（主机）、API、Workload（工作负载）和 Identity（身份）** 建立一个持续学习、具备时间感知能力的 **安全边界记忆（Security Boundary Memory）**——一个不断学习该实体"正常行为边界"的模型——并随时间持续观察这个边界发生变化的确切时刻。

ECHOBOUND 提出的核心问题不是"这个事件可疑吗？"，而是：

> 这个实体在过去的时间里拥有过怎样的边界？这个边界是如何形成的？它究竟在哪里发生了变化？这种变化是否符合预期？有哪些证据支持这一判断？这种变化对整个系统的安全意味着什么？

### 架构总览

| 层级 | 职责 | 技术 |
|---|---|---|
| 内核可观测性 | 仅采集进程、网络、文件、身份与容器事件的元数据 | eBPF（BCC）、tracepoint/kprobe，并优雅降级至 `/proc` |
| 时序图谱 | 具备起止时间/最后可见/频率/置信度/状态的版本化节点与边 | SQLite（参考实现），与存储提供方无关的抽象层 |
| 行为智能 | 边界记忆、基线、漂移、策略、违规、查询、调查 | Python 3.11 |
| 本地 AI | 解释、假设生成、基于真实证据的调查工具 | 本地模型抽象层（兼容 Ollama 或确定性回退） |
| API | 带版本号的 REST + WebSocket | FastAPI |
| 指挥中心 | 安全运营界面 | 开箱即用的静态 HTML/CSS/JS 单页应用 + Next.js/React/TypeScript/React Flow/Three.js 参考前端 |

### 本仓库已实现的关键能力

- **安全边界模型**：为每个实体建立 Identity、Process、File、Network、Data、Temporal、Privilege、Container、Service 和 Trust 边界。
- **时序安全图谱**：每一条关系（`spawned`、`connected_to`、`queried`、`authenticated_to`、`contained_by` 等）都携带起止时间/最后可见/频率/置信度/状态/版本信息。
- **边界记忆引擎**：候选（Candidate）→已观测（Observed）→预期（Expected）的晋升过程由频率、时效性、持续时间、重复次数和来源可靠性共同驱动——绝不会因单一事件就改写规范边界。
- **上下文感知的基线引擎**：按环境、主机、部署版本、一天中的时段等维度划分作用域的、可版本化、可冻结、可回滚的基线。
- **漂移引擎家族**：边界差异引擎、首次边界偏离检测器、扩张/收缩/坍塌检测器、部署感知漂移引擎、变更关联引擎、边界恢复引擎。
- **策略引擎**：预期边界契约、允许/禁止的关系，以及可在关系真正建立之前评估假设关系的策略模拟器。
- **事件关联器**：将时间上和图谱上相邻的漂移归并为复合边界事件，并附带首因时间线。
- **本地 AI 调查员**：通过 `inspect_boundary`、`compare_behavior`、`trace_relationship`、`query_history`、`find_first_divergence`、`correlate_changes`、`compare_entities`、`summarize_incident` 等工具调用，完全基于真实存储的证据进行工作——它只负责解释和提出假设，绝不做出最终的安全判定。
- **采集器置信度模型 + 遥测完整性层 + 盲区检测器**：由采集器故障导致的事件量下降绝不会被误判为"什么都没发生"。
- **自我观测检测层 + 平台边界守护**：ECHOBOUND 以与监控任何实体相同的方式为自身的健康状况建模。
- **合成安全世界生成器 + 检测基准实验室 + 回归测试套件**：提供带种子、可复现的场景（新增/移除关系、渐进式/突发式/周期性/情境性/虚假漂移、部署引发的漂移、采集器故障、恢复），用于测试与持续集成。
- **营业时间与维护上下文引擎**：您可以直接在"设置"页面告诉 ECHOBOUND 您组织的真实营业时间（按星期几、任意时区）；系统会持续计算当前是营业中还是已关闭、是否处于维护窗口，以及距离下一次状态变化确切还有多长时间——并自动将其纳入计划漂移（Schedule Boundary Drift）检测。
- **完整的 REST + WebSocket API**、专业的**命令行工具**（`agent`、`collect`、`baseline`、`boundary`、`graph`、`query`、`drift`、`replay`、`investigate`、`snapshot`、`simulate`、`benchmark`、`report`、`operating-hours`）、Docker 与 Kubernetes 部署文件，以及自动化的 **pytest** 测试套件。

### 项目结构

```
echobound/
├── backend/                     Python 核心：图谱、边界记忆、漂移、策略、
│   ├── echobound/                查询引擎、事件、AI 调查员、API、CLI
│   │   ├── collectors/           eBPF 与 /proc 回退遥测采集器
│   │   └── ai/                   本地 AI 调查员 + 工具函数
│   ├── tests/                    pytest 测试套件
│   └── requirements.txt
├── frontend/
│   ├── dashboard/                开箱即用的静态安全指挥中心（HTML/CSS/JS）
│   └── web-nextjs/               Next.js + React + TypeScript 参考前端
└── deploy/
    ├── docker-compose.yml        （仓库根目录）
    └── k8s/                      Kubernetes Deployment/DaemonSet/HPA 清单
```

### 安装步骤

**环境要求：** Python 3.10 及以上版本；Node.js 18 及以上版本（仅在构建 Next.js 前端时需要）；若需使用真正的内核级 eBPF 采集器，则需要支持 BPF 的 Linux 内核及 `bcc` 软件包（其余部分可在任意操作系统上运行）。

```bash
# 1. 进入项目的 backend 目录
cd echobound/backend

# 2. 创建并激活虚拟环境（推荐）
python3 -m venv .venv
source .venv/bin/activate          # Windows 系统: .venv\Scripts\activate

# 3. 安装 Python 依赖
pip install -r requirements.txt

# 4.（仅限 Linux，可选，仅在需要真正的内核级 eBPF 采集器时安装）
sudo apt install bpfcc-tools python3-bpfcc   # Debian/Ubuntu
# 或： sudo dnf install bcc-tools python3-bcc  # Fedora

# 5. 启动 API 服务器
python -m echobound.main
# → http://localhost:8088   （接口文档位于 /docs）

# 6. 打开仪表盘（在另一个终端窗口 / 浏览器中）
cd ../frontend/dashboard
python3 -m http.server 8089
# → 打开 http://localhost:8089，如需要可在"设置"中修改 API 地址

# 7.（可选）生成一个合成安全世界，以便立即在界面中探索
curl -X POST http://localhost:8088/api/v1/synthetic/generate \
  -H "Content-Type: application/json" -d '{"seed":42,"tenant":"default"}'

# 8.（可选）运行自动化测试套件
cd ../../backend
pytest -q

# 9.（可选）将 CLI 安装为可执行命令
pip install -e .
echobound --help
```

**Docker（后端与仪表盘一起启动）：**

```bash
docker compose up --build
# API：    http://localhost:8088
# 仪表盘：  http://localhost:8089
```

**Next.js 参考前端（可选）：**

```bash
cd frontend/web-nextjs
npm install
npm run dev
# → http://localhost:3000
```

### 配置营业时间（无需编写代码）

打开仪表盘 → **设置 → 营业时间**。输入您的时区、开始/结束时间以及营业的星期几，点击 **快速设置**，系统会立即显示您当前是 **营业中**、**已关闭** 还是处于 **维护窗口** 中，并实时倒计时显示距下一次状态变化的时间。该配置会被漂移引擎的计划边界漂移检测器自动使用，也可通过 `POST /api/v1/context/operating-hours/quick-setup` 接口及 `echobound operating-hours` 命令以相同方式访问。

### 主题与语言

指挥中心内置五种主题（Windows 11 浅色、Windows 11 深色、AMOLED 纯黑、绯红主题、天蓝主题）和三种语言（English、فارسی、中文），并为波斯语正确实现从右到左（RTL）布局、为英文/中文实现从左到右（LTR）布局——均可在"设置"中随时切换，无需刷新页面。

### 许可证

本项目基于 Apache License 2.0 许可证发布——详见 `LICENSE` 文件。
