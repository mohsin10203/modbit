package id

// Prefix registry.
//
// Every Modbit entity family owns exactly one prefix, declared here and nowhere else. Prefixes are
// permanent: retiring an entity does not free its prefix for reuse (R-ID-02).
//
// Prefixes marked "wire-fixed" appear verbatim in api-and-events-v5.1.md and must not change.
//
// Entity families follow PRD v5.1 §33.1.
var (
	// Tenancy and identity.
	Organization    = Register("org", "Organization — top-level tenant") // wire-fixed
	Team            = Register("team", "Team within an organization")
	User            = Register("usr", "User")
	RoleBinding     = Register("rb", "Role binding")
	ServiceIdentity = Register("svc", "Service identity")
	SessionToken    = Register("stok", "Session token reference")

	// Project and source.
	Space              = Register("spc", "Space — durable project boundary") // wire-fixed
	Repository         = Register("repo", "Registered repository")
	RepositoryRevision = Register("rev", "Repository revision")
	Branch             = Register("brn", "Branch")
	Worktree           = Register("wtr", "Worktree")
	ContextSource      = Register("csrc", "Context source")
	IndexSnapshot      = Register("idxs", "Immutable index snapshot")
	IndexShard         = Register("shrd", "Index shard")
	ContextItem        = Register("citm", "Retrieved context item")
	DependencyEdge     = Register("dep", "Dependency graph edge")

	// CodeWiki.
	Wiki              = Register("wiki", "CodeWiki")
	WikiVersion       = Register("wikv", "CodeWiki version")
	WikiPage          = Register("wikp", "CodeWiki page")
	WikiCitation      = Register("wikc", "CodeWiki citation")
	WikiDiagram       = Register("wikd", "CodeWiki diagram")
	WikiGenerationJob = Register("wikj", "CodeWiki generation job")

	// Execution.
	Environment    = Register("env", "Environment definition")
	WorkerPool     = Register("wpool", "Worker pool")
	Worker         = Register("wrk", "Registered worker")
	WorkspaceLease = Register("wlease", "Workspace lease")
	WorkerLease    = Register("lease", "Signed worker lease")

	// Agent definitions.
	AgentProfile  = Register("prof", "Agent Profile")
	Rule          = Register("rule", "Rule")
	Skill         = Register("skl", "Skill")
	Workflow      = Register("wfl", "Workflow")
	Playbook      = Register("pbk", "Playbook")
	Plugin        = Register("plg", "Plugin")
	PluginVersion = Register("plgv", "Plugin version")
	MCPServer     = Register("mcp", "MCP server registration")
	Hook          = Register("hook", "Hook")

	// Runs.
	Run         = Register("run", "Run") // wire-fixed
	RunStep     = Register("step", "Run step")
	RunMessage  = Register("msg", "Run message")
	Checkpoint  = Register("ckpt", "Checkpoint")
	TraceEvent  = Register("evt", "Canonical event") // wire-fixed
	Correlation = Register("cor", "Correlation")     // wire-fixed
	TaskNode    = Register("task", "Task graph node")
	Delegation  = Register("dlg", "Delegated run link")
	Session     = Register("ses", "Human interaction session")

	// Outputs.
	Artifact   = Register("art", "Artifact") // wire-fixed
	Evidence   = Register("evd", "Evidence record")
	SharedFile = Register("shf", "Shared file")
	ObjectRef  = Register("obj", "Object-store payload reference") // wire-fixed

	// Policy and approval.
	Approval       = Register("apr", "Approval")
	Policy         = Register("pol", "Policy bundle")
	PolicyDecision = Register("pdec", "Policy decision") // wire-fixed

	// Automation.
	Automation    = Register("auto", "Automation")
	Trigger       = Register("trg", "Trigger")
	Subscription  = Register("sub", "Event subscription")
	ExternalEvent = Register("xevt", "Normalized external event")
	DeadLetter    = Register("dlq", "Dead-lettered event")

	// Inference.
	Provider           = Register("prv", "Model provider")
	Model              = Register("mdl", "Model")
	ModelPolicy        = Register("mpol", "Model routing policy")
	ModelCall          = Register("mcall", "Model call record")
	ProviderCredential = Register("pcred", "Provider credential reference")
	ProviderConnection = Register("pconn", "Provider connection")

	// Integrations and secrets.
	Integration           = Register("intg", "Integration")
	IntegrationCredential = Register("icred", "Integration credential reference")
	TaskSecret            = Register("tsec", "Task secret reference")
	SecretLease           = Register("slease", "Secret lease")

	// Review.
	Review          = Register("rvw", "Review")
	ReviewFinding   = Register("find", "Review or security finding")
	FindingFeedback = Register("fbk", "Finding feedback")

	// Usage and audit.
	UsageRecord = Register("use", "Usage record")
	Budget      = Register("bdg", "Budget")
	Quota       = Register("qta", "Quota")
	AuditEvent  = Register("aud", "Audit event")
	ExportJob   = Register("exp", "Export job")

	// Settings.
	SettingsDocument     = Register("setdoc", "Settings document")
	SettingsPolicy       = Register("setpol", "Settings policy")
	SettingsProfile      = Register("setprf", "Settings profile")
	SettingsSnapshot     = Register("setshot", "Settings snapshot") // wire-fixed
	SettingsSyncRevision = Register("setrev", "Settings sync revision")
	SettingsMigration    = Register("setmig", "Settings migration")

	// Environment blueprints.
	EnvironmentBlueprint = Register("blu", "Environment blueprint")
	EnvironmentSnapshot  = Register("snap", "Environment snapshot")
	SnapshotBuild        = Register("snapb", "Snapshot build")

	// Browser and desktop.
	BrowserSession     = Register("bses", "Browser session")
	BrowserAction      = Register("bact", "Browser action")
	ComputerUseSession = Register("cses", "Computer-use session")
	SessionInsight     = Register("insl", "Session insight")

	// Evaluation.
	Benchmark     = Register("bmk", "Benchmark")
	BenchmarkTask = Register("bmkt", "Benchmark task")
	EvalRun       = Register("evr", "Evaluation run")
	EvalResult    = Register("evres", "Evaluation result")

	// v5.1 additions.
	Memory                = Register("mem", "Tiered memory record")
	MemoryCorroboration   = Register("memc", "Memory corroboration entry")
	TaintEntry            = Register("tnt", "Taint ledger entry")
	Declassification      = Register("dcl", "Taint declassification")
	TrustState            = Register("trst", "Trust state")
	TrustEvent            = Register("trse", "Trust state change")
	CoordinationScope     = Register("cscope", "Coordination scope registration")
	CoordinationLock      = Register("clock", "Advisory coordination lock")
	CoordinationConflict  = Register("cconf", "Coordination conflict")
	RouteOutcome          = Register("rout", "Route outcome record")
	EvaluationGate        = Register("egate", "Evaluation gate state")
	Canary                = Register("cnry", "Provider-revision canary")
	AdequacyReport        = Register("adq", "Verification adequacy report")
	EvidenceExport        = Register("expo", "Evidence export record")
	CapabilityNegotiation = Register("capn", "Capability negotiation record")
)
