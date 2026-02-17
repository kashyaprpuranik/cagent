# Repo Separation Plan

Split the current monorepo into three repositories:

| Repo | Visibility | Contents |
|------|-----------|----------|
| **cagent** | Public | Data plane (proxy, DNS filter, agent-manager, email proxy) |
| **cagent-control** | Private | Control plane (API, frontend, DB, e2e tests, full-stack orchestration) |
| **cagent-ui** | Public | Shared React components consumed by both frontends |

## Current Structure

```
cagent/                          (monorepo)
├── control_plane/               → cagent-control
├── data_plane/                  → stays in cagent
├── packages/shared-ui/          → cagent-ui
├── e2e/                         → cagent-control/e2e
├── docs/
│   ├── configuration.md         → split (standalone sections stay, CP sections move)
│   ├── development.md           → split (CP dev moves, DP dev stays)
│   └── technical-review.md      → cagent-control (covers full architecture)
├── dev_up.sh                    → split (full-stack moves to CP, DP-only stays)
├── run_tests.sh                 → split (each repo gets its own)
├── CLAUDE.md                    → split (each repo gets its own)
├── README.md                    → rewrite (DP-only, link to cagent-control)
├── .dockerignore                → simplify (DP-only)
├── .gitignore                   → keep as-is
├── package.json                 → rewrite (DP workspace only)
└── .github/ISSUE_TEMPLATE/      → duplicate in both repos
```

## 1. Create cagent-ui Repo

Tiny repo with shared React components. Both frontends depend on it via git URL.

### Files (from `packages/shared-ui/`)

```
cagent-ui/
├── package.json               # name: @cagent/ui (renamed from @cagent/shared-ui)
├── tsconfig.json
├── tailwind.preset.js
├── src/
│   ├── index.ts
│   └── components/
│       ├── Badge.tsx
│       ├── BandwidthWidget.tsx
│       ├── BlockedDomainsWidget.tsx
│       ├── BlockedTimeseriesChart.tsx
│       ├── Button.tsx
│       ├── Card.tsx
│       ├── DiagnoseModal.tsx
│       ├── Input.tsx
│       ├── Modal.tsx
│       ├── Select.tsx
│       ├── Table.tsx
│       └── Toast.tsx
├── .gitignore
└── README.md
```

### Changes

- Rename package from `@cagent/shared-ui` to `@cagent/ui` in `package.json`
- Add a minimal README describing the component library
- Add `.gitignore` (node_modules/, dist/)

### Downstream Updates

Both frontends update their dependency:

```json
// Before (npm workspace link)
"@cagent/shared-ui": "*"

// After (git URL, pinned to commit)
"@cagent/ui": "github:kashyaprpuranik/cagent-ui#<commit>"
```

All imports change: `@cagent/shared-ui` → `@cagent/ui` (in both CP and DP frontend source).

## 2. Create cagent-control Repo

Private repo with control plane, e2e tests, and full-stack orchestration.

### Structure

```
cagent-control/
├── services/
│   ├── backend/                 # from control_plane/services/backend/
│   │   ├── control_plane/       # FastAPI app, routes, models, auth
│   │   ├── seed.py
│   │   ├── post_seed.py
│   │   ├── requirements.txt
│   │   ├── requirements-test.txt
│   │   └── tests/
│   └── frontend/                # from control_plane/services/frontend/
│       ├── src/
│       ├── package.json         # updated: @cagent/ui via git URL
│       └── ...
├── e2e/                         # from e2e/
│   ├── run_tests.sh             # updated: expects ../cagent sibling
│   ├── docker-compose.e2e.yml   # updated: paths reference ../cagent
│   ├── test_cp_dp_e2e.py
│   ├── echo-server.py
│   └── DEBUGGING.md
├── configs/
│   └── frps/                    # from control_plane/configs/frps/
├── docs/
│   ├── development.md           # CP dev guide (from docs/development.md, CP sections)
│   ├── configuration.md         # CP config guide (from docs/configuration.md, CP sections)
│   └── technical-review.md      # from docs/technical-review.md (full, covers both)
├── docker-compose.yml           # from control_plane/docker-compose.yml
├── dev_up.sh                    # full-stack orchestration (from root dev_up.sh)
├── run_tests.sh                 # CP tests + e2e (from root run_tests.sh, CP parts)
├── .env.example                 # from control_plane/.env.example
├── .dockerignore                # new, CP-specific
├── .gitignore
├── CLAUDE.md                    # new, CP-focused
├── README.md                    # from control_plane/README.md (expanded)
└── package.json                 # npm workspace: services/frontend
```

### Key Changes

#### Flatten control_plane/ to repo root

The `control_plane/` subdirectory becomes the repo root. All paths inside docker-compose.yml, Dockerfiles, and scripts drop the `control_plane/` prefix.

#### e2e tests expect sibling DP checkout

`e2e/run_tests.sh` changes:

```bash
# Before
DP_DIR="$ROOT_DIR/data_plane"

# After
DP_DIR="${CAGENT_DP_DIR:-$(cd "$ROOT_DIR/.." && pwd)/cagent}"
if [ ! -d "$DP_DIR/data_plane" ]; then
    echo "ERROR: Data plane repo not found at $DP_DIR"
    echo "Clone it: git clone https://github.com/kashyaprpuranik/cagent.git $DP_DIR"
    exit 1
fi
```

`e2e/docker-compose.e2e.yml` paths update:

```yaml
# Before
- ../data_plane/configs/cagent.yaml:/etc/cagent/cagent.yaml

# After (relative to cagent-control root)
- ${CAGENT_DP_DIR:-../../cagent}/data_plane/configs/cagent.yaml:/etc/cagent/cagent.yaml
```

#### dev_up.sh expects sibling DP checkout

```bash
# Before
CP_DIR="$ROOT_DIR/control_plane"
DP_DIR="$ROOT_DIR/data_plane"

# After
CP_DIR="$ROOT_DIR"
DP_DIR="${CAGENT_DP_DIR:-$(cd "$ROOT_DIR/.." && pwd)/cagent}/data_plane"
```

When running `--dp-only`, it tells the user to use the DP repo directly instead.

#### Frontend dependency update

`services/frontend/package.json`:

```json
{
  "dependencies": {
    "@cagent/ui": "github:kashyaprpuranik/cagent-ui#<commit>"
  }
}
```

All source imports: `@cagent/shared-ui` → `@cagent/ui`.

#### docker-compose.yml build context

The CP frontend Dockerfile currently references `packages/shared-ui` via npm workspace. After the split, the frontend installs `@cagent/ui` from git, so the build context no longer needs the workspace root. The Dockerfile can use `services/frontend/` as its build context directly.

#### .dockerignore (new)

```
*
!services/
!services/**
!configs/
!configs/**
**/node_modules
**/dist
**/.git
```

#### CLAUDE.md (new, CP-focused)

Covers:
- CP architecture (API, DB, Redis, frontend, FRP server)
- Backend conventions (FastAPI, SQLAlchemy, auth, multi-tenancy)
- Testing (pytest fixtures, test tokens, mocking)
- Frontend conventions
- e2e test setup (sibling DP checkout)
- Important files and gotchas

#### README.md (expanded from control_plane/README.md)

Add:
- Overview explaining relationship to cagent (DP) repo
- Full-stack setup instructions (requires sibling DP checkout)
- Link to DP repo for standalone usage

## 3. Update cagent (DP) Repo

Remove control plane, e2e, and update references.

### Files to Remove

```
control_plane/                   # entire directory
e2e/                             # entire directory
packages/                        # entire directory (shared-ui moved to cagent-ui)
docs/development.md              # CP-heavy, replaced with DP-focused version
docs/technical-review.md         # full-stack review, moves to CP
```

### Files to Update

#### package.json (root)

```json
{
  "private": true,
  "workspaces": [
    "data_plane/services/local_admin/frontend"
  ]
}
```

Single workspace. The DP frontend's `package.json` updates its dependency from `@cagent/shared-ui` to `@cagent/ui` via git URL.

#### .dockerignore

Simplify — remove CP frontend allowlist entries:

```
*
!package.json
!package-lock.json
!data_plane/services/local_admin/
!data_plane/services/local_admin/**
!data_plane/services/agent_manager/
!data_plane/services/agent_manager/**
**/node_modules
**/dist
**/.git
**/*.md
**/.env*
**/__pycache__
**/*.pyc
```

#### README.md

Rewrite for DP-only. Remove all CP architecture diagrams and setup instructions. Add:
- Note that cagent-control is available separately for centralized management
- Link to cagent-control for CP setup and full-stack deployment
- Keep standalone and auditing sections as-is
- Simplify "Control Plane Mode" section to just reference cagent-control

#### CLAUDE.md

Remove all CP sections:
- CP backend conventions, routes, models, auth
- CP testing (fixtures, conftest)
- CP frontend references
- CP important files
- Full-stack orchestration references

Keep:
- DP architecture, conventions, testing
- Docker/infrastructure section (networks, profiles, config generation)
- Data flow
- DP important files and gotchas

#### dev_up.sh

Becomes DP-only. Remove `--cp-only` and full-stack orchestration:

```bash
# Before
./dev_up.sh                     # Full stack: CP + DP
./dev_up.sh --cp-only           # Control plane only
./dev_up.sh --dp-only           # Data plane only
./dev_up.sh --dp-only --admin   # Data plane with admin UI

# After
./dev_up.sh                     # Data plane (standalone with admin UI)
./dev_up.sh --admin             # Same (default includes admin)
./dev_up.sh --minimal           # Minimal (no agent-manager)
./dev_up.sh down                # Stop everything
```

Remove all CP_DIR references, SEED_AGENT_TOKEN, CP compose commands.

#### run_tests.sh

Becomes DP-only. Remove `--cp`, `--cp-dp-e2e` flags:

```bash
# Before
./run_tests.sh                  # CP + DP tests + frontend
./run_tests.sh --cp             # CP backend tests
./run_tests.sh --cp-dp-e2e      # CP+DP integration tests

# After
./run_tests.sh                  # DP unit/config tests + frontend type-check
./run_tests.sh --e2e            # Include DP standalone e2e
./run_tests.sh --frontend       # Frontend type-check only
```

#### docs/configuration.md

Remove CP sections:
- "Connected Mode: Control Plane" (section starting at line 52)
- "Agent Management" (line 162) — CP-specific agent commands
- "Per-Agent Configuration" (line 191) — CP API
- "Log Querying" (line 308) — CP log store

Keep:
- "Standalone Mode: cagent.yaml"
- "Domain Policy Fields" (shared reference)
- "Path Filtering", "Credential Injection"
- "SSH Access" (DP feature)

Add:
- Note linking to cagent-control for connected mode configuration

#### docs/development.md

Rewrite for DP-only:
- Remove "Quick Start" (CP dev_up.sh), "Database Seeding", "API Testing with curl"
- Remove CP sections from "Local Development", "Docker Development"
- Keep DP testing, DP Docker commands, directory structure
- Update directory structure tree to remove control_plane/

#### data_plane/services/local_admin/frontend/package.json

```json
{
  "dependencies": {
    "@cagent/ui": "github:kashyaprpuranik/cagent-ui#<commit>"
  }
}
```

Update all imports in frontend source files: `@cagent/shared-ui` → `@cagent/ui`.

## 4. Execution Order

### Phase 1: Create cagent-ui (no breaking changes)

1. Create `cagent-ui` repo on GitHub (public)
2. Copy `packages/shared-ui/` contents to repo root
3. Rename package to `@cagent/ui` in package.json
4. Add README.md and .gitignore
5. Push initial commit, note the commit hash

### Phase 2: Update both frontends to use cagent-ui (still in monorepo)

1. Update DP frontend (`data_plane/services/local_admin/frontend/package.json`): replace `@cagent/shared-ui` workspace dependency with `@cagent/ui` git URL
2. Update CP frontend (`control_plane/services/frontend/package.json`): same change
3. Find-and-replace all imports: `@cagent/shared-ui` → `@cagent/ui` in both frontend source directories
4. Update root `package.json`: remove `packages/shared-ui` from workspaces
5. Run `npm install` to regenerate lock file
6. Run frontend type-check (`npx tsc --noEmit`) for both frontends
7. Run full test suite to verify nothing broke
8. Commit: "Migrate shared-ui to external @cagent/ui package"

### Phase 3: Create cagent-control repo

1. Create `cagent-control` repo on GitHub (private)
2. Copy files according to the structure in section 2
3. Flatten `control_plane/` to repo root (update all internal paths)
4. Update `e2e/run_tests.sh` and `e2e/docker-compose.e2e.yml` for sibling checkout
5. Update `dev_up.sh` for sibling checkout
6. Write new `CLAUDE.md` (CP-focused)
7. Expand `README.md` with full-stack setup instructions
8. Split docs (configuration.md, development.md; copy technical-review.md)
9. Create `.dockerignore`
10. Run CP backend tests: `cd services/backend && pytest tests/ -v`
11. Run CP frontend type-check: `cd services/frontend && npx tsc --noEmit`
12. Run e2e tests with sibling checkout: `./e2e/run_tests.sh` (requires DP at `../cagent`)
13. Push initial commit

### Phase 4: Clean up cagent (DP) repo

1. Remove `control_plane/`, `e2e/`, `packages/`
2. Update `README.md` (DP-only, link to cagent-control)
3. Update `CLAUDE.md` (remove CP sections)
4. Update `dev_up.sh` (DP-only)
5. Update `run_tests.sh` (remove CP and e2e flags)
6. Update `docs/configuration.md` (remove CP sections)
7. Rewrite `docs/development.md` (DP-only)
8. Remove `docs/technical-review.md` (moved to CP)
9. Simplify `.dockerignore` (remove CP allowlist entries)
10. Update root `package.json` (single workspace)
11. Run `npm install` to regenerate lock file
12. Run full DP test suite: `./run_tests.sh`
13. Run DP e2e tests: `./run_tests.sh --e2e`
14. Commit: "Remove control plane (moved to cagent-control)"

## 5. Cross-Repo Development Workflow

### Local Setup (Full Stack)

```bash
# Clone all three repos as siblings
git clone https://github.com/kashyaprpuranik/cagent.git
git clone https://github.com/kashyaprpuranik/cagent-control.git  # private
git clone https://github.com/kashyaprpuranik/cagent-ui.git

# Full stack dev (from CP repo)
cd cagent-control
./dev_up.sh                 # starts CP + DP (expects ../cagent)

# DP standalone dev (from DP repo)
cd cagent
./dev_up.sh                 # starts DP only

# Run CP+DP e2e tests
cd cagent-control
./e2e/run_tests.sh          # expects ../cagent
```

### Updating Shared UI

```bash
cd cagent-ui
# Make changes, commit, push
# Note the new commit hash

# Update DP frontend
cd ../cagent
# Update git URL hash in data_plane/services/local_admin/frontend/package.json
npm install

# Update CP frontend
cd ../cagent-control
# Update git URL hash in services/frontend/package.json
npm install
```

### Future: Published Images

When ready to eliminate the sibling checkout requirement for e2e tests:

1. Set up GitHub Actions in `cagent` to build and push DP images to GHCR on every push to main
2. Update `cagent-control/e2e/run_tests.sh` to pull images from `ghcr.io/kashyaprpuranik/cagent-*` when sibling checkout is not available
3. Tag DP images with commit hash for reproducibility

## 6. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Breaking e2e tests during migration | Run e2e tests at each phase before committing |
| Stale shared-ui version in one frontend | Pin to commit hash, update both frontends together |
| npm install slower with git URL dependency | Acceptable for a small package; npm caches git deps |
| Developer forgets to clone sibling repo | dev_up.sh and e2e/run_tests.sh check for sibling and print clone instructions |
| CP Dockerfile build context changes | Test Docker build in phase 3 before pushing |
| Divergent docs after split | technical-review.md stays in CP as single source of truth for full architecture |
