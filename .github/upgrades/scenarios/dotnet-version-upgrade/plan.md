# .NET Version Upgrade Plan

## Overview

**Target**: Upgrade all 10 projects from net8.0 to net10.0
**Scope**: 10 projects (6 libraries, 1 app, 3 test projects), ~175 issues identified

### Selected Strategy
**All-At-Once** — All projects upgraded simultaneously in a single operation.
**Rationale**: 10 projects, all on net8.0, straightforward upgrade with mostly behavioral/optional issues (15 mandatory out of 175 total).

## Tasks

### 01-update-tfms: Update target frameworks and global.json

Update all project files to target net10.0. Update global.json if present to require the .NET 10 SDK.

**Done when**: All 10 .csproj files target net10.0 and any global.json references .NET 10 SDK.

---

### 02-update-packages: Update NuGet package references

Update all NuGet packages to versions compatible with net10.0. Address deprecated packages in test projects and recommended upgrades across the solution.

**Done when**: All packages reference net10.0-compatible versions, no deprecated packages remain, `dotnet restore` succeeds.

---

### 03-fix-build-issues: Fix compilation and API compatibility issues

Resolve mandatory breaking changes (Api.0001 binary incompatibilities, Api.0002 source incompatibilities) and behavioral changes (Api.0003) flagged in the assessment. Primary areas: Demo project (5 mandatory), Fido2.AspNet (2 mandatory), and Fido2 core library.

**Done when**: Solution builds with zero errors.

---

### 04-run-tests: Validate all tests pass

Run the full test suite to confirm the upgrade hasn't broken functionality.

**Done when**: All tests pass.
