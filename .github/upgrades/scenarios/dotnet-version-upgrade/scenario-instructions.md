# .NET Version Upgrade

## Strategy
**Selected**: All-At-Once
**Rationale**: 10 projects, all net8.0, straightforward upgrade (15 mandatory issues out of 175 total)

### Execution Constraints
- Single atomic upgrade — all projects updated together
- Validate full solution build after TFM + package updates
- Run full test suite after build succeeds

## Preferences
- **Flow Mode**: Automatic
- **Commit Strategy**: Single Commit at End
- **Target Framework**: net10.0
- **Source branch**: feature/ml-dsa (in-place, no working branch)

## Decisions
- In-place upgrade on feature/ml-dsa, no separate working branch — user will git rollback if needed

## Custom Instructions

