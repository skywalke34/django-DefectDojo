# Universal Parser V2 - Continuation Prompt

**Saved**: 2025-11-27 (after Conversation 1.2)
**Time**: ~11:00 PM PST

---

## Continuation Prompt for Next Session

```
Continue UP V2 - Starting Conversation 1.3 (State Machines & Conditional Logic).

Current state:
- Branch: upV2-1.2-priority-chains (continue in same branch OR merge to dev first)
- Last commit: 8d493fe6a7 - feat: Add priority chain extraction with source_fields
- Private repo: https://github.com/skywalke34/universal-parser-v2 (code backed up)
- All 108 tests passing

Read the master plan at ~/.claude/plans/delegated-splashing-barto.md
Read yaml_config.py to see current schema with template + source_fields support.

Focus: Design state machine and conditional logic syntax.

Patterns to support from master plan:
- Pattern #6: Status state machine (Trivy's 8 states → multiple boolean outputs)
- Pattern #2: Conditional append (append-if-present for description building)
- Pattern #14: Fixed/constant values (Ggshield: severity="High", cwe=798)

Key files to modify:
- universal-parser-v2/app/models/yaml_config.py (add state_machine, conditionals, fixed_value)
- universal-parser-v2/app/services/normalizer.py (implement new extraction types)
- universal-parser-v2/tests/ (add tests for each pattern)

Ask about branch management before starting.
```

---

## Milestone 1 Progress

| Conversation | Topic | Status | Commit |
|--------------|-------|--------|--------|
| 1.1 | Template Strings | ✅ Complete | 818aabd02e |
| 1.2 | Priority Chains | ✅ Complete | 8d493fe6a7 |
| 1.3 | State Machines & Conditionals | ⏳ Next | - |

---

## What Was Completed in Conversation 1.2

### Features Added
- `source_fields: List[str]` for priority chain extraction (first-available semantics)
- `_extract_first_available()` method in normalizer
- `get_source_fields_list()` helper for unified extraction
- Fixed README architecture diagram to show both user inputs clearly

### Files Changed
- `app/models/yaml_config.py` - Added source_fields field and validation
- `app/services/normalizer.py` - Added priority chain extraction logic
- `tests/test_priority_chains.py` - NEW: 24 tests
- `docs/PARSER_CONFIG.md` - Added source_fields documentation
- `README.md` - Fixed architecture diagram

### Test Count
- 108 tests passing (84 original + 24 new)

---

## Key Patterns Still to Implement (Conversation 1.3)

### Pattern #6: Status State Machine
Trivy maps 8 states to multiple output fields:
- "not_affected" → active=False, verified=True, is_mitigated=True
- "false_positive" → false_p=True, active=False
- "affected" → active=True, verified=True

### Pattern #2: Conditional Append
Description templates with conditional sections:
- Base description from primary field
- Conditional append: "**Target:** {target}" (if present)

### Pattern #14: Fixed Values
All findings get hardcoded values:
- Ggshield: severity="High", cwe=798
