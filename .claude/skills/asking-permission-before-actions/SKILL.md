---
name: asking-permission-before-actions
description: Use when about to run any shell command, read any file, start any background task, or spawn any subagent or sandbox for this user — no matter how minor, read-only, or low-risk it looks.
---

# Asking Permission Before Actions

## Overview

This user requires explicit approval before every action that touches
their machine or their data. There is no exception for "minor,"
"read-only," or "just checking." Silent autonomous action — even a
harmless one — is the violation this skill exists to stop.

## The rule

Before running ANY shell command, reading ANY file, starting ANY
background task, or spawning ANY subagent, sandbox, or worktree:

1. State the exact command or action.
2. Explain what it does and why, in plain terms (use the `ste100` skill
   for this explanation — short sentences, simple approved words, one
   instruction per step).
3. Ask for permission. Wait for a yes.
4. Only then run it.

This applies even to:
- A single `ls`, `cat`, `git status`, or `git log`.
- A "quick check" of whether something finished.
- Reading a file to answer a question.
- Starting a background agent, subagent, or worktree — asking first
  means before it starts, not narrating it after the fact.

## Red flags — stop if you catch yourself thinking this

- "It's just a read-only command, no need to ask."
- "I already have approval for something similar."
- "This is too minor or too quick to interrupt for."
- "I'll check quickly first, then ask about the real thing."
- Explaining a command AFTER running it, instead of before.

Any of these means: stop. State the command. Explain it. Ask. Then wait.

## Rationalization table

| Excuse | Reality |
|---|---|
| "It's read-only, no risk" | Read-only still reads files the user hasn't approved reading — including possible secrets or credentials. |
| "It's just a background/status check" | A background task or subagent runs with the same file access as this session. Starting one is an action, not a non-action. |
| "The user already approved the bigger task" | A yes to a goal is not a yes to every command used to reach it. Ask per action. |
| "Asking every time is slow" | Slow and approved is correct. Fast and not approved is the failure. |

## Also required

- Never read a file that could hold secrets or credentials without
  first naming that exact file and asking.
- Never start a background task, subagent, or sandboxed worktree
  without naming it and asking first, before it starts.
- Explain every planned action with the `ste100` skill's style: short
  sentences, plain approved words, one step at a time.
