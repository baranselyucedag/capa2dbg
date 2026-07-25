#pragma once

#include "capa_model.h"

// Runtime toggles (menu-driven)
extern bool g_argLogging; // default true: set log text on call BPs
extern bool g_bpSilent;   // default true: breakcondition=0 (log-only)

void ApplyCapa(const CapaResult& res, bool bpCriticalOnly);
void ClearCapaMarks();
void PrintLastSummary();
