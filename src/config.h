#pragma once

#include <string>

void LoadAllowlistConfig();
bool IsCriticalNamespace(const std::string& ns);
std::string CapaCategory(const std::string& ns);
std::string GetCapaPath();
bool LabelCategoryPrefixEnabled();

bool CacheEnabledConfig();
std::string CacheDirOverride();
int CacheMaxMb();
bool CacheAdoptManual();
