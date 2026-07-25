#pragma once

#include "capa_model.h"
#include <string>

bool LoadCapaJson(const char* path, CapaResult& out);
bool LoadCapaJsonFromString(const std::string& text, CapaResult& out);
