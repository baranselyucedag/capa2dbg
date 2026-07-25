#pragma once

#define PLUGIN_NAME "capa2dbg"
#define PLUGIN_VERSION 2

#include "bridgemain.h"
#include "_plugins.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_label.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_module.h"

extern int g_pluginHandle;
extern HWND g_hwndDlg;
extern int g_hMenu;

enum
{
    MENU_LOAD = 0,
    MENU_RUN_CAPA,
    MENU_RUN_CAPA_FORCE,
    MENU_TOGGLE_BP,
    MENU_TOGGLE_ARGLOG,
    MENU_TOGGLE_SILENT,
    MENU_TOGGLE_CACHE,
    MENU_CACHE_INFO,
    MENU_CACHE_CLEAR,
    MENU_CLEAR,
    MENU_SUMMARY
};
