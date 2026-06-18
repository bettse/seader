#include "ui_memory_policy.h"

bool seader_ui_memory_should_release_submenu(SeaderUiMemoryPhase phase) {
    return phase == SeaderUiMemoryPhaseHfReadActive;
}
