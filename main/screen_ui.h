/**
 * @file screen_ui.h
 * @brief Native ST7789 status UI for the penetration tool.
 *
 * @copyright Copyright (c) 2026 swtmaxx
 * @note MIT licensed, see LICENSE in the repository root.
 */
#ifndef SCREEN_UI_H
#define SCREEN_UI_H

/**
 * @brief Initialise display and start the UI render task.
 *
 * Must be called once from app_main.
 */
void screen_ui_init(void);

#endif /* SCREEN_UI_H */
