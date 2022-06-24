#include "bolos_target.h"

#include "ui.h"

#include "exception.h"
#include "globals.h"
#include "glyphs.h" // ui-menu
#include "keys.h"
#include "memory.h"
#include "os_cx.h" // ui-menu
#include "to_string.h"

#include <stdbool.h>
#include <string.h>


#define G global.ui

void ui_refresh(void) {
    ux_stack_display(0);
}

// CALLED BY THE SDK
unsigned char io_event(unsigned char channel);

unsigned char io_event(__attribute__((unused)) unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID && !(U4BE(G_io_seproxyhal_spi_buffer, 3) & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
        // no break is intentional
        fallthrough;
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void ui_cfg_screen(size_t);
void ui_initial_screen(void);

void switch_sign_hash_cb(void) {
    nvram_data data;
    memcpy(&data, &N_data, sizeof(nvram_data));

    switch (data.sign_hash_policy) {
    case WARN_ON_SIGN_HASH:
        data.sign_hash_policy = DISALLOW_ON_SIGN_HASH;
        strcpy(data.sign_hash_policy_prompt, "Disallow");
        break;
    case DISALLOW_ON_SIGN_HASH:
        data.sign_hash_policy = ALLOW_ON_SIGN_HASH;
        strcpy(data.sign_hash_policy_prompt, "Allow");
        break;
    case ALLOW_ON_SIGN_HASH:
        data.sign_hash_policy = WARN_ON_SIGN_HASH;
        strcpy(data.sign_hash_policy_prompt, "Allow with warning");
        break;
    }

    nvm_write((void*)&N_data, (void*)&data, sizeof(N_data));

    ui_cfg_screen(0);
}

UX_STEP_CB(
    ux_cfg_flow_1_step,
    bn,
    switch_sign_hash_cb(),
    {
      "Sign hash policy",
      N_data_real.sign_hash_policy_prompt
    });
UX_STEP_CB(
    ux_cfg_flow_2_step,
    bn,
    ui_initial_screen(),
    {
      "Main menu",
      ""
    });
UX_FLOW(ux_cfg_flow,
        &ux_cfg_flow_1_step,
        &ux_cfg_flow_2_step);


UX_STEP_NOCB(
    ux_idle_flow_1_step,
    bn,
    {
      "Avalanche",
      VERSION
    });
UX_STEP_CB(
    ux_idle_flow_cfg_step,
    bn,
    ui_cfg_screen(0),
    {
      "Configuration",
      ""
    });
UX_STEP_CB(
    ux_idle_flow_quit_step,
    pb,
    exit_app(),
    {
      &C_icon_dashboard_x,
      "Quit",
    });

UX_FLOW(ux_idle_flow,
    &ux_idle_flow_1_step,
    &ux_idle_flow_cfg_step,
    &ux_idle_flow_quit_step
);

// prompt
#define PROMPT_SCREEN_NAME(idx) ux_prompt_flow_ ## idx ## _step
#define EVAL(...) __VA_ARGS__
#define BLANK()
#define PROMPT_SCREEN_TPL(idx) \
    EVAL(UX_STEP_NOCB_INIT BLANK() ( \
        PROMPT_SCREEN_NAME(idx), \
        bnnn_paging, \
        G.switch_screen(idx-G.prompt.offset),\
        { \
            .title = G.prompt.active_prompt, \
            .text = G.prompt.active_value, \
        }))

PROMPT_SCREEN_TPL(0);
PROMPT_SCREEN_TPL(1);
PROMPT_SCREEN_TPL(2);
PROMPT_SCREEN_TPL(3);
PROMPT_SCREEN_TPL(4);
PROMPT_SCREEN_TPL(5);
PROMPT_SCREEN_TPL(6);

static void prompt_response(bool const accepted) {
    ui_initial_screen();
    if (accepted) {
        G.ok_callback();
    } else {
        G.cxl_callback();
    }
}

UX_STEP_CB(
    ux_prompt_flow_accept_step,
    pb,
    prompt_response(true),
    {
        &C_icon_validate_14,
        G.accept_prompt_str
    });

UX_STEP_CB(
    ux_prompt_flow_reject_step,
    pb,
    prompt_response(false),
    {
        &C_icon_crossmark,
        "Reject"
    });

UX_FLOW(ux_prompts_flow,
    &PROMPT_SCREEN_NAME(0),
    &PROMPT_SCREEN_NAME(1),
    &PROMPT_SCREEN_NAME(2),
    &PROMPT_SCREEN_NAME(3),
    &PROMPT_SCREEN_NAME(4),
    &PROMPT_SCREEN_NAME(5),
    &PROMPT_SCREEN_NAME(6),
    &ux_prompt_flow_reject_step,
    &ux_prompt_flow_accept_step
);
_Static_assert(NUM_ELEMENTS(ux_prompts_flow) - 3 /*reject + accept + end*/ == MAX_SCREEN_COUNT, "ux_prompts_flow doesn't have the same number of screens as MAX_SCREEN_COUNT");

void ui_initial_screen(void) {

    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);

}

void switch_screen(uint32_t which) {
    if (which >= MAX_SCREEN_COUNT)
        THROW(EXC_MEMORY_ERROR);
    const char *label = (const char *)PIC(global.ui.prompt.prompts[which]);
    strncpy(global.ui.prompt.active_prompt, label, sizeof(global.ui.prompt.active_prompt));
    global.ui.prompt.active_prompt[sizeof(global.ui.prompt.active_prompt) - 1] = 0;
    if (global.ui.prompt.callbacks[which] == NULL)
        THROW(EXC_MEMORY_ERROR);
    check_null(global.ui.prompt.active_value);
    check_null(global.ui.prompt.callback_data[which]);
    global.ui.prompt.callbacks[which](global.ui.prompt.active_value, sizeof(global.ui.prompt.active_value),
                                      global.ui.prompt.callback_data[which]);
}

void ui_prompt_debug(size_t screen_count) {
    for(uint32_t i = 0; i < screen_count; i++) {
        G.switch_screen(i);
        PRINTF("Prompt %d:\n%s\n%s\n", i, global.ui.prompt.active_prompt, global.ui.prompt.active_value);
    }
}

__attribute__((noreturn))
void ui_prompt_with(uint16_t const exception, char const *const accept_str, char const *const *labels, ui_callback_t ok_c, ui_callback_t cxl_c) {
    check_null(labels);
    check_null(accept_str);
    global.ui.prompt.prompts = labels;

    size_t const screen_count = ({
        size_t i = 0;
        while (i < MAX_SCREEN_COUNT && labels[i] != NULL) { i++; }
        i;
    });

    G.switch_screen = switch_screen;
    // We fill the destination buffers at the end instead of the beginning so we can
    // use the same array for any number of screens.
    // size_t const offset = MAX_SCREEN_COUNT - screen_count;

    G.switch_screen = switch_screen;
    G.prompt.offset = MAX_SCREEN_COUNT - screen_count;
    strncpy(G.accept_prompt_str, accept_str, sizeof(G.accept_prompt_str));

    ui_prompt_debug(screen_count);

    G.ok_callback = ok_c;
    G.cxl_callback = cxl_c;
    ux_flow_init(0, &ux_prompts_flow[G.prompt.offset], NULL);

#ifdef AVA_DEBUG
    // In debug mode, the THROW below produces a PRINTF statement in an invalid position and causes the screen to blank,
    // so instead we just directly call the equivalent longjmp for debug only.
    longjmp(try_context_get()->jmp_buf, exception);
#else
    THROW(exception);
#endif
}

void ui_cfg_screen(size_t i) {
    // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_cfg_flow, ux_cfg_flow[i]);
}

__attribute__((noreturn))
void ui_prompt(const char *const *labels, ui_callback_t ok_c, ui_callback_t cxl_c) {
    ui_prompt_with(ASYNC_EXCEPTION, "Accept", labels, ok_c, cxl_c);
}

__attribute__((noreturn)) void ui_prompt_with_cb(void (*switch_screen_cb)(uint32_t), size_t screen_count, ui_callback_t ok_c, ui_callback_t cxl_c) {
    check_null(switch_screen_cb);

    G.switch_screen = switch_screen_cb;
    G.prompt.offset = MAX_SCREEN_COUNT - screen_count;

    G.ok_callback = ok_c;
    G.cxl_callback = cxl_c;
    ux_flow_init(0, &ux_prompts_flow[G.prompt.offset], NULL);

#ifdef AVA_DEBUG
    ui_prompt_debug(screen_count);
    // In debug mode, the THROW below produces a PRINTF statement in an invalid position and causes the screen to blank,
    // so instead we just directly call the equivalent longjmp for debug only.
    longjmp(try_context_get()->jmp_buf, ASYNC_EXCEPTION);
#else
    THROW(ASYNC_EXCEPTION);
#endif
}
