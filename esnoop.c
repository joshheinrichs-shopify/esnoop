#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Block.h>

typedef struct {
    const char *name;
    es_event_type_t type;
} event_map_t;

static const event_map_t EVENT_TABLE[] = {
    // Authorization Event Types
    {"auth_chdir", ES_EVENT_TYPE_AUTH_CHDIR},
    {"auth_chroot", ES_EVENT_TYPE_AUTH_CHROOT},
    {"auth_clone", ES_EVENT_TYPE_AUTH_CLONE},
    {"auth_copyfile", ES_EVENT_TYPE_AUTH_COPYFILE},
    {"auth_create", ES_EVENT_TYPE_AUTH_CREATE},
    {"auth_deleteextattr", ES_EVENT_TYPE_AUTH_DELETEEXTATTR},
    {"auth_exchangedata", ES_EVENT_TYPE_AUTH_EXCHANGEDATA},
    {"auth_exec", ES_EVENT_TYPE_AUTH_EXEC},
    {"auth_fcntl", ES_EVENT_TYPE_AUTH_FCNTL},
    {"auth_file_provider_materialize", ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE},
    {"auth_file_provider_update", ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE},
    {"auth_fsgetpath", ES_EVENT_TYPE_AUTH_FSGETPATH},
    {"auth_get_task", ES_EVENT_TYPE_AUTH_GET_TASK},
    {"auth_get_task_read", ES_EVENT_TYPE_AUTH_GET_TASK_READ},
    {"auth_getattrlist", ES_EVENT_TYPE_AUTH_GETATTRLIST},
    {"auth_getextattr", ES_EVENT_TYPE_AUTH_GETEXTATTR},
    {"auth_iokit_open", ES_EVENT_TYPE_AUTH_IOKIT_OPEN},
    {"auth_kextload", ES_EVENT_TYPE_AUTH_KEXTLOAD},
    {"auth_link", ES_EVENT_TYPE_AUTH_LINK},
    {"auth_listextattr", ES_EVENT_TYPE_AUTH_LISTEXTATTR},
    {"auth_mmap", ES_EVENT_TYPE_AUTH_MMAP},
    {"auth_mount", ES_EVENT_TYPE_AUTH_MOUNT},
    {"auth_mprotect", ES_EVENT_TYPE_AUTH_MPROTECT},
    {"auth_open", ES_EVENT_TYPE_AUTH_OPEN},
    {"auth_proc_check", ES_EVENT_TYPE_AUTH_PROC_CHECK},
    {"auth_proc_suspend_resume", ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME},
    {"auth_readdir", ES_EVENT_TYPE_AUTH_READDIR},
    {"auth_readlink", ES_EVENT_TYPE_AUTH_READLINK},
    {"auth_remount", ES_EVENT_TYPE_AUTH_REMOUNT},
    {"auth_rename", ES_EVENT_TYPE_AUTH_RENAME},
    {"auth_searchfs", ES_EVENT_TYPE_AUTH_SEARCHFS},
    {"auth_setacl", ES_EVENT_TYPE_AUTH_SETACL},
    {"auth_setattrlist", ES_EVENT_TYPE_AUTH_SETATTRLIST},
    {"auth_setextattr", ES_EVENT_TYPE_AUTH_SETEXTATTR},
    {"auth_setflags", ES_EVENT_TYPE_AUTH_SETFLAGS},
    {"auth_setmode", ES_EVENT_TYPE_AUTH_SETMODE},
    {"auth_setowner", ES_EVENT_TYPE_AUTH_SETOWNER},
    {"auth_settime", ES_EVENT_TYPE_AUTH_SETTIME},
    {"auth_signal", ES_EVENT_TYPE_AUTH_SIGNAL},
    {"auth_truncate", ES_EVENT_TYPE_AUTH_TRUNCATE},
    {"auth_uipc_bind", ES_EVENT_TYPE_AUTH_UIPC_BIND},
    {"auth_uipc_connect", ES_EVENT_TYPE_AUTH_UIPC_CONNECT},
    {"auth_unlink", ES_EVENT_TYPE_AUTH_UNLINK},
    {"auth_utimes", ES_EVENT_TYPE_AUTH_UTIMES},

    // Notification Event Types
    {"notify_access", ES_EVENT_TYPE_NOTIFY_ACCESS},
    {"notify_chdir", ES_EVENT_TYPE_NOTIFY_CHDIR},
    {"notify_chroot", ES_EVENT_TYPE_NOTIFY_CHROOT},
    {"notify_clone", ES_EVENT_TYPE_NOTIFY_CLONE},
    {"notify_close", ES_EVENT_TYPE_NOTIFY_CLOSE},
    {"notify_copyfile", ES_EVENT_TYPE_NOTIFY_COPYFILE},
    {"notify_create", ES_EVENT_TYPE_NOTIFY_CREATE},
    {"notify_cs_invalidated", ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED},
    {"notify_deleteextattr", ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR},
    {"notify_dup", ES_EVENT_TYPE_NOTIFY_DUP},
    {"notify_exchangedata", ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA},
    {"notify_exec", ES_EVENT_TYPE_NOTIFY_EXEC},
    {"notify_exit", ES_EVENT_TYPE_NOTIFY_EXIT},
    {"notify_fcntl", ES_EVENT_TYPE_NOTIFY_FCNTL},
    {"notify_file_provider_materialize", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE},
    {"notify_file_provider_update", ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE},
    {"notify_fork", ES_EVENT_TYPE_NOTIFY_FORK},
    {"notify_fsgetpath", ES_EVENT_TYPE_NOTIFY_FSGETPATH},
    {"notify_getattrlist", ES_EVENT_TYPE_NOTIFY_GETATTRLIST},
    {"notify_getextattr", ES_EVENT_TYPE_NOTIFY_GETEXTATTR},
    {"notify_get_task", ES_EVENT_TYPE_NOTIFY_GET_TASK},
    {"notify_get_task_read", ES_EVENT_TYPE_NOTIFY_GET_TASK_READ},
    {"notify_get_task_inspect", ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT},
    {"notify_get_task_name", ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME},
    {"notify_iokit_open", ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN},
    {"notify_kextload", ES_EVENT_TYPE_NOTIFY_KEXTLOAD},
    {"notify_kextunload", ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD},
    {"notify_link", ES_EVENT_TYPE_NOTIFY_LINK},
    {"notify_listextattr", ES_EVENT_TYPE_NOTIFY_LISTEXTATTR},
    {"notify_lookup", ES_EVENT_TYPE_NOTIFY_LOOKUP},
    {"notify_mmap", ES_EVENT_TYPE_NOTIFY_MMAP},
    {"notify_mount", ES_EVENT_TYPE_NOTIFY_MOUNT},
    {"notify_mprotect", ES_EVENT_TYPE_NOTIFY_MPROTECT},
    {"notify_open", ES_EVENT_TYPE_NOTIFY_OPEN},
    {"notify_proc_check", ES_EVENT_TYPE_NOTIFY_PROC_CHECK},
    {"notify_proc_suspend_resume", ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME},
    {"notify_pty_close", ES_EVENT_TYPE_NOTIFY_PTY_CLOSE},
    {"notify_pty_grant", ES_EVENT_TYPE_NOTIFY_PTY_GRANT},
    {"notify_readdir", ES_EVENT_TYPE_NOTIFY_READDIR},
    {"notify_readlink", ES_EVENT_TYPE_NOTIFY_READLINK},
    {"notify_remote_thread_create", ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE},
    {"notify_remount", ES_EVENT_TYPE_NOTIFY_REMOUNT},
    {"notify_rename", ES_EVENT_TYPE_NOTIFY_RENAME},
    {"notify_searchfs", ES_EVENT_TYPE_NOTIFY_SEARCHFS},
    {"notify_setacl", ES_EVENT_TYPE_NOTIFY_SETACL},
    {"notify_setattrlist", ES_EVENT_TYPE_NOTIFY_SETATTRLIST},
    {"notify_setegid", ES_EVENT_TYPE_NOTIFY_SETEGID},
    {"notify_seteuid", ES_EVENT_TYPE_NOTIFY_SETEUID},
    {"notify_setextattr", ES_EVENT_TYPE_NOTIFY_SETEXTATTR},
    {"notify_setgid", ES_EVENT_TYPE_NOTIFY_SETGID},
    {"notify_setflags", ES_EVENT_TYPE_NOTIFY_SETFLAGS},
    {"notify_setmode", ES_EVENT_TYPE_NOTIFY_SETMODE},
    {"notify_setowner", ES_EVENT_TYPE_NOTIFY_SETOWNER},
    {"notify_setregid", ES_EVENT_TYPE_NOTIFY_SETREGID},
    {"notify_setreuid", ES_EVENT_TYPE_NOTIFY_SETREUID},
    {"notify_settime", ES_EVENT_TYPE_NOTIFY_SETTIME},
    {"notify_setuid", ES_EVENT_TYPE_NOTIFY_SETUID},
    {"notify_signal", ES_EVENT_TYPE_NOTIFY_SIGNAL},
    {"notify_stat", ES_EVENT_TYPE_NOTIFY_STAT},
    {"notify_trace", ES_EVENT_TYPE_NOTIFY_TRACE},
    {"notify_truncate", ES_EVENT_TYPE_NOTIFY_TRUNCATE},
    {"notify_uipc_bind", ES_EVENT_TYPE_NOTIFY_UIPC_BIND},
    {"notify_uipc_connect", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT},
    {"notify_unlink", ES_EVENT_TYPE_NOTIFY_UNLINK},
    {"notify_unmount", ES_EVENT_TYPE_NOTIFY_UNMOUNT},
    {"notify_utimes", ES_EVENT_TYPE_NOTIFY_UTIMES},
    {"notify_write", ES_EVENT_TYPE_NOTIFY_WRITE},
};

#define NUM_EVENTS (sizeof(EVENT_TABLE) / sizeof(EVENT_TABLE[0]))

static dispatch_queue_t g_event_queue = NULL;

es_event_type_t get_event_type(const char *event_name) {
    for (const event_map_t *event = EVENT_TABLE; event < EVENT_TABLE + NUM_EVENTS; ++event) {
        if (strcmp(event->name, event_name) == 0) {
            return event->type;
        }
    }

    return (es_event_type_t)-1;  // Invalid event type
}

void list_events() {
    for (size_t i = 0; i < NUM_EVENTS; i++) {
        printf("%s\n", EVENT_TABLE[i].name);
    }
}

void init_dispatch_queue() {
	// Choose an appropriate Quality of Service class appropriate for your app.
	// https://developer.apple.com/documentation/dispatch/dispatchqos
	dispatch_queue_attr_t queue_attrs = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_CONCURRENT, QOS_CLASS_USER_INITIATED, 0);

	g_event_queue = dispatch_queue_create("event_queue", queue_attrs);
}

static void handle_auth_worker(es_client_t *client, const es_message_t *msg) {
    // Auto-approve all AUTH events
    es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, true);
}


static void handle_event(es_client_t *client, const es_message_t *msg)
{
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        // Note: `es_retain_message` and `es_release_message` are only available in
        // macOS 11.0 and newer. To run this sample project on macOS 10.15, first
        // update the deployment target in the project settings, then modify this
        // function to use the older `es_copy_message` and `es_free_message` APIs.
        es_retain_message(msg);

        dispatch_async(g_event_queue, ^{
            handle_auth_worker(client, msg);
            es_release_message(msg);
        });
    }
}

int main(int argc, char *argv[]) {
    es_client_t *client;
    es_new_client_result_t result;
    es_event_type_t events[NUM_EVENTS];
    uint32_t event_count = 0;

    // Check for --list option
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        list_events();
        return 0;
    }

    // Parse command-line arguments
    for (int i = 1; i < argc && event_count < NUM_EVENTS; i++) {
        es_event_type_t event = get_event_type(argv[i]);
        if (event != (es_event_type_t)-1) {
            events[event_count++] = event;
        } else {
            fprintf(stderr, "Unknown event type: %s\n", argv[i]);
        }
    }

    if (event_count == 0) {
        fprintf(stderr, "No valid events specified\n");
        return 1;
    }

    init_dispatch_queue();

    // Create a new ES client with a block
    result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        handle_event(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create ES client: %d\n", result);
        return 1;
    }

    // Subscribe to specified event types
    es_return_t subscribe_result = es_subscribe(client, events, event_count);
    if (subscribe_result != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Failed to subscribe to events: %d\n", subscribe_result);
        es_delete_client(client);
        return 1;
    }

    printf("Endpoint security program running. Subscribed to %d events. Press Ctrl+C to exit.\n", event_count);

	dispatch_main();

    // Clean up (this part will never be reached in this example)
    es_unsubscribe_all(client);
    es_delete_client(client);

    return 0;
}
