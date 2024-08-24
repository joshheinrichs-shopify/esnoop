#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <stdlib.h>
#include <Block.h>

int main(int argc, char *argv[]) {
    es_client_t *client;
    es_new_client_result_t result;

    // Create a new ES client with a block
    result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        // No-op: We're not doing anything with the events
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create ES client: %d\n", result);
        return 1;
    }

    // Subscribe to specific event types
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_MOUNT,
        ES_EVENT_TYPE_NOTIFY_SETFLAGS
    };
    
    uint32_t event_count = sizeof(events) / sizeof(es_event_type_t);
    
    es_return_t subscribe_result = es_subscribe(client, events, event_count);
    if (subscribe_result != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Failed to subscribe to events: %d\n", subscribe_result);
        es_delete_client(client);
        return 1;
    }

    printf("Endpoint security program running. Press Ctrl+C to exit.\n");

    // Main loop
    while(1) {
        // No-op: We're not doing anything in the main loop
    }

    // Clean up (this part will never be reached in this example)
    es_unsubscribe_all(client);
    es_delete_client(client);

    return 0;
}
