/*
 * sanity.nvim Demo Program
 *
 * This program intentionally contains various memory and threading bugs
 * to demonstrate the features of sanity.nvim. DO NOT use this code
 * as a reference for correct programming practices!
 *
 * Compile and run with different tools:
 *
 *   # Memcheck (memory errors and leaks)
 *   gcc -g -lpthread demo.c -o demo
 *   valgrind --tool=memcheck --xml=yes --xml-file=memcheck.xml ./demo
 *
 *   # Helgrind (thread errors)
 *   valgrind --tool=helgrind --xml=yes --xml-file=helgrind.xml ./demo
 *
 *   # AddressSanitizer
 *   gcc -g -fsanitize=address demo.c -o demo_asan
 *   ./demo_asan 2> asan.log
 *
 *   # ThreadSanitizer
 *   gcc -g -fsanitize=thread -lpthread demo.c -o demo_tsan
 *   ./demo_tsan 2> tsan.log
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================
 * BUG 1: Data Race
 *
 * Two threads access 'shared_counter' without synchronization.
 * Helgrind and ThreadSanitizer will detect this.
 * ============================================================ */

int shared_counter = 0;

void *increment_counter(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        shared_counter++;  /* DATA RACE: unsynchronized write */
    }
    return NULL;
}

void *read_counter(void *arg) {
    (void)arg;
    int local;
    for (int i = 0; i < 1000; i++) {
        local = shared_counter;  /* DATA RACE: unsynchronized read */
    }
    printf("Counter read: %d\n", local);
    return NULL;
}

void demonstrate_data_race(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, increment_counter, NULL);
    pthread_create(&t2, NULL, read_counter, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("Final counter: %d\n", shared_counter);
}

/* ============================================================
 * BUG 2: Definitely Lost Memory
 *
 * Memory is allocated but never freed, and no pointer remains.
 * Memcheck will report this as "definitely lost".
 * ============================================================ */

void allocate_and_lose(int size) {
    char *buffer = malloc(size);
    if (buffer) {
        memset(buffer, 'A', size);
        printf("Allocated %d bytes at %p\n", size, (void *)buffer);
    }
    /* BUG: buffer is never freed, pointer goes out of scope */
}

void demonstrate_definitely_lost(void) {
    allocate_and_lose(64);
    allocate_and_lose(128);
    allocate_and_lose(256);
}

/* ============================================================
 * BUG 3: Still Reachable Memory
 *
 * Memory is allocated and a pointer still exists at exit,
 * but it was never freed. This is often intentional for
 * global data structures.
 * ============================================================ */

char *global_config = NULL;

void load_config(void) {
    global_config = malloc(512);
    if (global_config) {
        strcpy(global_config, "some_setting=value");
        printf("Config loaded: %s\n", global_config);
    }
    /* BUG: global_config is never freed (still reachable at exit) */
}

/* ============================================================
 * BUG 4: Invalid Read (Use After Free)
 *
 * Memory is freed and then accessed. This is undefined behavior.
 * Memcheck and AddressSanitizer will catch this.
 * ============================================================ */

void demonstrate_use_after_free(void) {
    char *data = malloc(32);
    if (!data) return;

    strcpy(data, "Hello, World!");
    printf("Before free: %s\n", data);

    free(data);

    /* BUG: accessing memory after it has been freed */
    printf("After free: %c\n", data[0]);
}

/* ============================================================
 * BUG 5: Invalid Write (Buffer Overflow)
 *
 * Writing beyond the allocated buffer size.
 * Memcheck and AddressSanitizer will detect this.
 * ============================================================ */

void write_to_buffer(char *buf, int size) {
    for (int i = 0; i <= size; i++) {  /* BUG: off-by-one, should be i < size */
        buf[i] = 'X';
    }
}

void process_data(void) {
    char *buffer = malloc(16);
    if (buffer) {
        write_to_buffer(buffer, 16);  /* Overflow: writes 17 bytes */
        free(buffer);
    }
}

void demonstrate_buffer_overflow(void) {
    process_data();
}

/* ============================================================
 * BUG 6: Uninitialized Value
 *
 * Using a variable before it has been initialized.
 * Memcheck will report "Conditional jump depends on uninitialised value".
 * ============================================================ */

void demonstrate_uninitialized(void) {
    int values[10];
    int sum = 0;

    /* BUG: values[] is never initialized */
    for (int i = 0; i < 10; i++) {
        if (values[i] > 0) {  /* Conditional on uninitialized value */
            sum += values[i];
        }
    }
    printf("Sum: %d\n", sum);
}

/* ============================================================
 * BUG 7: Double Free
 *
 * Freeing the same memory twice causes undefined behavior.
 * Memcheck and AddressSanitizer will catch this.
 * ============================================================ */

void demonstrate_double_free(void) {
    char *ptr = malloc(64);
    if (!ptr) return;

    free(ptr);
    /* BUG: freeing already freed memory */
    /* Uncomment to trigger: free(ptr); */
    printf("Double free demonstration (commented out to allow program to continue)\n");
}

/* ============================================================
 * BUG 8: Memory Leak in Nested Structure
 *
 * A linked list where nodes are lost, demonstrating
 * both "definitely lost" and "indirectly lost" categories.
 * ============================================================ */

struct Node {
    int value;
    char *name;
    struct Node *next;
};

struct Node *create_node(int value, const char *name) {
    struct Node *node = malloc(sizeof(struct Node));
    if (node) {
        node->value = value;
        node->name = malloc(strlen(name) + 1);
        if (node->name) {
            strcpy(node->name, name);
        }
        node->next = NULL;
    }
    return node;
}

void demonstrate_nested_leak(void) {
    struct Node *head = create_node(1, "first");
    if (head) {
        head->next = create_node(2, "second");
        if (head->next) {
            head->next->next = create_node(3, "third");
        }
    }
    printf("Created linked list with 3 nodes\n");
    /* BUG: entire list is leaked - head is definitely lost,
     * subsequent nodes and their names are indirectly lost */
}

/* ============================================================
 * BUG 9: Lock Order Violation (Potential Deadlock)
 *
 * Two threads acquire locks in different orders, which can
 * lead to deadlock. Helgrind will detect this. Note that this
 * program may not terminate.
 * ============================================================ */

pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;

void *thread_order_ab(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock_a);
    usleep(1000);  /* Increase chance of interleaving */
    pthread_mutex_lock(&lock_b);
    printf("Thread AB acquired both locks\n");
    pthread_mutex_unlock(&lock_b);
    pthread_mutex_unlock(&lock_a);
    return NULL;
}

void *thread_order_ba(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock_b);  /* BUG: opposite lock order */
    usleep(1000);
    pthread_mutex_lock(&lock_a);
    printf("Thread BA acquired both locks\n");
    pthread_mutex_unlock(&lock_a);
    pthread_mutex_unlock(&lock_b);
    return NULL;
}

void demonstrate_lock_order(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_order_ab, NULL);
    pthread_create(&t2, NULL, thread_order_ba, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}

/* ============================================================
 * Main: Run all demonstrations
 * ============================================================ */

int main(int argc, char *argv[]) {
    printf("=== sanity.nvim Demo Program ===\n\n");

    /* Select which demo to run, or all if no argument */
    int demo = (argc > 1) ? atoi(argv[1]) : 0;

    if (demo == 0 || demo == 1) {
        printf("--- Demo 1: Data Race ---\n");
        demonstrate_data_race();
        printf("\n");
    }

    if (demo == 0 || demo == 2) {
        printf("--- Demo 2: Definitely Lost Memory ---\n");
        demonstrate_definitely_lost();
        printf("\n");
    }

    if (demo == 0 || demo == 3) {
        printf("--- Demo 3: Still Reachable Memory ---\n");
        load_config();
        printf("\n");
    }

    if (demo == 0 || demo == 4) {
        printf("--- Demo 4: Use After Free ---\n");
        demonstrate_use_after_free();
        printf("\n");
    }

    if (demo == 0 || demo == 5) {
        printf("--- Demo 5: Buffer Overflow ---\n");
        demonstrate_buffer_overflow();
        printf("\n");
    }

    if (demo == 0 || demo == 6) {
        printf("--- Demo 6: Uninitialized Value ---\n");
        demonstrate_uninitialized();
        printf("\n");
    }

    if (demo == 0 || demo == 7) {
        printf("--- Demo 7: Double Free (disabled) ---\n");
        demonstrate_double_free();
        printf("\n");
    }

    if (demo == 0 || demo == 8) {
        printf("--- Demo 8: Nested Structure Leak ---\n");
        demonstrate_nested_leak();
        printf("\n");
    }

    if (demo == 0 || demo == 9) {
        printf("--- Demo 9: Lock Order Violation ---\n");
        demonstrate_lock_order();
        printf("\n");
    }

    printf("=== Demo Complete ===\n");
    return 0;
}
