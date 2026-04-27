/**
 * \file static_memory.c
 * \brief Реализация статического аллокатора памяти для Mbed TLS в загрузчике
 * 
 * Этот файл предоставляет реализации calloc и free, которые используют
 * предварительно выделенный статический буфер вместо динамической кучи.
 * Это устраняет фрагментацию памяти и делает использование памяти предсказуемым.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* ============================================ */
/* CONFIGURATION: Настройте размеры под ваш MCU */
/* ============================================ */

/* Размер статического буфера памяти (в байтах) */
/* Для минимальной конфигурации PSA обычно достаточно 8-16 КБ */
/* Увеличьте, если получаете ошибки нехватки памяти */
#ifndef STATIC_MEMORY_POOL_SIZE
#define STATIC_MEMORY_POOL_SIZE (16 * 1024)  /* 16 КБ */
#endif

/* Выравнивание по 4 или 8 байт (зависит от архитектуры MCU) */
#ifndef MEMORY_ALIGNMENT
#define MEMORY_ALIGNMENT 4
#endif

/* ============================================ */
/* INTERNAL STRUCTURES                          */
/* ============================================ */

/* Заголовок блока памяти */
typedef struct memory_block_header {
    size_t size;              /* Размер блока данных (без заголовка) */
    uint8_t is_free;          /* 1 = свободен, 0 = занят */
    uint8_t padding[3];       /* Выравнивание до 4 байт */
    struct memory_block_header* next;  /* Следующий блок */
    struct memory_block_header* prev;  /* Предыдущий блок */
} memory_block_header_t;

#define BLOCK_HEADER_SIZE sizeof(memory_block_header_t)
#define MIN_BLOCK_SIZE (BLOCK_HEADER_SIZE + MEMORY_ALIGNMENT)

/* Статический пул памяти */
static uint8_t static_memory_pool[STATIC_MEMORY_POOL_SIZE] __attribute__((aligned(MEMORY_ALIGNMENT)));

/* Указатель на первый блок (инициализируется один раз) */
static memory_block_header_t* first_block = NULL;

/* Флаг инициализации */
static int memory_initialized = 0;

/* ============================================ */
/* HELPER FUNCTIONS                             */
/* ============================================ */

/**
 * \brief Инициализация пула памяти
 * Создает один большой свободный блок из всего пула
 */
static void init_memory_pool(void) {
    if (memory_initialized) {
        return;
    }

    /* Создаем один большой свободный блок */
    first_block = (memory_block_header_t*)static_memory_pool;
    first_block->size = STATIC_MEMORY_POOL_SIZE - BLOCK_HEADER_SIZE;
    first_block->is_free = 1;
    first_block->next = NULL;
    first_block->prev = NULL;

    memory_initialized = 1;
}

/**
 * \brief Выравнивание размера до границы выравнивания
 */
static size_t align_size(size_t size) {
    return (size + (MEMORY_ALIGNMENT - 1)) & ~(MEMORY_ALIGNMENT - 1);
}

/**
 * \brief Разделение блока, если он слишком большой
 */
static void split_block(memory_block_header_t* block, size_t required_size) {
    size_t remaining = block->size - required_size;
    
    /* Разделяем только если остаток достаточно велик для нового блока */
    if (remaining >= MIN_BLOCK_SIZE) {
        memory_block_header_t* new_block = (memory_block_header_t*)((uint8_t*)block + BLOCK_HEADER_SIZE + required_size);
        new_block->size = remaining - BLOCK_HEADER_SIZE;
        new_block->is_free = 1;
        new_block->next = block->next;
        new_block->prev = block;
        
        if (block->next) {
            block->next->prev = new_block;
        }
        
        block->next = new_block;
        block->size = required_size;
    }
}

/**
 * \brief Объединение с соседними свободными блоками
 */
static void merge_blocks(memory_block_header_t* block) {
    /* Объединение с предыдущим блоком */
    if (block->prev && block->prev->is_free) {
        memory_block_header_t* prev = block->prev;
        prev->size += BLOCK_HEADER_SIZE + block->size;
        prev->next = block->next;
        
        if (block->next) {
            block->next->prev = prev;
        }
        
        block = prev;
    }
    
    /* Объединение со следующим блоком */
    if (block->next && block->next->is_free) {
        memory_block_header_t* next = block->next;
        block->size += BLOCK_HEADER_SIZE + next->size;
        block->next = next->next;
        
        if (next->next) {
            next->next->prev = block;
        }
    }
}

/* ============================================ */
/* PUBLIC API: calloc и free                    */
/* ============================================ */

/**
 * \brief Статическая реализация calloc
 * 
 * @param nmemb Количество элементов
 * @param size Размер каждого элемента
 * @return Указатель на выделенную память или NULL при неудаче
 */
void* mbedtls_calloc_static(size_t nmemb, size_t size) {
    /* Инициализация при первом вызове */
    if (!memory_initialized) {
        init_memory_pool();
    }

    /* Проверка на переполнение */
    if (nmemb == 0 || size == 0) {
        return NULL;
    }
    
    /* Проверка на переполнение умножения */
    if (nmemb > SIZE_MAX / size) {
        return NULL;
    }

    size_t total_size = nmemb * size;
    size_t aligned_size = align_size(total_size);

    /* Поиск подходящего свободного блока (first-fit) */
    memory_block_header_t* current = first_block;
    while (current) {
        if (current->is_free && current->size >= aligned_size) {
            /* Нашли подходящий блок */
            split_block(current, aligned_size);
            current->is_free = 0;
            
            /* Обнуляем память (как требует calloc) */
            void* ptr = (uint8_t*)current + BLOCK_HEADER_SIZE;
            memset(ptr, 0, current->size);
            
            return ptr;
        }
        current = current->next;
    }

    /* Не нашли свободный блок */
    return NULL;
}

/**
 * \brief Статическая реализация free
 * 
 * @param ptr Указатель на освобождаемую память
 */
void mbedtls_free_static(void* ptr) {
    if (!ptr || !memory_initialized) {
        return;
    }

    /* Получаем заголовок блока */
    memory_block_header_t* block = (memory_block_header_t*)((uint8_t*)ptr - BLOCK_HEADER_SIZE);
    
    /* Проверка границ (опционально, можно отключить для экономии места) */
    if ((uint8_t*)block < static_memory_pool || 
        (uint8_t*)block >= static_memory_pool + STATIC_MEMORY_POOL_SIZE) {
        return; /* Неверный указатель */
    }

    /* Помечаем блок как свободный */
    block->is_free = 1;
    
    /* Объединяем с соседними свободными блоками */
    merge_blocks(block);
}

/**
 * \brief Получение статистики использования памяти (для отладки)
 * 
 * @param free_bytes Указатель для записи количества свободных байт
 * @param used_bytes Указатель для записи количества занятых байт
 * @param max_used_bytes Указатель для записи максимального количества занятых байт
 */
void mbedtls_get_memory_stats(size_t* free_bytes, size_t* used_bytes, size_t* max_used_bytes) {
    if (!memory_initialized) {
        if (free_bytes) *free_bytes = STATIC_MEMORY_POOL_SIZE;
        if (used_bytes) *used_bytes = 0;
        if (max_used_bytes) *max_used_bytes = 0;
        return;
    }

    size_t free_total = 0;
    size_t used_total = 0;
    memory_block_header_t* current = first_block;

    while (current) {
        if (current->is_free) {
            free_total += current->size;
        } else {
            used_total += current->size;
        }
        current = current->next;
    }

    if (free_bytes) *free_bytes = free_total;
    if (used_bytes) *used_bytes = used_total;
    if (max_used_bytes) *max_used_bytes = used_total; /* Можно доработать для отслеживания пика */
}

/**
 * \brief Сброс пула памяти (только для тестирования!)
 * Внимание: Не используйте в продакшене, все выделенные блоки будут потеряны!
 */
void mbedtls_reset_memory_pool(void) {
    memory_initialized = 0;
    first_block = NULL;
    init_memory_pool();
}
