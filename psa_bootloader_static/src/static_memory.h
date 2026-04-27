#ifndef STATIC_MEMORY_H
#define STATIC_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Получение статистики использования памяти
 * 
 * @param free_bytes Указатель для свободных байт (может быть NULL)
 * @param used_bytes Указатель для занятых байт (может быть NULL)
 * @param max_used_bytes Указатель для макс. занятых байт (может быть NULL)
 */
void mbedtls_get_memory_stats(size_t* free_bytes, size_t* used_bytes, size_t* max_used_bytes);

/**
 * \brief Сброс пула памяти (только для тестирования!)
 */
void mbedtls_reset_memory_pool(void);

#ifdef __cplusplus
}
#endif

#endif /* STATIC_MEMORY_H */
