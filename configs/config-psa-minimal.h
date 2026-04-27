/**
 * \file config-psa-minimal.h
 * \brief Минимальная конфигурация для PSA Crypto в загрузчике микроконтроллера
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONFIG_PSA_MINIMAL_H
#define MBEDTLS_CONFIG_PSA_MINIMAL_H

/* Версия формата конфигурации */
#define MBEDTLS_CONFIG_VERSION 0x04000000

/* ============================================ */
/* SECTION: Platform abstraction layer          */
/* ============================================ */

/* Отключаем сетевые функции (не нужны в загрузчике) */
#undef MBEDTLS_NET_C

/* Отключаем стандартный тайминг (если не нужен) */
#undef MBEDTLS_TIMING_C

/* Включаем альтернативные реализации если есть */
/* #define MBEDTLS_PLATFORM_ALT */
/* #define MBEDTLS_ENTROPY_ALT */

/* ============================================ */
/* SECTION: General configuration options       */
/* ============================================ */

/* Минимальные функции версии */
#define MBEDTLS_VERSION_FEATURES

/* Отключаем преобразование ошибок в строки (экономия места) */
#undef MBEDTLS_ERROR_C
#define MBEDTLS_ERROR_STRERROR_DUMMY

/* ============================================ */
/* SECTION: PSA Crypto Configuration            */
/* ============================================ */

/* Включаем PSA Crypto API */
#define MBEDTLS_PSA_CRYPTO_C

/* Включаем встроенный генератор случайных чисел для PSA */
#define MBEDTLS_PSA_CRYPTO_DRIVERS

/* Включаем базовую поддержку энтропии */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* ============================================ */
/* SECTION: Cryptographic algorithms            */
/* ============================================ */
/* Включите только те алгоритмы, которые нужны вашему загрузчику */

/* AES (для шифрования прошивки) */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_C

/* SHA-256 (для хеширования и проверки целостности) */
#define MBEDTLS_SHA256_C

/* HMAC (для аутентификации) */
#define MBEDTLS_MD_C

/* ECDSA (для проверки подписи прошивки) - опционально */
/* #define MBEDTLS_ECP_C */
/* #define MBEDTLS_ECDSA_C */
/* #define MBEDTLS_ASN1_PARSE_C */
/* #define MBEDTLS_ASN1_WRITE_C */

/* ============================================ */
/* SECTION: System support                      */
/* ============================================ */

/* Отключаем файловый ввод-вывод (нет ФС в загрузчике) */
#undef MBEDTLS_FS_IO

/* Отключаем stdin/stdout */
#undef MBEDTLS_SELF_TEST

/* ============================================ */
/* SECTION: Memory management                   */
/* ============================================ */

/* Отключаем динамическое выделение памяти в PSA Crypto */
#define MBEDTLS_PSA_STATIC_KEY_SLOTS
#define MBEDTLS_PSA_STATIC_CRYPTO_OPERATIONS

/* Ограничиваем количество одновременных операций */
#define MBEDTLS_PSA_CRYPTO_CLIENT_ID_NB_MAX 1
#define MBEDTLS_PSA_CRYPTO_MAX_OPERATION_COUNT 4

/* Используем статический аллокатор вместо calloc/free */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_STD_CALLOC mbedtls_calloc_static
#define MBEDTLS_PLATFORM_STD_FREE mbedtls_free_static

/* Лимиты памяти для предотвращения динамического роста */
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_MEMORY_DEBUG /* Опционально: для отладки использования памяти */

/* Размеры буферов (настройте под ваши нужды) */
#define MBEDTLS_MEMORY_ALIGN_MULTIPLE 4
/* Примерный размер буфера: 8-16 КБ для минимальной конфигурации */
/* #define CUSTOM_MEMORY_BUFFER_SIZE 16384 */

/* Для кастомного статического аллокатора раскомментируйте и реализуйте: */
/* #define MBEDTLS_PLATFORM_MEMORY */
/* #define MBEDTLS_PLATFORM_STD_CALLOC custom_static_calloc */
/* #define MBEDTLS_PLATFORM_STD_FREE custom_static_free */

#endif /* MBEDTLS_CONFIG_PSA_MINIMAL_H */
