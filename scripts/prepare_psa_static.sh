#!/bin/bash
# prepare_psa_static.sh - Скрипт для подготовки исходников Mbed TLS PSA со статической памятью
# Для использования в загрузчиках микроконтроллеров без динамического выделения памяти

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/psa_bootloader_static"

echo "=== Подготовка исходников Mbed TLS PSA со статической памятью ==="
echo ""

# Очистка предыдущей версии
if [ -d "$OUTPUT_DIR" ]; then
    echo "Удаление предыдущей версии..."
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR/include/psa"
mkdir -p "$OUTPUT_DIR/include/mbedtls"
mkdir -p "$OUTPUT_DIR/include/mbedtls/private"
mkdir -p "$OUTPUT_DIR/src"

# Копирование заголовочных файлов PSA из tf-psa-crypto
echo "Копирование заголовочных файлов PSA..."
cp "$PROJECT_ROOT/tf-psa-crypto/include/psa/*.h" "$OUTPUT_DIR/include/psa/" 2>/dev/null || true

# Копирование заголовочных файлов Mbed TLS
echo "Копирование заголовочных файлов Mbed TLS..."
cp "$PROJECT_ROOT/include/mbedtls/*.h" "$OUTPUT_DIR/include/mbedtls/" 2>/dev/null || true
if [ -d "$PROJECT_ROOT/include/mbedtls/private" ]; then
    cp "$PROJECT_ROOT/include/mbedtls/private/*.h" "$OUTPUT_DIR/include/mbedtls/private/" 2>/dev/null || true
fi

# Копирование конфигурационного файла
echo "Настройка конфигурации..."
cp "$PROJECT_ROOT/configs/config-psa-minimal.h" "$OUTPUT_DIR/include/mbedtls/mbedtls_config.h"

# Копирование реализаций криптографических алгоритмов
echo "Копирование исходных файлов библиотеки..."

# Основные файлы ядра PSA Crypto из tf-psa-crypto/core
CORE_PSA_FILES=(
    "psa_crypto.c"
    "psa_crypto_slot_management.c"
    "psa_crypto_storage.c"
    "psa_its_file.c"
    "psa_crypto_random.c"
    "psa_util.c"
    "tf_psa_crypto_version.c"
)

# Файлы драйверов (алгоритмы) из tf-psa-crypto/drivers/builtin/src
ALGORITHM_FILES=(
    "aes.c"
    "aesce.c"
    "aria.c"
    "camellia.c"
    "ccm.c"
    "chacha20.c"
    "chachapoly.c"
    "cipher.c"
    "cipher_wrap.c"
    "cmac.c"
    "constant_time.c"
    "entropy.c"
    "entropy_poll.c"
    "gcm.c"
    "md.c"
    "sha256.c"
    "sha512.c"
    "sha3.c"
    "platform.c"
    "platform_util.c"
    "memory_buffer_alloc.c"
    "threading.c"
    "ctr_drbg.c"
)

# Общие заголовки из library/
COMMON_HEADERS=(
    "common.h"
    "mbedtls_private_access.h"
    "alignment.h"
    "bn_mul.h"
    "check_crypto_config.h"
    "ct_macros.h"
    "debug_internal.h"
    "mps_error.h"
    "mps_reader.h"
    "mps_trace.h"
    "pk_internal.h"
    "psa_util_internal.h"
)

# Копирование основных файлов PSA из tf-psa-crypto/core
for file in "${CORE_PSA_FILES[@]}"; do
    if [ -f "$PROJECT_ROOT/tf-psa-crypto/core/$file" ]; then
        cp "$PROJECT_ROOT/tf-psa-crypto/core/$file" "$OUTPUT_DIR/src/"
    fi
done

# Копирование файлов алгоритмов из tf-psa-crypto/drivers/builtin/src
for file in "${ALGORITHM_FILES[@]}"; do
    if [ -f "$PROJECT_ROOT/tf-psa-crypto/drivers/builtin/src/$file" ]; then
        cp "$PROJECT_ROOT/tf-psa-crypto/drivers/builtin/src/$file" "$OUTPUT_DIR/src/"
    elif [ -f "$PROJECT_ROOT/library/$file" ]; then
        cp "$PROJECT_ROOT/library/$file" "$OUTPUT_DIR/src/"
    fi
done

# Копирование общих заголовков из library/
for file in "${COMMON_HEADERS[@]}"; do
    if [ -f "$PROJECT_ROOT/library/$file" ]; then
        cp "$PROJECT_ROOT/library/$file" "$OUTPUT_DIR/src/"
    fi
done

# Копирование psa_crypto_driver_wrappers.h если существует
if [ -f "$PROJECT_ROOT/tf-psa-crypto/drivers/builtin/include/mbedtls/psa_crypto_driver_wrappers.h" ]; then
    cp "$PROJECT_ROOT/tf-psa-crypto/drivers/builtin/include/mbedtls/psa_crypto_driver_wrappers.h" "$OUTPUT_DIR/src/"
fi

# Копирование файла статического аллокатора
echo "Добавление статического аллокатора памяти..."
cp "$PROJECT_ROOT/configs/static_memory.c" "$OUTPUT_DIR/src/"

# Создание README
echo "Создание документации..."
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Mbed TLS PSA Crypto - Статическая версия для загрузчика

Эта версия Mbed TLS настроена для работы в загрузчиках микроконтроллеров **без использования динамического выделения памяти** (heap).

## Структура

```
psa_bootloader_static/
├── include/
│   ├── psa/              # Заголовочные файлы PSA API (14 файлов)
│   └── mbedtls/          # Заголовочные файлы Mbed TLS
│       └── mbedtls_config.h  # Конфигурация
└── src/                  # Исходные файлы библиотеки
    └── static_memory.c   # Статический аллокатор памяти
```

## Особенности

- **Статическое выделение памяти**: Все выделения памяти происходят из предварительно определенного буфера (16 КБ по умолчанию)
- **Нет фрагментации кучи**: Память управляется внутри библиотеки
- **Предсказуемое использование памяти**: Максимальное потребление известно на этапе компиляции
- **Минимальная конфигурация**: Включены только AES, SHA-256, GCM, CCM, CTR_DRBG

## Настройка

### 1. Изменение размера пула памяти

Откройте `src/static_memory.c` и измените:

```c
#define STATIC_MEMORY_POOL_SIZE (16 * 1024)  // Измените на нужное значение
```

Рекомендуемые размеры:
- Минимальная (AES + SHA-256): 8-12 КБ
- С GCM/CCM: 12-16 КБ
- С ECDSA: 16-24 КБ

### 2. Добавление файлов в проект

Добавьте в вашу систему сборки:

**Заголовочные файлы:**
```
-I path/to/psa_bootloader_static/include
```

**Исходные файлы:**
```
path/to/psa_bootloader_static/src/*.c
```

### 3. Реализация энтропии

Для работы генератора случайных чисел необходимо предоставить источник энтропии.
В файле `src/entropy_poll.c` найдите функцию `mbedtls_hardware_poll` и реализуйте её для вашего MCU:

```c
int mbedtls_hardware_poll(void *data, unsigned char *output, 
                          size_t len, size_t *olen) {
    // Ваша реализация аппаратного ГСЧ
    // Например, чтение из RNG периферии STM32/ESP32/nRF и т.д.
    return 0;
}
```

### 4. Инициализация

Перед использованием PSA Crypto вызовите:

```c
#include "psa/crypto.h"

psa_status_t status = psa_crypto_init();
if (status != PSA_SUCCESS) {
    // Обработка ошибки
}
```

## Использование PSA API

Пример шифрования AES-GCM:

```c
#include "psa/crypto.h"

uint8_t key[32] = { /* 256-битный ключ */ };
uint8_t nonce[12] = { /* 96-битный nonce */ };
uint8_t plaintext[] = "Hello, World!";
uint8_t ciphertext[256];
size_t ciphertext_len;

psa_key_id_t key_id;
psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

// Создаем ключ
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
psa_set_key_bits(&attributes, 256);

psa_status_t status = psa_import_key(&attributes, key, sizeof(key), &key_id);
if (status != PSA_SUCCESS) { /* ошибка */ }

// Шифруем
status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_GCM);
// ... настройка nonce и шифрование

// Освобождаем ключ
psa_destroy_key(key_id);
```

## Отладка использования памяти

Для мониторинга использования памяти используйте:

```c
#include "static_memory.h" // Или объявите функции вручную

size_t free_bytes, used_bytes, max_used;
mbedtls_get_memory_stats(&free_bytes, &used_bytes, &max_used);

printf("Free: %zu, Used: %zu, Max Used: %zu\n", 
       free_bytes, used_bytes, max_used);
```

## Оптимизация размера

Для уменьшения размера кода:

1. Отключите неиспользуемые алгоритмы в `mbedtls_config.h`
2. Используйте флаги оптимизации компилятора: `-Os` (размер) или `-O2` (скорость)
3. Отключите отладку: уберите `MBEDTLS_MEMORY_DEBUG`

## Лицензия

Apache-2.0 OR GPL-2.0-or-later
EOF

# Копирование заголовка для static_memory.c
cat > "$OUTPUT_DIR/src/static_memory.h" << 'EOF'
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
EOF

echo ""
echo "=== Готово! ==="
echo ""
echo "Результат сохранен в: $OUTPUT_DIR"
echo ""
echo "Статистика:"
echo "- Заголовочные файлы PSA: $(ls $OUTPUT_DIR/include/psa/*.h 2>/dev/null | wc -l)"
echo "- Заголовочные файлы Mbed TLS: $(ls $OUTPUT_DIR/include/mbedtls/*.h 2>/dev/null | wc -l)"
echo "- Исходные файлы: $(ls $OUTPUT_DIR/src/*.c 2>/dev/null | wc -l)"
echo ""
echo "Следующие шаги:"
echo "1. Скопируйте папку в ваш проект прошивки"
echo "2. Добавьте пути к include и src в систему сборки"
echo "3. Реализуйте mbedtls_hardware_poll() для вашего MCU"
echo "4. Настройте размер пула памяти в static_memory.c"
echo "5. Вызовите psa_crypto_init() перед использованием"
echo ""
