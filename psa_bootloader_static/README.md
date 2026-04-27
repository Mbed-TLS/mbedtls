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
