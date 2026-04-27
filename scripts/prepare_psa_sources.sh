#!/bin/bash
# Скрипт для подготовки минимальных исходников Mbed TLS PSA Crypto для загрузчика

set -e

OUTPUT_DIR="${1:-psa_crypto_sources}"
CONFIG_FILE="${2:-../configs/config-psa-minimal.h}"

echo "=== Подготовка исходников Mbed TLS PSA Crypto ==="
echo "Выходная директория: $OUTPUT_DIR"
echo "Конфигурация: $CONFIG_FILE"

# Создаем выходную директорию
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/include"
mkdir -p "$OUTPUT_DIR/src"

# Копируем заголовочные файлы PSA из tf-psa-crypto
echo "Копирование заголовочных файлов..."
cp -r ../tf-psa-crypto/include/psa "$OUTPUT_DIR/include/"
cp -r ../tf-psa-crypto/include/mbedtls "$OUTPUT_DIR/include/" 2>/dev/null || true

# Копируем основной mbedtls config
cp ../include/mbedtls/mbedtls_config.h "$OUTPUT_DIR/include/mbedtls/" 2>/dev/null || mkdir -p "$OUTPUT_DIR/include/mbedtls"

# Копируем конфигурационный файл
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$OUTPUT_DIR/include/psa/crypto_config.h"
    echo "Конфигурация скопирована в include/psa/crypto_config.h"
fi

# Основные файлы ядра PSA Crypto
CORE_FILES=(
    "psa_crypto.c"
    "psa_crypto_client.c"
    "psa_crypto_random.c"
    "psa_crypto_slot_management.c"
    "psa_crypto_storage.c"
    "psa_its_file.c"
    "psa_util.c"
)

echo "Копирование файлов ядра PSA Crypto..."
for file in "${CORE_FILES[@]}"; do
    if [ -f "../tf-psa-crypto/core/$file" ]; then
        cp "../tf-psa-crypto/core/$file" "$OUTPUT_DIR/src/"
        echo "  + core/$file"
    fi
done

# Файлы алгоритмов (встроенные драйверы)
ALGO_FILES=(
    # AES
    "aes.c"
    "aesni.c"
    # Шифрование
    "cipher.c"
    "cipher_wrap.c"
    "block_cipher.c"
    # Режимы
    "ccm.c"
    "gcm.c"
    "cmac.c"
    # Хеш-функции
    "md5.c"
    "sha1.c"
    "sha256.c"
    "sha512.c"
    # DRBG
    "ctr_drbg.c"
    "hmac_drbg.c"
    # Энтропия
    "entropy.c"
    "entropy_poll.c"
    # Утилиты
    "constant_time.c"
    "platform.c"
    "platform_util.c"
)

echo "Копирование файлов алгоритмов..."
for file in "${ALGO_FILES[@]}"; do
    if [ -f "../tf-psa-crypto/drivers/builtin/src/$file" ]; then
        cp "../tf-psa-crypto/drivers/builtin/src/$file" "$OUTPUT_DIR/src/"
        echo "  + drivers/builtin/src/$file"
    fi
done

# Дополнительные файлы для композитных операций
COMPOSITE_FILES=(
    "psa_crypto_aead.c"
    "psa_crypto_cipher.c"
    "psa_crypto_hash.c"
    "psa_crypto_mac.c"
)

echo "Копирование файлов композитных операций..."
for file in "${COMPOSITE_FILES[@]}"; do
    if [ -f "../tf-psa-crypto/drivers/builtin/src/$file" ]; then
        cp "../tf-psa-crypto/drivers/builtin/src/$file" "$OUTPUT_DIR/src/"
        echo "  + drivers/builtin/src/$file"
    fi
done

# Создаем README
cat > "$OUTPUT_DIR/README.md" << EOF
# Mbed TLS PSA Crypto Sources for Bootloader

Минимальный набор исходников TF-PSA-Crypto для использования PSA Crypto API в загрузчике микроконтроллера.

## Структура
- \`include/\` - заголовочные файлы (PSA API)
- \`src/\` - исходные файлы библиотеки

## Использование

1. Добавьте \`include/\` в пути поиска заголовочных файлов вашего компилятора
2. Добавьте все файлы из \`src/\` в ваш проект сборки
3. Реализуйте следующие функции платформы:
   - \`calloc\`, \`free\` - управление памятью
   - Аппаратный генератор случайных чисел (или используйте встроенный CTR_DRBG)

## Конфигурация

Файл \`include/psa/crypto_config.h\` содержит минимальную конфигурацию.
Отредактируйте его, чтобы включить/выключить нужные алгоритмы.

## Необходимые алгоритмы для загрузчика

Обычно требуются:
- PSA_ALG_GCM или PSA_ALG_CCM - для шифрования прошивки
- PSA_ALG_SHA_256 - для хеширования
- PSA_ALG_ECDSA (опционально) - для проверки подписи

## Примечания

- Для экономии места отключите ненужные алгоритмы в crypto_config.h
- Реализуйте mbedtls_platform_set_calloc_free() если нужен кастомный аллокатор
EOF

echo ""
echo "=== Готово! ==="
echo "Исходники подготовлены в директории: $OUTPUT_DIR"
echo ""
echo "Содержимое:"
echo "  Заголовочные файлы: $(find "$OUTPUT_DIR/include" -name '*.h' | wc -l)"
echo "  Исходные файлы: $(find "$OUTPUT_DIR/src" -name '*.c' | wc -l)"
echo ""
echo "Следующие шаги:"
echo "1. Скопируйте папку $OUTPUT_DIR в ваш проект загрузчика"
echo "2. Добавьте include/ в пути заголовочных файлов"
echo "3. Добавьте src/*.c в сборку проекта"
echo "4. Настройте crypto_config.h под ваши нужды"
