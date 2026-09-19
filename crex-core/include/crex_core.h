#ifndef CREX_CORE_H
#define CREX_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CrexBufferHandle CrexBufferHandle;

/// Creates a new Piece Table buffer
CrexBufferHandle* crex_buffer_create(const char* initial_text);

/// Inserts text into buffer at byte offset
void crex_buffer_insert(CrexBufferHandle* handle, size_t offset, const char* text);

/// Deletes text from buffer at byte offset
void crex_buffer_delete(CrexBufferHandle* handle, size_t offset, size_t length);

/// Returns the complete reconstructed text (must be freed with crex_string_free)
char* crex_buffer_get_text(const CrexBufferHandle* handle);

/// Returns the line count of the buffer
size_t crex_buffer_line_count(const CrexBufferHandle* handle);

/// Returns the byte length of the buffer
size_t crex_buffer_length(const CrexBufferHandle* handle);

/// Parses buffer into JSON AST tokens (must be freed with crex_string_free)
char* crex_buffer_parse_ast(const CrexBufferHandle* handle, const char* language);

/// Frees a string allocated by Crex Core
void crex_string_free(char* ptr);

/// Frees the buffer handle
void crex_buffer_free(CrexBufferHandle* handle);

#ifdef __cplusplus
}
#endif

#endif /* CREX_CORE_H */
