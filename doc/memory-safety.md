# Approach to memory safety in C++ code

## Objective

This approach aims to mitigate memory safety vulnerabilities (such as use-after-free, buffer overflows, and uninitialized memory access) to levels comparable with memory-safe languages like Rust and Haskell. However, issues related to memory leaks (e.g., cyclic references in std::shared_ptr) and concurrency (e.g., data races, thread-safety) are covered in a separate document.

## Memory Allocation Guidelines

Memory objects should be created using:
- Static allocation using the function-local static variable pattern (to avoid destruction order issues).
- Stack allocation and RAII for automatic lifetime management.
- Smart pointers (std::unique_ptr, std::shared_ptr) for dynamically allocated memory.

# Reference and Pointer Safety Rules

Pointers to allocated objects must follow these guidelines:
- Prefer std::unique_ptr or std::shared_ptr for all heap-allocated objects.
- Direct references (&) and std::span may only be used if:
  - They are stored in stack-allocated objects, which are allocated after the referenced object.
  - They are only used within the same thread.
- References to statically allocated objects are only allowed from stack-allocated objects.

These rules ensure no references outlive the objects they refer to, eliminating risks of dangling pointers and use-after-free errors.

## Testing and Validation

To enforce memory safety:
Any modules passing references directly must have more robust unit tests with the following requirements:
- High test coverage (90%+ branches and aiming 100% where possible) for functions using direct references or std::span.
- Clang's AddressSanitizer must be enabled in CI/CD.
- Regular fuzz testing for modules handling raw references or std::span to detect unexpected edge cases as part of every release preparation.
